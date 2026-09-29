/*
 * pty_test.c -- test harness: drive ./fooc through a pseudo-terminal so the
 * interactive shell it spawns has a terminal on its stdin.
 *
 * Test scaffolding, not part of the lab. It exists because the exploit's final
 * act is to replace its own stdin/stdout with the TCP socket and exec a shell.
 * Anything already sitting on the real stdin (a pipe, a here-doc) is discarded
 * at that moment, so the commands must arrive via a real tty or not at all.
 *
 * Usage: pty_test <fooc-args...>
 *   e.g. pty_test -t ret2win
 *        pty_test -t shellcode
 *
 * Exit status: 0 if the "PWNED-OK" marker appeared in the session.
 */
#define _GNU_SOURCE

#include <errno.h>     /* strerror().                                        */
#include <fcntl.h>     /* open(), O_RDWR.                                    */
#include <pty.h>       /* posix_openpt(), grantpt(), ptsname_r().            */
#include <stdio.h>     /* printf() and friends.                              */
#include <stdlib.h>    /* _exit().                                           */
#include <string.h>    /* strstr().                                          */
#include <sys/wait.h>  /* waitpid().                                         */
#include <sys/select.h>/* select(), for a timeout that is not a busy loop.  */
#include <termios.h>   /* tcgetattr()/tcsetattr(), cfmakeraw().              */
#include <signal.h>     /* kill(), SIGKILL.                                 */
#include <unistd.h>    /* read, write, dup2, usleep, setsid, close.          */

/* The marker we type; seeing it back proves we really got a shell. */
#define MARKER "PWNED-OK"

/*
 * The two things we require before calling a technique a success. Both must
 * appear, and neither is present in the harness's own output:
 *
 *   MARKER  the literal string our `echo` prints
 *   "uid="  the first two fields of `id` output, i.e. a real program really
 *           ran inside a real shell on the far side of the connection
 *
 * MARKER alone is not sufficient. It also occurs in the command line we typed,
 * so a terminal that merely echoes input -- or any harness that checks a
 * single read() chunk -- would score a false positive. "uid=" can only come
 * from a live shell executing a program, which is the claim under test.
 */
#define MARKER "PWNED-OK"
#define IDOUT  "uid="

/*
 * transcript -- everything the pty has ever given us, appended by
 * drain_master(). The success check scans this rather than individual read()
 * chunks, because a marker can straddle a chunk boundary and a per-chunk
 * strstr() would miss a genuine success. Generously sized; a few tens of KB is
 * far more than a `id`/`uname` session produces.
 */
static char transcript[65536];

/*
 * drain_master() -- read whatever is available on the pty master, for at most
 * `ms` milliseconds, echoing it to our stdout and returning the number of
 * bytes seen.
 *
 * Everything goes to ONE stream, stdout. An earlier version sent pre-shell
 * output to stderr and shell output to stdout, which meant the two halves of
 * the session landed in different places: running the harness with
 * `2>/dev/null` silently ate the first line of every command's output and made
 * `uid=1000(hanez)` look like `(hanez)`. Concatenating onto one stream means
 * the transcript reads in order and can be piped without surprises.
 *
 * select() with a timeout, rather than a bare read(), keeps this from
 * spinning: we genuinely stop when the far end goes quiet, which matters
 * because the shell is interactive and silent for long stretches.
 */
static int drain_master(int master, int ms)
{
    struct timeval tv;
    fd_set         rfds;
    int            total = 0;
    char           buf[4096];

    FD_ZERO(&rfds);
    FD_SET(master, &rfds);
    tv.tv_sec  = ms / 1000;
    tv.tv_usec = (ms % 1000) * 1000;

    /* select() returns >0 readable, 0 on timeout, -1 on error. */
    while (select(master + 1, &rfds, NULL, NULL, &tv) > 0) {
        ssize_t n = read(master, buf, sizeof(buf));
        if (n <= 0)
            break;
        fwrite(buf, 1, (size_t)n, stdout);
        fflush(stdout);
        total += (int)n;

        /* Keep a copy for the success check, so it is not lost between chunks. */
        if ((size_t)total < sizeof(transcript) - 1)
            strncat(transcript, buf, (size_t)n);

        /* Reset the deadline so a chatty peer cannot keep us here forever. */
        FD_ZERO(&rfds);
        FD_SET(master, &rfds);
        tv.tv_sec  = 0;
        tv.tv_usec = 200000;
    }
    return total;
}

/*
 * technique_of() -- find the value of fooc's -t flag in our own argv, so the
 * summary line names the technique we actually ran rather than the option
 * letter that introduced it.
 */
static const char *technique_of(int argc, char **argv)
{
    for (int i = 1; i + 1 < argc; i++)
        if (strcmp(argv[i], "-t") == 0)
            return argv[i + 1];
    return "(default: ret2win)";
}

int main(int argc, char **argv)
{
    int            master;            /* pty master end: our window in.      */
    char           slave_name[256];   /* Path of the pty slave.               */
    struct termios saved;             /* The terminal state to restore.        */
    int            have_saved = 0;    /* Did tcgetattr() succeed?             */
    pid_t          pid;               /* The child running fooc.              */
    int            ok = 0;            /* Did the marker come back?            */
    int            saw_id = 0;        /* Did real `id` output come back?      */
    int            round;             /* Which read phase we are in.           */

    /* ---- 1. Allocate a pty. --------------------------------------------- */
    master = posix_openpt(O_RDWR);
    if (master < 0) {
        perror("posix_openpt");
        return 2;
    }
    if (grantpt(master) < 0 || unlockpt(master) < 0) {
        perror("grantpt/unlockpt");
        return 2;
    }
    if (ptsname_r(master, slave_name, sizeof(slave_name)) != 0) {
        perror("ptsname_r");
        return 2;
    }

    /* ---- 2. Fork; the child becomes the pty slave and execs fooc. ------- */
    pid = fork();
    if (pid < 0) {
        perror("fork");
        return 2;
    }

    if (pid == 0) {
        int s;
        char *args[64];
        int   n = 0;

        if (setsid() < 0)
            _exit(127);
        s = open(slave_name, O_RDWR);
        if (s < 0)
            _exit(127);
        dup2(s, STDIN_FILENO);
        dup2(s, STDOUT_FILENO);
        dup2(s, STDERR_FILENO);
        if (s > STDERR_FILENO)
            close(s);

        /*
         * Pass everything through to fooc except our own --dump flag and its
         * argument, which fooc's getopt() would reject and exit on.
         */
        args[n++] = (char *)"./fooc";
        for (int i = 1; i < argc && n < 63; i++) {
            if (strcmp(argv[i], "--dump") == 0) {
                i++;            /* Skip the filename too.                   */
                continue;
            }
            args[n++] = argv[i];
        }
        args[n] = NULL;
        execv(args[0], args);
        _exit(127);
    }

    /*
     * ---- 3. Terminal settings: cooked, but SILENT.
     *
     * We deliberately do NOT call cfmakeraw(). A real interactive shell needs
     * an ordinary line-discipline terminal: input line-buffered, signals
     * generated, and (on this system) bash's bracketed-paste sequences. Raw
     * mode made the shell misbehave and the harness see nothing back even
     * though the exploit was working perfectly.
     *
     * We DO turn ECHO off, and that detail is load-bearing. The marker we
     * check for appears in the command line itself ("echo PWNED-OK"), so with
     * echo enabled the pty cheerfully sends our own keystrokes back to us and
     * the harness reports success whether or not a shell ever ran. That is a
     * false positive, and it hid a real failure here: the shellcode technique
     * was crashing (the target's stack is non-executable) while the test
     * cheerfully printed marker=SEEN.
     *
     * So: everything default except ECHO. That gives us a real terminal for
     * the shell, without the pty lying to us about what came back.
     */
    if (tcgetattr(master, &saved) == 0) {
        struct termios quiet = saved;
        have_saved = 1;         /* Saved purely so we can restore it on exit.*/
        quiet.c_lflag &= ~(tcflag_t)ECHO;   /* ICANON, ISIG stay ON.         */
        quiet.c_lflag |= ECHONL;            /* ...but keep the newline.     */
        tcsetattr(master, TCSANOW, &quiet);
    }

    /*
     * ---- 4. Wait for the exploit to finish analysing, connecting, sending
     * the payload and exec'ing the shell.
     *
     * fooc does a full objdump analysis plus a /proc/self/mem scan before it
     * sends anything, and only then does it hand the socket to a shell. Any
     * bytes we type before that point are written to the pty and then thrown
     * away when fooc dup2()s the socket over its own stdin, so we must wait.
     */
    for (round = 0; round < 12; round++)
        drain_master(master, 250);

    /* ---- 5. Type the proof commands. ------------------------------------ */
    dprintf(master, "id; echo " MARKER "; uname -sr; exit\n");

    /* ---- 6. Read until we have both signals (or we give up). ------------- */
    for (round = 0; round < 20; round++) {
        drain_master(master, 250);

        /*
         * Scan everything seen SO FAR, not just the latest chunk. A string
         * can straddle a read() boundary -- "PWN" in one chunk and "ED-OK" in
         * the next -- and a per-chunk strstr() would then miss a real success.
         * Keeping the whole transcript and rescanning it costs nothing at this
         * size and removes a whole class of flaky-test nonsense.
         */
        if (strstr(transcript, MARKER) != NULL) ok = 1;
        if (strstr(transcript, IDOUT)  != NULL) saw_id = 1;
        if (ok && saw_id)
            break;      /* Proof obtained; no need to keep waiting.          */
    }

    /* ---- 7. Tidy up. --------------------------------------------------- */
    kill(pid, SIGKILL);       /* The shell may ignore our 'exit'.            */
    waitpid(pid, NULL, 0);
    if (have_saved)
        tcsetattr(master, TCSANOW, &saved);
    close(master);

    /*
     * Report the two signals separately so a failure is diagnosable at a
     * glance: marker-without-`id` means the shell echoed our input but never
     * ran anything; no marker at all means the payload never landed.
     */
    /* Optionally dump the raw transcript for post-mortem debugging:
     *   pty_test -t shellcode --dump raw.txt
     * (Anything after --dump is taken as a filename; the check still runs.) */
    for (int i = 1; i + 1 < argc; i++) {
        if (strcmp(argv[i], "--dump") == 0) {
            FILE *f = fopen(argv[i + 1], "w");
            if (f != NULL) {
                fwrite(transcript, 1, strlen(transcript), f);
                fclose(f);
                fprintf(stderr, "[pty_test] transcript (%zu bytes) -> %s\n",
                        strlen(transcript), argv[i + 1]);
            }
        }
    }

    fprintf(stderr, "\n[pty_test] technique=%-10s marker=%-7s id_output=%s\n",
            technique_of(argc, argv),
            ok ? "SEEN" : "MISSING",
            saw_id ? "SEEN" : "MISSING");
    return (ok && saw_id) ? 0 : 1;
}
