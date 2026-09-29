/*
 * pty_suid_test.c -- test harness: drive ./foosc through a pseudo-terminal
 * so the interactive shell it hands over to has a real terminal.
 *
 * Why a pty at all: the exploit's last act is to relay the user's terminal
 * to the shell running on the victim. Anything already sitting on the real
 * stdin (a pipe, a here-doc) is at the wrong end of that relay, so the
 * commands must arrive via a real tty. This harness supplies one.
 *
 * What it proves, and in what order:
 *
 *   SHELL  the marker literal comes back AND real `id` output appears.
 *          Both are required because the marker alone also occurs in the
 *          command line we typed *to* the pty, so any harness that does not
 *          disable echo (see below) scores a false positive.
 *
 *   ROOT   the transcript contains "uid=0(", i.e. the shell on the far side
 *          really is root. That can only come from a live `id` executed by
 *          a root shell, and it is the entire claim of this lab.
 *
 * Flags:
 *   --must-root   exit 0 only if BOTH a shell and ROOT are proven.
 *                 Used for the techniques that MUST escalate (shellcode,
 *                 ret2win-root).
 *   --dump FILE   write the raw transcript for post-mortem analysis.
 *
 * Exit status without --must-root: 0 when a shell is proven (marker + uid=),
 * regardless of root. That is how the Makefile reports the "demoted shell"
 * techniques (ret2win/ret2libc), whose whole lesson is that they succeed as
 * shells yet do NOT get root.
 *
 * The critical detail shared with tests/pty_test.c in the parent lab: the
 * pty must run COOKED but with ECHO off. With ECHO on, the pty mirrors our
 * own keystrokes back into the transcript, the command line "echo
 * SUID-ROOT-OK" supplies the marker, and the harness reports success whether
 * or not any shell ever ran. That silent false positive cost real time in
 * the parent lab; it is documented there and avoided here from the start.
 */
#define _GNU_SOURCE

#include <errno.h>     /* strerror().                                        */
#include <fcntl.h>     /* open(), O_RDWR.                                    */
#include <pty.h>       /* posix_openpt(), grantpt(), ptsname_r().            */
#include <stdio.h>     /* printf() and friends.                              */
#include <stdlib.h>    /* _exit().                                           */
#include <string.h>    /* strstr().                                          */
#include <sys/wait.h>  /* waitpid().                                         */
#include <sys/select.h>/* select(): timeout without a busy loop.            */
#include <termios.h>   /* tcgetattr()/tcsetattr().                           */
#include <signal.h>    /* kill(), SIGKILL.                                   */
#include <unistd.h>    /* read, write, dup2, usleep, setsid, close.          */

/* The literal we ask the remote shell to print; seeing it come back (with
 * ECHO off) proves a shell really echoed it from the other side. */
#define MARKER "SUID-ROOT-OK"

/* Proofs a real program ran inside the far-side shell. Matching is strict:
 * "uid=" must be followed by digits and a parenthesis -- i.e. the exact
 * shape of `id` output ("uid=1000(hanez)"). A bare "uid=" substring is NOT
 * enough, because foosc's own diagnostics print "target euid=1000
 * ruid=1000", and both "euid="/"ruid=" contain "uid=". That accidental
 * substring made the hardened-build tests report id_output=SEEN while no
 * shell existed -- the false positive this strict match eliminates. */
#define IDOUT  "uid="

/* PROOF the far-side shell is root. "uid=0(" matches "uid=0(root)" and the
 * older "uid=0( root)"-style output of any id implementation; only 'id' can
 * print this line, and the parenthesis rules out any foosc/daemon chatter. */
#define ROOTOUT "uid=0("

/* saw_real_uid_output() -- true iff the transcript contains "uid=" followed
 * by one or more digits and then '(' . That is the signature of `id`'s
 * output and of nothing foosc or foosd prints. */
static int saw_real_uid_output(const char *t)
{
    const char *p = t;
    while ((p = strstr(p, IDOUT)) != NULL) {
        const char *q = p + 4;      /* past "uid="                          */
        int digits = 0;
        while (*q >= '0' && *q <= '9') {
            q++;
            digits++;
        }
        if (digits > 0 && *q == '(')
            return 1;
        p = q;                      /* keep scanning for the next "uid=".   */
    }
    return 0;
}

/* Everything the pty has ever produced, scanned after every drain so a
 * marker straddling a read() boundary cannot be missed. */
static char transcript[65536];

/* drain_master() -- read the pty master for up to `ms` ms, echo to stdout,
 * and append to the transcript. select() with a deadline keeps us from
 * spinning while the (interactive, silent) shell thinks. */
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

    while (select(master + 1, &rfds, NULL, NULL, &tv) > 0) {
        ssize_t n = read(master, buf, sizeof(buf));
        if (n <= 0)
            break;
        fwrite(buf, 1, (size_t)n, stdout);
        fflush(stdout);
        total += (int)n;
        if ((size_t)total < sizeof(transcript) - 1)
            strncat(transcript, buf, (size_t)n);

        /* A chatty peer should not hold us forever: reset the deadline. */
        FD_ZERO(&rfds);
        FD_SET(master, &rfds);
        tv.tv_sec  = 0;
        tv.tv_usec = 200000;
    }
    return total;
}

static const char *technique_of(int argc, char **argv)
{
    for (int i = 1; i + 1 < argc; i++)
        if (strcmp(argv[i], "-t") == 0)
            return argv[i + 1];
    return "(default: shellcode)";
}

int main(int argc, char **argv)
{
    int            master;
    char           slave_name[256];
    struct termios saved;
    int            have_saved = 0;
    pid_t          pid;
    int            ok = 0;         /* marker seen                            */
    int            saw_id = 0;     /* "uid=" seen: real program ran          */
    int            saw_root = 0;   /* "uid=0(" seen: it was root            */
    int            must_root = 0;  /* --must-root flag                       */
    int            round;

    /* True when --must-root is present: the verdict then demands uid=0. */
    for (int i = 1; i < argc; i++)
        if (strcmp(argv[i], "--must-root") == 0)
            must_root = 1;

    /* ---- 1. Allocate a pty. ------------------------------------------ */
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

    /* ---- 2. Fork; the child becomes the pty slave and execs foosc. --- */
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

        /* Forward everything except our own --must-root / --dump plumbing,
         * which foosc's getopt() would reject. */
        args[n++] = (char *)"./foosc";
        for (int i = 1; i < argc && n < 63; i++) {
            if (strcmp(argv[i], "--must-root") == 0)
                continue;
            if (strcmp(argv[i], "--dump") == 0) {
                i++;
                continue;
            }
            args[n++] = argv[i];
        }
        args[n] = NULL;
        execv(args[0], args);
        _exit(127);
    }

    /* ---- 3. Terminal: cooked but SILENT. ----------------------------- */
    /* NOT cfmakeraw(): the shell needs a real line-discipline terminal.
     * ECHO off is load-bearing (see the header comment). ECHONL stays on so
     * we still see the newline when the pty processes our input. */
    if (tcgetattr(master, &saved) == 0) {
        struct termios quiet = saved;
        have_saved = 1;
        quiet.c_lflag &= ~(tcflag_t)ECHO;
        quiet.c_lflag |= ECHONL;
        tcsetattr(master, TCSANOW, &quiet);
    }

    /* ---- 4. Wait out foosc's analysis + connect + payload phases. ----- */
    for (round = 0; round < 12; round++)
        drain_master(master, 250);

    /* ---- 5. Type the proof commands. --------------------------------- */
    dprintf(master, "id; echo " MARKER "; uname -sr; exit\n");

    /* ---- 6. Read until we have the signals we need (or give up). ----- */
    for (round = 0; round < 20; round++) {
        drain_master(master, 250);

        /* Rescan the WHOLE transcript, not the latest chunk: strings can
         * straddle read() boundaries. */
        if (strstr(transcript, MARKER) != NULL)      ok = 1;
        if (saw_real_uid_output(transcript))          saw_id = 1;
        if (strstr(transcript, ROOTOUT) != NULL)      saw_root = 1;

        /* --must-root: require everything. Otherwise require a live shell. */
        if (must_root) {
            if (ok && saw_id && saw_root)
                break;
        } else if (ok && saw_id) {
            break;
        }
    }

    /* ---- 7. Tidy up. ------------------------------------------------- */
    kill(pid, SIGKILL);
    waitpid(pid, NULL, 0);
    if (have_saved)
        tcsetattr(master, TCSANOW, &saved);
    close(master);

    /* Optional --dump for post-mortems:  pty_suid_test -t shellcode --dump x */
    for (int i = 1; i + 1 < argc; i++) {
        if (strcmp(argv[i], "--dump") == 0) {
            FILE *f = fopen(argv[i + 1], "w");
            if (f != NULL) {
                fwrite(transcript, 1, strlen(transcript), f);
                fclose(f);
                fprintf(stderr, "[pty_suid_test] transcript (%zu bytes) -> %s\n",
                        strlen(transcript), argv[i + 1]);
            }
        }
    }

    fprintf(stderr,
            "\n[pty_suid_test] technique=%-12s marker=%-7s id_output=%-7s root=%s\n",
            technique_of(argc, argv),
            ok ? "SEEN" : "MISSING",
            saw_id ? "SEEN" : "MISSING",
            saw_root ? "SEEN" : "MISSING");

    if (must_root)
        return (ok && saw_id && saw_root) ? 0 : 1;
    return (ok && saw_id) ? 0 : 1;
}