/*
 * ============================================================================
 * foosd.c  --  "foosd": an INTENTIONALLY VULNERABLE SUID-ROOT network daemon
 * ============================================================================
 *
 *  PURPOSE
 *  -------
 *  This is the SUID companion to `food`. Where `food` demonstrated how a
 *  buffer overflow becomes remote code execution, `foosd` demonstrates what
 *  happens when that RCE lands in a process whose *effective* uid is 0
 *  (root) because the binary has the setuid bit set.
 *
 *  Run it without the setuid bit and you get a normal user shell, exactly as
 *  with food. Give the binary the setuid bit (`sudo make setuid`) and the
 *  exact same exploit-shipped shellcode opens a *root* shell -- because the
 *  process the shellcode runs in already has euid 0, and the shellcode is
 *  careful to clear the *real* uid as well (see the comment in foosc.c).
 *
 *  This lab exists so you understand, hands-on, why "SUID bit + any reachable
 *  memory-corruption bug" is one of the most dangerous combinations in Unix,
 *  and -- the other half of the lesson -- why a carefully written SUID
 *  program is not necessarily safe either: the setuid bit silently changes
 *  the meaning of EVERY bug in the program.
 *
 *  WHAT THE SETUID BIT ACTUALLY DOES
 *  --------------------------------
 *  Every process carries three user ids:
 *
 *      real uid (ruid)       the account that STARTED the process
 *      effective uid (euid)  what the kernel checks when making decisions
 *      saved uid  (suid)     the "slot" a privileged process may return to
 *
 *  A normal program has ruid == euid == saver. When you run a setuid binary:
 *
 *      ruid = you            (e.g. 1000, hanez)
 *      euid = the file owner (e.g. 0, root)
 *
 *  The process is *root for all access-control purposes* even though the user
 *  who launched it is not. Every program under test in this lab is a child of
 *  that process (the daemon forks per connection), so each child also has
 *  euid 0. THAT is the whole attack surface the exploit aims at.
 *
 *  THE CRUCIAL SECOND FACT -- WHY THIS LAB NEEDS setreuid SHELLCODE
 *  ----------------------------------------------------------------
 *  The classic "I got root, I'll just spawn /bin/sh" does NOT work from a
 *  setuid process, and the reason is a defence built into the shell itself:
 *
 *      When bash (and dash, and most shells) starts with euid != ruid and is
 *      NOT given the `-p` (privileged) flag, it sets euid = ruid and walks
 *      away from the privilege. Bash documented this in its manual page. It
 *      exists precisely to stop a setuid binary from dropping the attacker
 *      into a root shell.
 *
 *  So in this lab:
 *      win()                 -> execl("/bin/sh")      -> shell, but uid 1000
 *      system("/bin/sh")     -> ret2libc              -> shell, but uid 1000
 *      shellcode without
 *      setreuid(0,0)         -> execl                 -> shell, but uid 1000
 *      shellcode WITH
 *      setreuid(0,0)         -> ruid becomes 0, bash sees equal uids,
 *                              keeps euid 0           -> ROOT SHELL
 *
 *  The shellcode in foosc.c therefore begins with setreuid(0, 0). That is the
 *  same reason the classic 24-byte /bin/sh shellcode you will find all over
 *  the internet starts with a setuid(0) syscall.
 *
 *  SAFETY RAILS (please keep them in place)
 *  ----------------------------------------
 *    * Binds to 127.0.0.1 by default and REFUSES a non-loopback bind unless
 *      you pass -L. A setuid-root process listening on a real interface is a
 *      remote root hole waiting for a port scan. Do not do it.
 *    * Prints a startup warning to the log when it detects that it IS running
 *      with euid 0, because a well-designed daemon has no business being
 *      root on an unprivileged port (2343 > 1024).
 *    * Does not bind on 0.0.0.0 even with -L unless you also give -h 0.0.0.0;
 *      -L merely lifts the loopback *guard*.
 *
 *  Build:  make foosd            (as your normal user)
 *          sudo make setuid      (once, gives foosd the +s bit and root owner)
 *
 *  THE BUILD FLAGS ARE THE SAME DELIBERATE REMOVALS AS food
 *  --------------------------------------------------------
 *    -fno-stack-protector   no canary: the overflow is not detected
 *    -no-pie                fixed addresses: win(), win_root() are constants
 *    -z execstack           the stack is executable: shellcode can run
 *
 *  `make hardened` rebuilds this file with all three re-enabled, which stops
 *  every technique, and `make test-hardened` shows you the log evidence.
 *  Note carefully in README.md: NOT ONE of those compiler mitigations does
 *  anything about the "the binary is setuid root" design decision. Memory
 *  safety and least privilege are two separate problems.
 *
 *  Usage:  ./foosd [-h HOST] [-p PORT] [-d] [-L]
 * ============================================================================
 */

/* Request the gnu decls we need (dprintf, etc.). */
#define _GNU_SOURCE

#include <arpa/inet.h>  /* inet_pton(): parse "127.0.0.1" into bytes.        */
#include <errno.h>     /* errno, strerror().                                 */
#include <fcntl.h>     /* dup2() -- hand the accepted socket to the shell.   */
#include <grp.h>       /* setgroups(): part of the (never-called) privilege
                        * drop -- supplementary groups must go first.        */
#include <netinet/in.h>/* struct sockaddr_in, htons().                       */
#include <signal.h>    /* signal(), sigaction().                             */
#include <stdarg.h>    /* va_list for our log wrapper.                       */
#include <stdint.h>    /* uint16_t.                                          */
#include <stdio.h>     /* dprintf, snprintf.                                 */
#include <stdlib.h>    /* atoi, _exit, getenv.                               */
#include <string.h>    /* memset, strncmp, memchr, strlen.                   */
#include <sys/socket.h>/* socket, bind, listen, accept.                      */
#include <sys/stat.h>  /* umask.                                             */
#include <sys/types.h> /* ssize_t, pid_t.                                    */
#include <sys/ucontext.h>/* ucontext_t: REG_RIP etc. for the crash reporter. */
#include <sys/wait.h>  /* waitpid().                                         */
#include <unistd.h>    /* read, write, dup2, fork, getpid, setsid, chdir.    */

/* ------------------------------------------------------------------------- */
/* Configuration constants                                                    */
/* ------------------------------------------------------------------------- */

/* Port. 2343 is deliberately not the 2342 used by food, so both labs can run
 * side by side. It is above 1024 --- which is itself a teaching point: a
 * correct daemon does not need root to bind this port, so being setuid is a
 * design mistake, not a requirement. */
#define FOOSD_PORT 2343

/* Loopback is the ONLY default. -L is required to go further. */
#define FOOSD_HOST "127.0.0.1"

/* Size of the overflowed buffer. Same shape as food so the exploit's
 * objdump-based offset detection (shared logic) works unchanged. */
#define FOOSD_BUFSZ 64

/* How much read() accepts. The mismatch with FOOSD_BUFSZ IS the bug. */
#define FOOSD_READMAX 512

/* Size of the second (format-string demo) buffer. */
#define FOOSD_LOGSZ 128

/* ------------------------------------------------------------------------- */
/* Logging (same design as food: the log never travels to the attacker)       */
/* ------------------------------------------------------------------------- */

/* g_logfd -- a private copy of stdout taken BEFORE the socket is dup2()'d
 * over fd 1. Every logmsg() line goes here, so a client that overwrites our
 * memory or crashes a child never learns internal paths or addresses from
 * logs (and never mixes its own bytes with ours). */
static int g_logfd = -1;

/* logmsg() -- timestamped, pid-prefixed line to the log descriptor. One
 * write() per line, so forked children cannot interleave mid-line. */
static void logmsg(const char *fmt, ...)
{
    char    line[1024];       /* Whole-message scratch.                     */
    va_list ap;               /* Variadic argument cursor.                  */
    int     n;                /* Bytes formatted.                           */

    /* va_start MUST precede any use of ap. An uninitialised va_list makes
     * vsnprintf walk wild stack memory -- a real bug that was hit in the
     * earlier food.c, hence the comment. */
    va_start(ap, fmt);
    n = vsnprintf(line, sizeof(line) - 32, fmt, ap);
    va_end(ap);               /* Always pair va_start with va_end.          */
    if (n < 0)
        return;

    if (g_logfd >= 0)
        dprintf(g_logfd, "[foosd %d] %s\n", (int)getpid(), line);
}

/* read_exact() / write_all() -- the CORRECT I/O helpers, present so you can
 * hold them next to the deliberately broken read() in vulnerable_handler()
 * and see the difference: these loop until done and check every result. */
__attribute__((unused))
static ssize_t read_exact(int fd, void *buf, size_t n)
{
    size_t got = 0;
    while (got < n) {
        ssize_t r = read(fd, (char *)buf + got, n - got);
        if (r < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (r == 0)
            break;
        got += (size_t)r;
    }
    return (ssize_t)got;
}

static ssize_t write_all(int fd, const void *buf, size_t n)
{
    size_t sent = 0;
    while (sent < n) {
        ssize_t w = write(fd, (const char *)buf + sent, n - sent);
        if (w <= 0) {
            if (w < 0 && errno == EINTR)
                continue;
            return -1;
        }
        sent += (size_t)w;
    }
    return (ssize_t)sent;
}

/* ------------------------------------------------------------------------- */
/* The ret2win targets                                                        */
/* ------------------------------------------------------------------------- */

/*
 * win() -- the "easy" backdoor, and the reason a whole section of README.md
 * exists. It is the same function as in food.c with ONE addition's worth of
 * subtlety:
 *
 *   execl("/bin/sh", "sh", NULL)
 *
 * gives the attacker a shell, but NOT a root shell, even though THIS process
 * has euid 0, because bash/dash reset euid = ruid at startup when the two
 * differ (and here ruid is still the launching user, e.g. 1000). So win()
 * is a demonstration of control-flow hijack, and at the same time a real,
 * documented example of a defence (the shell's privilege guard) that spoils
 * what would otherwise be a one-line root shell.
 *
 * It is also precisely the trap people fall into with "SUID + system()": the
 * injected command runs in a shell that just dropped the effective id, so on
 * modern systems the classic setuid+system() trick no longer yields root --
 * see README.md's "why the old one-liners fail" section.
 */
__attribute__((noinline, used))
static void win(void)
{
    pid_t pid;

    logmsg("win() reached -- exec'ing /bin/sh (uid will NOT be root while "
           "euid!=ruid: the shell resets it; use win_root or shellcode for "
           "a real root shell)");

    /* Fork so the daemon's accept loop child can be reaped and return. */
    pid = fork();
    if (pid < 0) {
        logmsg("win(): fork() failed: %s", strerror(errno));
        _exit(1);
    }
    if (pid > 0) {
        waitpid(pid, NULL, 0);
        /* Must NOT return: that would pop attacker bytes as the next RIP. */
        _exit(0);
    }

    /* Child. prepare_client_fds() already made fds 0/1/2 the socket. */
    execl("/bin/sh", "sh", (char *)NULL);
    _exit(127);           /* Only reached if exec failed.                 */
}

/*
 * win_root() -- the "privileged" backdoor. Byte-for-byte the same function
 * as win() EXCEPT it first calls setreuid(0, 0).
 *
 * Why does that one line matter? Seeing it is the difference between a
 * broken exploit and a root shell, so it deserves a close look:
 *
 *   * setuid(0)     would set euid = 0 and saved = 0 but LEAVE ruid = 1000.
 *                   bash would then still see euid != ruid and still reset.
 *   * setreuid(0,0) sets BOTH real and effective to 0, and (being privileged)
 *                   Linux also sets the saved id to 0.
 *                   bash now sees euid == ruid == 0 and keeps root.
 *
 * That is why classic /bin/sh shellcode begins with a uid-clearing syscall:
 * the "real" uid is the one the shell's guard compares against, and it must
 * be cleared too. This function exists so `foosc -t ret2win-root` has a
 * second, plain-C way to reach root and you can compare the two backdoors
 * directly in the debugger.
 */
__attribute__((noinline, used))
static void win_root(void)
{
    pid_t pid;

    /* Nothing to check: a setuid process may set its uids arbitrarily. If
     * foosd is NOT setuid this fails silently and the result is simply a
     * non-root shell -- the lab works either way, which is deliberate. */
    (void)setreuid(0, 0);

    logmsg("win_root() reached -- setreuid(0,0) done, exec'ing /bin/sh");

    pid = fork();
    if (pid < 0) {
        logmsg("win_root(): fork() failed: %s", strerror(errno));
        _exit(1);
    }
    if (pid > 0) {
        waitpid(pid, NULL, 0);
        _exit(0);
    }

    execl("/bin/sh", "sh", (char *)NULL);
    _exit(127);
}

/* ------------------------------------------------------------------------- */
/* The vulnerable handler -- Bug #1 and Bug #2 live here                     */
/* ------------------------------------------------------------------------- */

__attribute__((noinline, used))
static void vulnerable_handler(int fd)
{
    char buf[FOOSD_BUFSZ];    /* 64 stack bytes. The whole ballgame.        */
    char line[FOOSD_LOGSZ];   /* Second buffer, for the format-string demo. */
    ssize_t n;                /* Bytes actually read.                      */

    /*
     * The BUF= leak -- the same deliberate CWE-200 disclosure as food. The
     * stack is ASLR-randomised; without this the shellcode could not find
     * itself. Real-world leaks of this kind come from %p format bugs, crash
     * dumps, debug endpoints, or serialised uninitialised pointers.
     *
     * FIX: never print addresses to untrusted clients.
     */
    dprintf(fd, "BUF=%p\n", (void *)buf);

    /*
     * ====================================================================
     * BUG #1 -- UNBOUNDED COPY INTO A FIXED STACK BUFFER   (CWE-120)
     * ====================================================================
     * Identical to food: 512 bytes are accepted into a 64-byte array, so the
     * attacker writes 448 bytes past the end, overwriting the saved frame
     * pointer and — 8 bytes later — the saved return address. On return,
     * `ret` jumps wherever the attacker said:
     *
     *      [ 64 bytes buf ][ 8 bytes saved rbp ][ 8 bytes RETURN ADDRESS ]
     *
     * The ONLY difference from food is *what that means*: here the hijacked
     * process has euid 0, so "attacker controls RIP" becomes "attacker
     * controls root's RIP".
     *
     * FIXES (in increasing order of strength):
     *   1. n = read(fd, buf, sizeof(buf) - 1);            <-- the real fix
     *   2. -fstack-protector-strong (canary aborts `ret`)
     *   3. do not take network input into fixed stack buffers at all
     * And SEPARATELY: do not run this daemon setuid. Memory safety and
     * least privilege are two different bugs; fix both.
     */
    n = read(fd, buf, FOOSD_READMAX);       /* <-- CWE-120, THE bug.        */
    if (n <= 0)
        return;

    /* Echo back a truncated copy so you can watch the overflow in the log.
     * Clamping for display does not undo the overwrite that already happened. */
    {
        ssize_t show = n < FOOSD_BUFSZ ? n : FOOSD_BUFSZ;
        logmsg("vulnerable_handler: read %zd bytes, echoing %zd", n, show);
        (void)write_all(fd, buf, (size_t)show);
    }

    /*
     * ====================================================================
     * BUG #2 -- NETWORK DATA USED AS A FORMAT STRING        (CWE-134)
     * ====================================================================
     * Same as food: attacker '%'-specifiers in `buf` could read stack words
     * with %x or write memory with %n. Here -- setuid root -- a %n is a
     * write-what-where primitive IN A ROOT PROCESS, so this second bug is
     * worse than it was in food. It runs only on a copy in `line`, and only
     * triggers if the payload contains '%'.
     *
     * FIX: printf("%s", buf), never printf(buf).
     */
    if (memchr(buf, '%', (size_t)n) != NULL) {
        snprintf(line, sizeof(line), "%.*s", (int)FOOSD_LOGSZ - 1, buf);
        logmsg("vulnerable_handler: payload contains '%%', echoing it raw");
        (void)write_all(fd, line, strlen(line));
    }

    /* On return the (attacker-controlled) saved return address becomes RIP. */
}

/* ------------------------------------------------------------------------- */
/* Crash reporter (same rationale as food: a crash should tell you it was     */
/* malicious; the fault address is the return address the client supplied).   */
/* ------------------------------------------------------------------------- */

static void on_sigsegv(int sig, siginfo_t *si, void *ucv)
{
    ucontext_t *uc = (ucontext_t *)ucv;
    unsigned long rip = 0, rsp = 0;

    if (uc != NULL) {
        rip = (unsigned long)uc->uc_mcontext.gregs[REG_RIP];
        rsp = (unsigned long)uc->uc_mcontext.gregs[REG_RSP];
    }

    logmsg("SIGSEGV: faulting address %p", si ? si->si_addr : (void *)0);
    logmsg("SIGSEGV: RIP=%#lx  RSP=%#lx  (RIP is the address the client "
           "supplied)", rip, rsp);
    logmsg("SIGSEGV: if RIP is a real address the attacker jumped there; "
           "if it looks like 0x4028xx it may BE the `ret` itself: a ret "
           "into a non-canonical address (e.g. 0x4141414141414141) faults "
           "at the ret, not at the target.");

    /* Re-raise with the default disposition so the process still dies, with
     * the correct status, rather than re-executing the faulting instruction
     * forever (returning from this handler would do exactly that). */
    signal(sig, SIG_DFL);
    raise(sig);
}

static void install_crash_reporter(void)
{
    struct sigaction sa;

    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = on_sigsegv;   /* Extended two-argument handler.       */
    sa.sa_flags     = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);

    if (sigaction(SIGSEGV, &sa, NULL) < 0)
        logmsg("sigaction(SIGSEGV) failed: %s", strerror(errno));
    if (sigaction(SIGBUS,  &sa, NULL) < 0)
        logmsg("sigaction(SIGBUS) failed: %s", strerror(errno));
}

/* ------------------------------------------------------------------------- */
/* fd handling                                                                */
/* ------------------------------------------------------------------------- */

/* prepare_client_fds() -- put the accepted socket onto fds 0/1/2 so that
 * every technique (ret2win, ret2libc, shellcode) produces a shell that
 * automatically speaks over the network. */
static void prepare_client_fds(int fd)
{
    if (fd != STDIN_FILENO)  dup2(fd, STDIN_FILENO);
    if (fd != STDOUT_FILENO) dup2(fd, STDOUT_FILENO);
    if (fd != STDERR_FILENO) dup2(fd, STDERR_FILENO);
    if (fd > STDERR_FILENO)  close(fd);   /* Don't leak the spare descriptor.*/
}

/* ------------------------------------------------------------------------- */
/* THE INFORMATION LEAK                                                       */
/* ------------------------------------------------------------------------- */

/*
 * send_leaks() -- tell the attacker:
 *
 *   ids=               this process's euid/ruid. THE SUID DIAGNOSTIC.
 *                      The exploit prints a warning when euid is not 0,
 *                      because without the setuid bit there will be no root
 *                      shell and the user would otherwise think the exploit
 *                      is broken.
 *   leak stack=...     an address on the stack, for the shellcode
 *   leak libc=...      the real address of read() inside libc, for ret2libc
 *
 * The `ids=` spelling (rather than "euid="/"ruid=") is deliberate: the test
 * harness proves a live shell by grepping for the string "uid=" in the
 * session transcript, and "euid=" / "ruid=" both contain that substring, so
 * printing them would make the banner itself pass the check. The ids= form
 * cannot be confused with a shell's `id` output. This kind of "the probe and
 * the answer must not share a signature" thinking is exactly what you do
 * when you write real assertions about untrusted output.
 */
static void send_leaks(int fd)
{
    long stack_marker = 0x4141414141414141L;  /* Obvious in a debugger.     */
    ssize_t (*libc_read)(int, void *, size_t);/* Real address of read().    */

    libc_read = &read;        /* &read resolves through the GOT to libc.    */

    dprintf(fd, "FOOSD 1.0 ids=%d/%d leak stack=%p libc=%p\n",
            (int)geteuid(), (int)getuid(),
            (void *)&stack_marker, (void *)libc_read);
}

/* THE CORRECT DESIGN, PRESENT BUT NEVER CALLED
 * -------------------------------------------
 * drop_privs() -- what a well-written daemon would do the moment it no
 * longer needs root. Two mistakes to notice, both of which are immune to
 * every compiler mitigation:
 *
 *   * ORDER: you must drop in the order gid-capabilities that matter --
 *     setgroups() before setgid() before setuid(), and only AFTER binding
 *     the port and opening any root-only files. Drop first and the whole
 *     point of root is gone.
 *   * PERMANENCE: setuid() to a nonzero value and check it stuck (a root
 *     process may later regain privileges via saved id otherwise).
 *
 * In this lab it is deliberately absent from the accept loop, because the
 * lab NEEDS the children to stay root. Keeping the correct version in the
 * source, commented, lets you diff "what should be here" against "what is
 * here" -- the two-line difference is the entire exploit surface.
 */
__attribute__((unused))
static void drop_privs(void)
{
    /* Order matters: setgroups() first (a non-root user may not), then
     * setgid(), then setuid(). Never the reverse. */
    (void)setgroups(0, NULL);          /* Remove all supplementary groups.  */
    (void)setgid(1000);                /* Lose group privileges.            */
    if (setuid(1000) < 0)              /* Any non-zero uid is fine here.    */
        _exit(1);                      /* If we cannot drop, FAIL CLOSED.   */

    /* Verify. getuid()/geteuid() are cheap; a SUID program whose drop failed
     * silently is a root hole wearing a costume. */
    if (getuid() != 1000 || geteuid() != 1000)
        _exit(1);
}

/* ------------------------------------------------------------------------- */
/* Per-connection handling                                                    */
/* ------------------------------------------------------------------------- */

static void handle_client(int fd)
{
    static const char banner[] =
        "FOOSD 1.0 - deliberately vulnerable SUID service\n"
        "Type 'quit' to disconnect. Buffer = 64 bytes, read accepts 512.\n";

    prepare_client_fds(fd);    /* fds 0,1,2 now all point at the socket.    */
    install_crash_reporter();  /* Log (g_logfd) lines, not to the socket.   */

    logmsg("client connected (uid=%d euid=%d)", (int)getuid(), (int)geteuid());

    (void)write_all(STDOUT_FILENO, banner, sizeof(banner) - 1);
    send_leaks(STDOUT_FILENO);

    vulnerable_handler(STDOUT_FILENO);

    /* Only reached when the payload did NOT hijack RIP. */
    logmsg("vulnerable_handler returned normally -- payload did not hijack RIP");
    (void)write_all(STDOUT_FILENO, "OK: no hijack, disconnecting.\n", 29);
}

/* ------------------------------------------------------------------------- */
/* The server loop                                                           */
/* ------------------------------------------------------------------------- */

static int make_listener(const char *host, int port)
{
    struct sockaddr_in addr;
    int fd;
    int one = 1;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        logmsg("socket() failed: %s", strerror(errno));
        return -1;
    }

    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) < 0)
        logmsg("setsockopt(SO_REUSEADDR) failed: %s", strerror(errno));

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port   = htons((uint16_t)port);

    if (inet_pton(AF_INET, host, &addr.sin_addr) != 1) {
        logmsg("bad bind address: %s", host);
        close(fd);
        return -1;
    }

    if (port < 1 || port > 65535) {
        logmsg("port out of range: %d", port);
        close(fd);
        return -1;
    }

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        logmsg("bind(%s:%d) failed: %s", host, port, strerror(errno));
        close(fd);
        return -1;
    }

    if (listen(fd, 16) < 0) {
        logmsg("listen() failed: %s", strerror(errno));
        close(fd);
        return -1;
    }

    return fd;
}

static void usage(const char *argv0)
{
    fprintf(stderr,
            "usage: %s [-h HOST] [-p PORT] [-d] [-L]\n"
            "\n"
            "  -h HOST   address to bind (default %s -- loopback only!\n"
            "            -L is required to bind anywhere else)\n"
            "  -p PORT   TCP port to listen on (default %d)\n"
            "  -d        daemonise: fork into the background\n"
            "  -L        ALLOW binding to a non-loopback address (dangerous:\n"
            "            this binary is meant to be run SETUID ROOT)\n"
            "\n"
            "WARNING: this program is intentionally exploitable AND is meant\n"
            "to be run setuid root. Do not run it on any host that matters,\n"
            "never bind it beyond loopback, and remove the setuid bit with\n"
            "`sudo make unsetuid` when you are done.\n",
            argv0, FOOSD_HOST, FOOSD_PORT);
}

int main(int argc, char **argv)
{
    const char *host = FOOSD_HOST;   /* Bind address.                        */
    int         port = FOOSD_PORT;   /* Bind port.                           */
    int         daemonise = 0;       /* -d.                                  */
    int         allow_nonloopback = 0; /* -L. The setuid safety guard.       */
    int         lfd;                 /* Listening socket.                    */
    int         i;                   /* getopt() index.                      */

    while ((i = getopt(argc, argv, ":h:p:dL")) != -1) {
        switch (i) {
        case 'h': host = optarg; break;
        case 'p': port = atoi(optarg); break;
        case 'd': daemonise = 1; break;
        case 'L': allow_nonloopback = 1; break;
        case ':': fprintf(stderr, "missing argument to -%c\n", optopt);
                  usage(argv[0]);
                  return 2;
        default:  usage(argv[0]);
                  return 2;
        }
    }

    /*
     * THE SETUID SAFETY GUARD.
     *
     * A setuid-root process that listens on a non-loopback interface is a
     * remote root service. This guard is not a mitigation, it is a default:
     * the administrator must consciously type -L to override it. Refuse by
     * default, document the exception, fail loudly.
     */
    if (!allow_nonloopback &&
        (strcmp(host, "127.0.0.1") != 0 && strcmp(host, "localhost") != 0 &&
         strcmp(host, "::1") != 0)) {
        fprintf(stderr,
                "foosd: refusing to bind %s: this binary may be setuid root.\n"
                "       Loopback is the only permitted default. If you really\n"
                "       know what you are doing, pass -L.\n", host);
        return 1;
    }

    signal(SIGPIPE, SIG_IGN);
    signal(SIGCHLD, SIG_IGN);      /* Auto-reap forked children.            */

    /* Reserve a private log descriptor BEFORE sockets are dup2'd over fd 1. */
    g_logfd = dup(STDOUT_FILENO);
    if (g_logfd < 0) {
        g_logfd = STDOUT_FILENO;
        fprintf(stderr, "foosd: warning: could not reserve a log descriptor\n");
    }

    /*
     * SELF-DIAGNOSIS OF THE SUID STATE -- printed once, to the log.
     *
     *   "suid active":  euid==0 and ruid!=0  -> a setuid-root binary
     *   "run as root":  euid==0 and ruid==0  -> started by root directly
     *   "plain user":   euid==ruid!=0        -> +s bit not set (yet)
     *
     * foosc reads euid over the socket and can warn too; this log line is
     * for you at the console.
     */
    logmsg("startup: ruid=%d euid=%d %s",
           (int)getuid(), (int)geteuid(),
           (geteuid() == 0) ? "-> ROOT process"
                            : "-> NOT root (set the setuid bit with make setuid)");

    if (geteuid() == 0)
        logmsg("startup: WARNING: this daemon is running as root. It exists "
               "only to be exploited. Port %d does not need root.", port);

    lfd = make_listener(host, port);
    if (lfd < 0)
        return 1;

    logmsg("listening on %s:%d (pid %d) -- THIS SERVICE IS INTENTIONALLY "
           "VULNERABLE", host, port, (int)getpid());

    if (daemonise) {
        /* Standard double fork so we cannot acquire a controlling terminal. */
        pid_t p1 = fork();
        if (p1 < 0) { perror("fork"); return 1; }
        if (p1 > 0) _exit(0);
        if (setsid() < 0) perror("setsid");
        pid_t p2 = fork();
        if (p2 < 0) { perror("fork"); return 1; }
        if (p2 > 0) _exit(0);
        if (chdir("/") < 0) perror("chdir");
        umask(022);
    }

    /* ---- The accept loop. Each child serves one connection as root. ----- */
    for (;;) {
        struct sockaddr_in peer;
        socklen_t       plen = sizeof(peer);
        int             cfd;
        pid_t           pid;

        cfd = accept(lfd, (struct sockaddr *)&peer, &plen);
        if (cfd < 0) {
            if (errno == EINTR || errno == ECONNABORTED)
                continue;
            logmsg("accept() failed: %s", strerror(errno));
            continue;
        }

        /*
         * Fork per connection. The child KEEPS the root privileges -- that
         * is Bug #3 in this lab, "no privilege drop before handling
         * untrusted input" (CWE-271). See drop_privs() above for the code
         * a real daemon would call at this exact point.
         */
        pid = fork();
        if (pid < 0) {
            logmsg("fork() failed: %s", strerror(errno));
            close(cfd);
            continue;
        }

        if (pid == 0) {
            close(lfd);
            handle_client(cfd);
            _exit(0);
        }

        close(cfd);
    }
}