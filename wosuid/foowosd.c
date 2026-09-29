/*
 * ============================================================================
 * foowosd.c  --  "foowosd": an INTENTIONALLY VULNERABLE daemon that becomes
 *               root the honest way: by being STARTED as root.
 * ============================================================================
 *
 *  PURPOSE
 *  -------
 *  This is the "no setuid bit" companion to the other two labs:
 *
 *      food   / fooc     a plain daemon: the overflow gives you a user shell
 *      foosd  / foosc    a SETUID-root daemon: root arrives via the +s bit
 *      foowosd/ foowosc  THIS one: no +s bit anywhere. Root arrives because
 *                        somebody STARTED the process as root.
 *
 *  The setuid bit is not the only way a process ends up privileged. Any
 *  daemon launched by root -- a `sudo ./foowosd`, a systemd unit with
 *  `User=root`, an init script -- has real uid 0, effective uid 0, and saved
 *  uid 0. To the kernel and to every access-control check it makes, that
 *  process IS root, indistinguishable from one that arrived there via +s.
 *  And an overflow in a root process is a root exploit, filesystem
 *  attributes notwithstanding.
 *
 *  THAT is the lesson of this file: the setuid bit is a *transfer vehicle*
 *  for privilege, not the privilege itself. "I don't have SUID binaries" is
 *  NOT the same as "I am not vulnerable to privilege escalation". If your
 *  daemon runs as root and it has a reachable memory-safety bug, you have a
 *  root-exploit -- with or without the letter 's' in anyone's file mode.
 *
 *  WHY THE EXPLOIT HERE IS DIFFERENT FROM THE SUID LAB -- ruid
 *  ----------------------------------------------------------
 *  A setuid-root binary gives the process euid 0 but LEAVES ruid at the
 *  launching user's id (1000). bash and dash notice `euid != ruid` at
 *  startup and reset euid = ruid -- the shell's own guard against this
 *  attack -- which is why foosc's shellcode had to call setreuid(0,0) first.
 *
 *  A daemon *started* as root has ruid == euid == 0. There is no mismatch
 *  for the shell's guard to notice, so a plain `execve("/bin/sh")` keeps
 *  root -- no setreuid needed. The same 23 bytes that pwnd `food` in the
 *  parent lab, byte for byte, open a *root* shell against this daemon,
 *  because the process they run in is already fully root. The shellcode
 *  chosen for foowosc therefore does not contain a setreuid prefix.
 *
 *  SAFETY RAILS (identical policy to the SUID lab -- a root daemon is no
 *  less dangerous because it got there without +s)
 *  -------------------------------------------------
 *    * Binds 127.0.0.1 by default and REFUSES a non-loopback bind unless you
 *      pass -L. A root daemon on a real interface is a remote root service.
 *    * Logs at startup whether it is running as root or as a normal user, so
 *      you always know which exploit outcome to expect.
 *    * Same deliberate bugs as food/foosd, so the whole toolchain
 *      (objdump-based offset discovery, leak parsing, alignment fix, pty
 *      harness) carries over unchanged.
 *
 *  Build:  make foowosd
 *          make run-root      (needs sudo; starts the daemon as real root)
 *          make run-root-ns   (no sudo: user-namespace root, for verification)
 *          make run           (baseline: starts it as your normal user)
 *
 *  HOW TO BECOME ROOT HERE -- and how NOT to
 *  -----------------------------------------
 *    START AS ROOT:      sudo make run-root      -> ruid=0 euid=0
 *    START AS ROOT (ns): make run-root-ns        -> namespaced 0/0 (test-only)
 *    PLAIN USER:         make run                -> ruid=1000 euid=1000
 *
 *  The exploit behaves the same in all three cases -- it just yields a root
 *  shell in the first two. That "the agency, not the attribute, is what
 *  matters" property is the whole point of this lab.
 *
 *  THE BUILD FLAGS (same deliberate removals as the other two labs)
 *  ----------------------------------------------------------------
 *    -fno-stack-protector   no canary: the overflow is not detected
 *    -no-pie                fixed addresses: win() is a constant
 *    -z execstack           executable stack: shellcode can run
 *
 *  `make hardened` re-enables all three; the maliciously shareable lesson is
 *  that those flags do nothing about the "running as root" design decision.
 *
 *  Usage:  ./foowosd [-h HOST] [-p PORT] [-d] [-L]
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
#include <stdlib.h>    /* atoi, _exit.                                       */
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

/* Port. 2344 keeps this lab clear of food (2342) and foosd (2343). It is
 * above 1024 on purpose: binding it needs NO privilege, so root here is
 * pure design smell -- a correct daemon would drop privileges after bind,
 * and the lab's whole point is what happens when it does not. */
#define FOOWOSD_PORT 2344

/* Loopback is the ONLY default. -L is required to go further. */
#define FOOWOSD_HOST "127.0.0.1"

/* Size of the overflowed buffer. Same shape as food/foosd so the shared
 * objdump-based offset detection works unchanged. */
#define FOOWOSD_BUFSZ 64

/* How much read() accepts. The mismatch with FOOWOSD_BUFSZ IS the bug. */
#define FOOWOSD_READMAX 512

/* Size of the second (format-string demo) buffer. */
#define FOOWOSD_LOGSZ 128

/* ------------------------------------------------------------------------- */
/* Logging (same design as the other labs: the log never reaches the attacker)*/
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
        dprintf(g_logfd, "[foowosd %d] %s\n", (int)getpid(), line);
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
/* The ret2win target                                                         */
/* ------------------------------------------------------------------------- */

/*
 * win() -- the "easy" backdoor. The same function as in food.c and foosd.c,
 * and the difference between this lab and the SUID lab is contained in it.
 *
 * In the SUID lab this exact code produced a NON-root shell, because foosd
 * had euid 0 but ruid 1000, and bash reset euid = ruid at startup.
 *
 * Here the daemon is STARTED as root, so at this instant ruid == euid == 0.
 * fork() inherits both ids, execve() changes neither, and bash starts with
 * equal uid 0s -- its guard has nothing to reset, so execve("/bin/sh") keeps
 * root. "spawn a shell" works against a genuinely-root process; it only
 * fails against the half-root (euid-only) state the setuid bit produces.
 * That asymmetry -- why one lab needs setreuid and this one does not -- is
 * the entire technical heart of the two labs side by side.
 */
__attribute__((noinline, used))
static void win(void)
{
    pid_t pid;

    logmsg("win() reached -- exec'ing /bin/sh (ruid==euid here, so the shell "
           "stays root; contrast with foosd where ruid stayed 1000)");

    /* Fork so the daemon's accept-loop child can be reaped and return. */
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

/* ------------------------------------------------------------------------- */
/* The vulnerable handler -- Bug #1 and Bug #2 live here                     */
/* ------------------------------------------------------------------------- */

__attribute__((noinline, used))
static void vulnerable_handler(int fd)
{
    char buf[FOOWOSD_BUFSZ];  /* 64 stack bytes. The whole ballgame.        */
    char line[FOOWOSD_LOGSZ]; /* Second buffer, for the format-string demo. */
    ssize_t n;                /* Bytes actually read.                      */

    /*
     * The BUF= leak -- the same deliberate CWE-200 disclosure as the other
     * labs. The stack is ASLR-randomised; without this the shellcode could
     * not find itself. Real-world leaks of this kind come from %p format
     * bugs, crash dumps, debug endpoints, or serialised uninitialised
     * pointers.
     *
     * FIX: never print addresses to untrusted clients.
     */
    dprintf(fd, "BUF=%p\n", (void *)buf);

    /*
     * ====================================================================
     * BUG #1 -- UNBOUNDED COPY INTO A FIXED STACK BUFFER   (CWE-120)
     * ====================================================================
     * Identical to the other labs: 512 bytes are accepted into a 64-byte
     * array, so the attacker writes 448 bytes past the end, overwriting the
     * saved frame pointer and — 8 bytes later — the saved return address.
     * On return, `ret` jumps wherever the attacker said:
     *
     *      [ 64 bytes buf ][ 8 bytes saved rbp ][ 8 bytes RETURN ADDRESS ]
     *
     * The ONLY difference from food is *what that means*: here the hijacked
     * process has real-and-effective uid 0 (it was started as root), so
     * "attacker controls RIP" becomes "attacker controls root's RIP" --
     * with no setuid bit anywhere on this filesystem.
     *
     * FIXES (in increasing order of strength):
     *   1. n = read(fd, buf, sizeof(buf) - 1);            <-- the real fix
     *   2. -fstack-protector-strong (canary aborts `ret`)
     *   3. do not take network input into fixed stack buffers at all
     * And SEPARATELY: never run this daemon as root; and if you must, drop
     * privileges the moment you are done binding (see drop_privs()). Memory
     * safety and least privilege are two different bugs; fix both.
     */
    n = read(fd, buf, FOOWOSD_READMAX);     /* <-- CWE-120, THE bug.        */
    if (n <= 0)
        return;

    /* Echo back a truncated copy so you can watch the overflow in the log.
     * Clamping for display does not undo the overwrite that already happened. */
    {
        ssize_t show = n < FOOWOSD_BUFSZ ? n : FOOWOSD_BUFSZ;
        logmsg("vulnerable_handler: read %zd bytes, echoing %zd", n, show);
        (void)write_all(fd, buf, (size_t)show);
    }

    /*
     * ====================================================================
     * BUG #2 -- NETWORK DATA USED AS A FORMAT STRING        (CWE-134)
     * ====================================================================
     * Same as the other labs: attacker '%'-specifiers in `buf` could read
     * stack words with %x or write memory with %n. Here the process is
     * root, so a %n is a write-what-where primitive IN A ROOT PROCESS. It
     * runs only on a copy in `line`, and only if the payload contains '%'.
     *
     * FIX: printf("%s", buf), never printf(buf).
     */
    if (memchr(buf, '%', (size_t)n) != NULL) {
        snprintf(line, sizeof(line), "%.*s", (int)FOOWOSD_LOGSZ - 1, buf);
        logmsg("vulnerable_handler: payload contains '%%', echoing it raw");
        (void)write_all(fd, line, strlen(line));
    }

    /* On return the (attacker-controlled) saved return address becomes RIP. */
}

/* ------------------------------------------------------------------------- */
/* Crash reporter (same rationale as the other labs: a crash should tell you  */
/* it was malicious; the fault address is the return address the client       */
/* supplied).                                                                 */
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
           "if it is an address INSIDE vulnerable_handler itself it IS the "
           "`ret` instruction: a ret into a non-canonical address (e.g. "
           "0x4141414141414141) faults at the ret, not at the target.");

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
 *   ids=               this process's euid/ruid. THE "AM I ROOT ?" CHECK.
 *                      foowosc prints a loud warning when euid is not 0,
 *                      because without a root daemon there is no root shell
 *                      and the user would otherwise think the exploit broke.
 *   leak stack=...     an address on the stack, for the shellcode
 *   leak libc=...      the real address of read() inside libc, for ret2libc
 *
 * The `ids=` spelling (rather than "euid="/"ruid=") is deliberate: the test
 * harness proves a live shell by grepping the session transcript for the
 * strict `id`-output shape "uid=NNN(", and a banner containing "uid=" as
 * part of "euid="/"ruid=" would itself satisfy a careless grep. This kind of
 * "the probe and the answer must not share a signature" thinking is what you
 * do when you write real assertions about untrusted output.
 */
static void send_leaks(int fd)
{
    long stack_marker = 0x4141414141414141L;  /* Obvious in a debugger.     */
    ssize_t (*libc_read)(int, void *, size_t);/* Real address of read().    */

    libc_read = &read;        /* &read resolves through the GOT to libc.    */

    dprintf(fd, "FOOWOSD 1.0 ids=%d/%d leak stack=%p libc=%p\n",
            (int)geteuid(), (int)getuid(),
            (void *)&stack_marker, (void *)libc_read);
}

/* THE CORRECT DESIGN, PRESENT BUT NEVER CALLED
 * -------------------------------------------
 * drop_privs() -- what a well-written daemon would do the moment it no
 * longer needs root. Two mistakes to notice, both immune to every compiler
 * mitigation:
 *
 *   * ORDER: setgroups() before setgid() before setuid(), and ONLY AFTER
 *     binding the port and opening any root-only files. Drop first and the
 *     whole point of root is gone.
 *   * PERMANENCE: setuid() to a nonzero value and check it stuck (a root
 *     process may later regain privileges via the saved id otherwise).
 *
 * Port 2344 needs no privilege, so the correct design would call this right
 * after the listen() succeeds. In this lab it is deliberately absent from
 * main(), because the lab NEEDS the accept-loop children to stay root. The
 * commented function is your diff: the two missing calls at the point marked
 * "*** see drop_privs() ***" below are the entire exploit surface (Bug #3,
 * CWE-271: privilege not dropped before handling untrusted input).
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

    /* Verify. getuid()/geteuid() are cheap; a privileged program whose drop
     * failed silently is a root hole wearing a costume. */
    if (getuid() != 1000 || geteuid() != 1000)
        _exit(1);
}

/* ------------------------------------------------------------------------- */
/* Per-connection handling                                                    */
/* ------------------------------------------------------------------------- */

static void handle_client(int fd)
{
    static const char banner[] =
        "FOOWOSD 1.0 - deliberately vulnerable daemon (no setuid bit: root is\n"
        "here because this process was started as root).\n"
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
            "            this daemon exists to be exploited as ROOT)\n"
            "\n"
            "This lab gives you a ROOT shell only when the daemon was STARTED\n"
            "as root (sudo make run-root). There is no setuid bit anywhere.\n"
            "Do not run it on any host that matters, never bind it beyond\n"
            "loopback, and do not leave it running as root.\n",
            argv0, FOOWOSD_HOST, FOOWOSD_PORT);
}

int main(int argc, char **argv)
{
    const char *host = FOOWOSD_HOST;   /* Bind address.                        */
    int         port = FOOWOSD_PORT;   /* Bind port.                           */
    int         daemonise = 0;         /* -d.                                  */
    int         allow_nonloopback = 0; /* -L. The root-daemon safety guard.    */
    int         lfd;                   /* Listening socket.                    */
    int         i;                     /* getopt() index.                      */

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
     * THE ROOT-DAEMON SAFETY GUARD.
     *
     * A daemon that is running as root (it was started as root -- there is
     * no +s bit here, so this state is easy to forget) and listens on a
     * non-loopback interface is a remote root service. Refuse by default,
     * document the exception, fail loudly.
     */
    if (!allow_nonloopback &&
        (strcmp(host, "127.0.0.1") != 0 && strcmp(host, "localhost") != 0 &&
         strcmp(host, "::1") != 0)) {
        fprintf(stderr,
                "foowosd: refusing to bind %s: this daemon may be running as\n"
                "       root. Loopback is the only permitted default. If you\n"
                "       really know what you are doing, pass -L.\n", host);
        return 1;
    }

    signal(SIGPIPE, SIG_IGN);
    signal(SIGCHLD, SIG_IGN);      /* Auto-reap forked children.            */

    /* Reserve a private log descriptor BEFORE sockets are dup2'd over fd 1. */
    g_logfd = dup(STDOUT_FILENO);
    if (g_logfd < 0) {
        g_logfd = STDOUT_FILENO;
        fprintf(stderr, "foowosd: warning: could not reserve a log descriptor\n");
    }

    /*
     * SELF-DIAGNOSIS OF THE "AM I ROOT ?" STATE -- printed once, to the log.
     *
     *   ruid==euid==0        -> started as root: the exploit gives root
     *   ruid==euid!=0        -> started as a normal user: baseline only
     *
     * foowosc reads euid over the socket and can warn too; this log line is
     * for you at the console.
     */
    logmsg("startup: ruid=%d euid=%d %s",
           (int)getuid(), (int)geteuid(),
           (geteuid() == 0) ? "-> ROOT process"
                            : "-> NOT root (start as root: make run-root)");

    if (geteuid() == 0)
        logmsg("startup: WARNING: this daemon is running as root -- no setuid "
               "bit involved, just a root-started process. Port %d does not "
               "need root; see drop_privs().", port);

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

    /* ---- The accept loop. Each child serves one connection. The children
     *      stay root because the parent was started as root. ---- */
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
         * untrusted input" (CWE-271). See drop_privs() above for the exact
         * calls a well-written daemon would make at this point, and why the
         * order of those three calls is security-critical.
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