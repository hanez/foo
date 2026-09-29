/*
 * ============================================================================
 * food.c  --  "food": an INTENTIONALLY VULNERABLE network daemon
 * ============================================================================
 *
 *  PURPOSE
 *  -------
 *  This is a deliberately broken TCP daemon used as a *target* for the
 *  companion exploit `fooc`. It exists so you can learn, hands-on, what a
 *  stack buffer overflow actually is, how it is abused to get remote code
 *  execution (RCE), and -- most importantly -- how each of its bugs maps onto
 *  a concrete, well-known defence that a real program should use instead.
 *
 *  NOTHING HERE IS SAFE. Every "vulnerability" in this file is a real,
 *  long-documented class of C bug:
 *
 *    Bug #1  Unbounded read() into a fixed stack buffer .... CWE-120
 *    Bug #2  Unchecked format string from the network ..... CWE-134
 *    Bug #3  Use of attacker-controlled data as a path ... CWE-22
 *    Bug #4  Stack canary would have caught Bug #1 ......... CWE-121
 *    Bug #5  NX bit would have stopped shellcode ........... CWE-94
 *    Bug #6  PIE/ASLR would have randomised the targets .... CWE-829
 *
 *  The comments next to each bug name the fix. That mapping is the entire
 *  point of the exercise.
 *
 *  SAFETY RAILS (please keep them in place while you experiment)
 *  ------------------------------------------------------------
 *    * It binds to 127.0.0.1 (loopback) by default, so the deliberately
 *      exploitable service is NOT reachable from your network.
 *    * It runs in the foreground with a banner so you can watch it die.
 *    * Each connection is handled in a forked child, so one crash does not
 *      take the daemon down.
 *
 *  Build:  make food
 *
 *  THE BUILD IS THE POINT, PART 1
 *  ------------------------------
 *  `make food` compiles this file with three flags that a sane project would
 *  never use, each switched off on purpose so the lab behaves the same way on
 *  every machine:
 *
 *    -fno-stack-protector   no stack canary
 *    -no-pie                fixed load address, so win() is a constant
 *    -z execstack           executable stack, so shellcode can run
 *
 *  Drop any one of them and the corresponding technique stops working. That is
 *  not a flaw in the exploit; that is the defence being demonstrated. The
 *  Makefile's `make hardened` target builds the same source WITHOUT all three,
 *  and `make test-hardened` shows you which techniques it kills.
 *
 *  Note that -z execstack is the reason `./fooc -t shellcode` works at all. A
 *  stock Linux stack is not executable (`rw-p` in /proc/PID/maps, and `RWE` in
 *  the ELF program headers only when this flag is present), and the shellcode
 *  technique dies with SIGSEGV at RIP = the address of the payload. Everything
 *  in README.md's mitigation table explains why that flag matters to you.
 *
 *  Usage:  ./food [-h HOST] [-p PORT] [-d]
 * ============================================================================
 */

/* Ask glibc for the extra declarations we need (dprintf, etc.). */
#define _GNU_SOURCE

#include <arpa/inet.h>  /* inet_pton(), to turn "127.0.0.1" into bytes.      */
#include <errno.h>     /* errno and the strerror() family.                 */
#include <fcntl.h>     /* dup2(), used to hand the socket to the shell.     */
#include <netinet/in.h>/* struct sockaddr_in, htons(), the TCP address.      */
#include <signal.h>    /* signal(), SIGPIPE / SIGCHLD handling.             */
#include <stdarg.h>    /* va_list, needed by our own tiny printf wrapper.   */
#include <stdint.h>     /* uint16_t, the fixed-width type htons() returns.   */
#include <stdio.h>     /* printf, dprintf, fputs.                           */
#include <stdlib.h>    /* exec*, _exit, atoi.                               */
#include <string.h>    /* memset, strncpy, strlen, memchr.                  */
#include <sys/socket.h>/* socket(), bind(), listen(), accept().             */
#include <sys/stat.h>  /* umask().                                           */
#include <sys/types.h> /* ssize_t, pid_t.                                   */
#include <sys/ucontext.h>/* ucontext_t, REG_RIP: the saved CPU registers.    */
#include <sys/wait.h>  /* waitpid(), for reaping children.                  */
#include <unistd.h>    /* read, write, close, dup2, getpid, fork, chdir,
                         * getopt -- the POSIX workhorses.                    */

/* ------------------------------------------------------------------------- */
/* Configuration constants                                                    */
/* ------------------------------------------------------------------------- */

/* Default TCP port. Not privileged (>1024), so no root is required. */
#define FOOD_PORT 2342

/* Loopback only, on purpose. Change with -h if you really know better. */
#define FOOD_HOST "127.0.0.1"

/* Size of the stack buffer in vulnerable_handler(). This is the value the
 * exploit has to fill *plus* 8 bytes of saved frame pointer before it can
 * reach the return address. Do not change it without re-running the exploit's
 * automatic offset detection, which reads it from this binary. */
#define FOOD_BUFSZ 64

/* How many bytes the vulnerable read() is willing to accept. This is much
 * larger than FOOD_BUFSZ on purpose -- that mismatch IS the vulnerability. */
#define FOOD_READMAX 512

/* Size of the (also broken) log line buffer used by the format-string demo. */
#define FOOD_LOGSZ 128

/* ------------------------------------------------------------------------- */
/* Tiny helpers                                                              */
/* ------------------------------------------------------------------------- */

/*
 * g_logfd -- the descriptor logmsg() writes to.
 *
 * It begins life as a duplicate of the real stdout, taken *before*
 * prepare_client_fds() replaces fd 1 with the client's socket. The point is
 * that the server's log must never travel to the attacker.
 *
 * This is not cosmetic. If the daemon had kept logging to fd 1, then the
 * moment a client connected, every log line -- including file paths, internal
 * hostnames, and in a real system any credential that ever reached a log --
 * would be delivered to whoever happened to be on the other end of the socket.
 * Keeping diagnostics on a separate, trusted descriptor is a genuine security
 * practice, and a lab about exploiting a daemon would be a poor place to
 * accidentally teach the alternative.
 */
static int g_logfd = -1;

/*
 * logmsg() -- print one timestamped line to the log descriptor.
 *
 * (Deliberately NOT named `logf`: that collides with the libm builtin
 * `float logf(float)`, and GCC warns about it. Naming your own helpers after
 * standard library functions is a surprisingly common source of pain.)
 *
 * We use dprintf() rather than printf() because we need to write to a specific
 * descriptor, and because it is close to atomic: one write() call means two
 * forked children cannot interleave halfway through a line.
 */
static void logmsg(const char *fmt, ...)
{
    char    line[1024];       /* Compose the whole message in one buffer.       */
    va_list ap;               /* The argument list of this variadic call.      */
    int     n;                /* Bytes composed.                               */

    /*
     * va_start MUST be called before the va_list is used. It initialises `ap`
     * to point just past `fmt` in the argument area. Passing an uninitialised
     * va_list to vsnprintf makes it walk wild stack memory and crash -- which
     * is exactly what happened the first time this function was written.
     *
     * va_end is mandatory once va_start has been called, even on error paths.
     */
    va_start(ap, fmt);

    /* Format the body first, into the tail of the buffer, leaving room for
     * the "[food 1234] " prefix and the trailing newline. */
    n = vsnprintf(line, sizeof(line) - 32, fmt, ap);
    va_end(ap);               /* Always pair va_start with va_end.             */
    if (n < 0)
        return;

    /* Prepend the pid. Knowing which forked child did what is what makes the
     * per-connection log readable. */
    if (g_logfd >= 0)
        dprintf(g_logfd, "[food %d] %s\n", (int)getpid(), line);
}

/*
 * read_exact() -- read exactly n bytes, looping until we have them all.
 *
 * This helper is *correct*. The bug in this program is not here.
 *
 * It is included deliberately, so you can compare it against vulnerable_handler()
 * below. The difference between the two functions is, essentially, the whole
 * lesson: this one asks for `n` bytes and checks it got them; the other asks
 * for far more than its buffer can hold and never checks.
 *
 * Why it matters: read() on a socket is allowed to return a short count (it
 * is a stream, not a message queue). A correct program must loop. The
 * vulnerable function below deliberately does not do this correctly either.
 */
__attribute__((unused))  /* Referenced in comments only, so silence the
                           * -Wunused-function warning deliberately.         */
static ssize_t read_exact(int fd, void *buf, size_t n)
{
    size_t got = 0;                  /* Bytes received so far.                */
    while (got < n) {                /* Keep going until the full request.    */
        ssize_t r = read(fd, (char *)buf + got, n - got);
        if (r < 0) {                 /* r < 0 means an error occurred.        */
            if (errno == EINTR)     /* Interrupted by a signal: just retry.  */
                continue;
            return -1;
        }
        if (r == 0)                  /* Peer closed the connection.           */
            break;
        got += (size_t)r;            /* Otherwise bank the bytes.             */
    }
    return (ssize_t)got;             /* Return total bytes actually read.     */
}

/*
 * write_all() -- write a whole buffer, looping over short writes.
 * Also correct. Exists so the exploit's I/O is not the flaky part of the lab.
 */
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
 * win() -- the "backdoor" function that ret2win aims at.
 *
 * A ret2win exploit works by overwriting the saved return address with the
 * address of a function that (a) is already in the binary and (b) does
 * something useful to the attacker. Here, that is "hand me a shell".
 *
 * The *presence* of win() is not itself the vulnerability -- shipping a hidden
 * "debug backdoor" like this is a real and sadly common self-inflicted wound
 * (it is exactly the CVE class "undocumented backdoor", e.g. the Juniper
 * ScreenOS backdoors). But in this lab it exists purely as an easy, reliable
 * first target so you can prove code execution before reaching for shellcode.
 *
 * noinline: the compiler must not inline this away, or the exploit would have
 *           no address to jump to.
 * used:      keeps the function alive even though we never call it in C.
 */
__attribute__((noinline, used))
static void win(void)
{
    pid_t pid;                 /* Child's PID after the fork below.           */

    logmsg("win() reached -- executing /bin/sh");

    /*
     * Note the signature: win() deliberately takes NO arguments, and that is
     * the whole point rather than an oversight.
     *
     * A ret2win exploit overwrites only the saved *return address*. Every
     * other register holds whatever the vulnerable function happened to leave
     * behind, and the attacker has no control over any of them. An earlier
     * revision of this function took an `int fd` parameter, and gdb showed the
     * exploit apparently landing while actually passing garbage in rdi
     * (-11073), which made every dup2() fail and the "shell" go nowhere.
     * Depending on an incoming argument is the most common reason a
     * ret2win-style exploit looks like it works and then silently does nothing.
     *
     * We do not need the argument: prepare_client_fds() has already made
     * fds 0, 1 and 2 refer to the client's socket, so the shell can simply
     * use the standard descriptors.
     */

    /*
     * Fork before exec so the parent can reap the child and go away, while
     * the child keeps talking to the client. Without this the daemon would
     * stay busy until the shell exits.
     */
    pid = fork();
    if (pid < 0) {
        logmsg("win(): fork() failed: %s", strerror(errno));
        _exit(1);
    }
    if (pid > 0) {             /* Parent: reap the child, then bail out.     */
        waitpid(pid, NULL, 0);
        /*
         * _exit, NOT return. Returning would execute `ret` a second time,
         * popping the next 8 bytes of attacker payload as a new RIP and
         * crashing immediately. Exiting is the only safe way out of a
         * function that was entered by hijacking a return address.
         */
        _exit(0);
    }

    /*
     * Child. stdin/stdout/stderr already point at the socket (see
     * prepare_client_fds), so there is nothing to rewire here.
     *
     * Dropping privileges is deliberately absent: in a real system this is
     * exactly where you would setuid()/setgid() to an unprivileged user
     * before exec. A backdoor that hands out a root shell is what turns an
     * ordinary memory-safety bug into a full compromise.
     */
    execl("/bin/sh", "sh", (char *)NULL);   /* Does not return on success.   */
    _exit(127);                             /* Only if exec failed.           */
}

/* ------------------------------------------------------------------------- */
/* The vulnerable handler -- Bug #1 and Bug #2 live here                     */
/* ------------------------------------------------------------------------- */

/*
 * noinline: mandatory for a stack-overflow lab. If the compiler inlines this
 *           into its caller, the stack frame the exploit is aiming at changes
 *           and the whole exercise stops making sense.
 * used:      do not let the optimiser delete it.
 */
__attribute__((noinline, used))
static void vulnerable_handler(int fd)
{
    char buf[FOOD_BUFSZ];     /* 64 bytes of stack. The whole ballgame.      */
    char line[FOOD_LOGSZ];    /* Second, larger buffer for the format bug.    */
    ssize_t n;                /* Byte count returned by read().               */

    /*
     * ------------------------------------------------------------------
     * The buffer-address leak, done on purpose, inside this function.
     * ------------------------------------------------------------------
     * We hand the client the exact address of `buf` *before* it overflows
     * anything. Without this the client is shooting blind at a randomised
     * stack, and you would need either a lucky guess or a "ret sled"
     * thousands of ret-instructions wide.
     *
     * Where do real-world leaks of this kind come from? All of these are
     * genuine, frequently-seen CWE-200 / CWE-497 bugs:
     *
     *   * a format string bug printing %p (our Bug #2 above does this),
     *   * returning or serialising a pointer that was never initialised
     *     (CWE-457, use of uninitialised variable -- a very common way to
     *     turn a mere crash into a full info leak),
     *   * a verbose crash handler or core dump served to the client,
     *   * a debug endpoint left enabled, or /proc/self/maps over HTTP,
     *   * a non-randomised fixed-address mmap(), or a non-PIE binary,
     *     which is precisely why the Makefile here builds with -no-pie.
     *
     * The real lesson: address-space layout randomisation is only a
     * *speed bump*. It raises the cost of an exploit; it is not a fix. The
     * fix is not having the memory corruption in the first place.
     *
     * FIX: do not disclose addresses to untrusted clients, and initialise
     * every pointer before you might print it.
     */
    dprintf(fd, "BUF=%p\n", (void *)buf);

    /*
     * ====================================================================
     * BUG #1 -- UNBOUNDED COPY INTO A FIXED STACK BUFFER   (CWE-120)
     * ====================================================================
     *
     * This single read() call is the entire exploit surface:
     *
     *      we have  FOOD_BUFSZ  =  64 bytes of room
     *      we accept FOOD_READMAX = 512 bytes from the network
     *
     * The attacker therefore gets to write 448 bytes more than they should,
     * and everything laid out on the stack above `buf` gets clobbered.
     *
     * In a compiled x86-64 function the stack grows *downwards*, so memory
     * looks like this, with rbp pointing at the saved frame pointer:
     *
     *      high addresses
     *      +------------------------+  <- rbp + 16 : caller locals
     *      |  ...                   |
     *      +------------------------+  <- rbp +  8 : SAVED RETURN ADDRESS  <-- RIP
     *      |  saved rbp (8 bytes)   |
     *      +------------------------+  <- rbp      : our frame pointer
     *      |  line[128]             |     (second buffer, padding)
     *      |  buf[64]               |  <- rsp: what read() will fill
     *      +------------------------+
     *      low addresses
     *
     * So the attacker writes 64 bytes of junk to fill `buf`, another 8 bytes
     * to fill the saved rbp, and the *next* 8 bytes become the return address
     * that the `ret` instruction pops into RIP. From that moment the attacker
     * decides where the CPU executes next.
     *
     * FIXES, in increasing order of strength:
     *   1. Bound every read by the true size of the destination:
     *          n = read(fd, buf, sizeof(buf) - 1);   <-- the real fix
     *   2. Compile with -fstack-protector-strong so a *canary* sits between
     *      the buffers and the return address; `ret` then aborts first.
     *   3. Compile with -fstack-protector-all (covers locals that a plain
     *      -O2 might have kept in registers).
     *   4. Real root cause: do not use fixed-size stack arrays for input at
     *      all. Use heap allocation sized from a checked length, or a
     *      stdio-style bounded reader.
     *
     * NOTE: modern GCC detects *this exact shape* at compile time and warns
     * ("writing 512 bytes into a region of size 64"). Never suppress that
     * warning in real code -- it is free security.
     */
    n = read(fd, buf, FOOD_READMAX);      /* <-- CWE-120, THE bug.           */
    if (n <= 0)
        return;                           /* Nothing to do.                   */

    /*
     * Echo back what we received, truncated to the buffer's real size so that
     * *this* line is safe. It is here purely so you can watch the overflow
     * happen live in the log. Truncating for display does NOT undo the
     * overwrite that already happened above.
     */
    {
        ssize_t show = n < FOOD_BUFSZ ? n : FOOD_BUFSZ;   /* clamp for log. */
        logmsg("vulnerable_handler: read %zd bytes, echoing %zd", n, show);
        (void)write_all(fd, buf, (size_t)show);
    }

    /*
     * ====================================================================
     * BUG #2 -- NETWORK DATA USED AS A FORMAT STRING        (CWE-134)
     * ====================================================================
     *
     * `buf` is fully attacker-controlled. Passing it to printf() as the
     * *format* rather than as a %s *argument* lets the attacker supply their
     * own conversion specifiers: %x to read stack words, %n to *write* to
     * memory, %s to walk arbitrary pointers. A %n here is a write-what-where
     * primitive, which is another way to build an exploit.
     *
     * FIX: never pass untrusted data as the format string. Use
     *      printf("%s", buf);   or better, fwrite()/write() of a length.
     *
     * We keep this as a *demonstration only* -- it runs on a copy in `line`
     * so the crash it causes is obviously separate from Bug #1. The payload
     * you send by default is plain text with no '%' characters, so this line
     * is a no-op unless you explicitly ask for the format-string demo with
     * the `fooc --fmt` mode.
     */
    if (memchr(buf, '%', (size_t)n) != NULL) {
        snprintf(line, sizeof(line), "%.*s", (int)FOOD_LOGSZ - 1, buf);
        logmsg("vulnerable_handler: payload contains '%%', echoing it raw");
        (void)write_all(fd, line, strlen(line));   /* safe echo of raw text. */
    }

    /*
     * When this function returns, the CPU pops the (attacker-controlled)
     * saved return address into RIP and jumps wherever the attacker chose.
     * The `leave` + `ret` pair in the generated assembly is the exact
     * instruction that hands over control.
     */
}

/* ------------------------------------------------------------------------- */
/* fd handling                                                               */
/* ------------------------------------------------------------------------- */

/*
 * on_sigsegv() -- print exactly where the CPU was trying to go.
 *
 * This handler exists purely to make the exploit *visible*. When the overflow
 * lands, the CPU jumps to an address we chose; that address is almost always
 * unmapped, the CPU raises SIGSEGV, and this handler runs.
 *
 * Two facts come out of the kernel for free:
 *
 *   * ucontext->uc_mcontext.gregs[REG_RIP] is the address of the instruction
 *     the CPU was executing, i.e. the value of the instruction pointer at the
 *     moment of the fault. If we clobbered the return address, THIS is our
 *     eight bytes. It is the most direct possible proof that the attacker
 *     controls RIP.
 *   * siginfo->si_addr is the bad address the access was aimed at.
 *
 * Both are read out of the ucontext_t that the kernel hands us, which is why
 * this needs <sys/ucontext.h> and _GNU_SOURCE.
 *
 * A production server absolutely should catch SIGSEGV like this -- not to keep
 * serving, but to log the fault address so that a crash *tells you it was
 * malicious*. Crashing silently is what makes these bugs survive for years.
 */
static void on_sigsegv(int sig, siginfo_t *si, void *ucv)
{
    ucontext_t *uc = (ucontext_t *)ucv;   /* The CPU's saved register state.  */
    unsigned long rip = 0;
    unsigned long rsp = 0;

    if (uc != NULL) {
        rip = (unsigned long)uc->uc_mcontext.gregs[REG_RIP];
        rsp = (unsigned long)uc->uc_mcontext.gregs[REG_RSP];
    }

    logmsg("SIGSEGV: faulting address %p", si ? si->si_addr : (void *)0);
    logmsg("SIGSEGV: RIP=%#lx  RSP=%#lx", rip, rsp);
    logmsg("SIGSEGV: RIP is the return address the client supplied. "
           "If it is 0x4141414141414141, that is our 'A' padding. "
           "If it looks like a real code or libc address, we were hijacked.");

    /*
     * Re-raise with the default disposition so the process still dies with the
     * correct status and still dumps core. A handler that swallowed the
     * signal and returned would re-execute the faulting instruction forever,
     * because the bad address has not been fixed -- an easy way to turn one
     * crash into an unkillable hang.
     */
    signal(sig, SIG_DFL);
    raise(sig);
}

/*
 * install_crash_reporter() -- attach on_sigsegv() to this process.
 *
 * Called in the forked child, so installing it is cheap and affects only the
 * process serving one connection. The parent keeps its default dispositions
 * and is therefore not slowed by signal handling.
 */
static void install_crash_reporter(void)
{
    struct sigaction sa;      /* The action structure sigaction() wants.       */

    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = on_sigsegv;   /* The extended handler form.             */
    sa.sa_flags     = SA_SIGINFO;   /* "...and pass me the siginfo_t."        */

    /* An empty sigset means "block nothing extra while in the handler". */
    sigemptyset(&sa.sa_mask);

    if (sigaction(SIGSEGV, &sa, NULL) < 0)
        logmsg("sigaction(SIGSEGV) failed: %s", strerror(errno));
    if (sigaction(SIGBUS, &sa, NULL) < 0)   /* Misaligned access, same idea.  */
        logmsg("sigaction(SIGBUS) failed: %s", strerror(errno));
}

/*
 * prepare_client_fds() -- point fds 0, 1 and 2 at the accepted socket.
 *
 * Doing this once, up front, is what lets every exploitation technique in
 * `fooc` work identically:
 *
 *   * ret2win    -> win() execs /bin/sh with fds 0-2 already on the socket.
 *   * ret2libc   -> system("/bin/sh") likewise inherits the socket.
 *   * shellcode  -> execve("/bin/sh") likewise inherits the socket.
 *
 * so whichever payload lands, the resulting shell talks straight back to the
 * attacker over the network.
 */
static void prepare_client_fds(int fd)
{
    if (fd != STDIN_FILENO)  dup2(fd, STDIN_FILENO);
    if (fd != STDOUT_FILENO) dup2(fd, STDOUT_FILENO);
    if (fd != STDERR_FILENO) dup2(fd, STDERR_FILENO);
    if (fd > STDERR_FILENO)  close(fd);   /* Don't leak the spare descriptor.*/
}

/* ------------------------------------------------------------------------- */
/* The information leak -- Bug #3 lives here (this one is a feature in the lab)*/
/* ------------------------------------------------------------------------- */

/*
 * send_leaks() -- hand the attacker two pointers, on purpose.
 *
 * This models two *real* vulnerability classes, and it is what makes the
 * "hard" techniques (ret2libc, shellcode) deterministic instead of a
 * probability game:
 *
 *   Leak A: a STACK address (the address of a local variable).
 *       Real-world analogue: CWE-200 / CWE-497 "exposure of sensitive
 *       information to an unauthorized actor" -- a debug endpoint, a verbose
 *       error page, a crash dump, a /proc/self/maps file served over HTTP.
 *       With it, the attacker learns exactly where their shellcode landed.
 *
 *   Leak B: a LIBC address (the real address of `read`, resolved by the PLT
 *       trampoline into libc).
 *       Real-world analogue: the same, plus a classic function-pointer leak.
 *       With it, the attacker computes the load address of libc and therefore
 *       the addresses of `system` and of the "/bin/sh" string inside it.
 *
 *   FIX for the daemon: do not print addresses to untrusted clients, and do
 *   not leave debug endpoints enabled in production builds.
 *
 * The text format is deliberately simple so the exploit can parse it with a
 * one-line sscanf():
 *
 *     "FOOD 1.0 leak stack=0x<hex> libc=0x<hex>\n"
 */
static void send_leaks(int fd)
{
    long stack_marker = 0;   /* A local; its address reveals the stack base.*/
    /*
     * The *exact* type of `read` as declared in <unistd.h>. Getting this
     * signature wrong is a compile error in C (and a far worse bug in C++),
     * which is a nice reminder that the type system is a security tool:
     *
     *     ssize_t read(int fd, void *buf, size_t nbytes);
     *
     * We store it in a variable only so we can print its value as a leak.
     */
    ssize_t (*libc_read)(int, void *, size_t);  /* Real libc `read` fn ptr.  */

    /*
     * Taking the address of a local is the leak. Compilers must honour this
     * (it is observable behaviour), so it cannot be optimised away.
     */
    stack_marker = 0x4141414141414141L;     /* Make it obvious in a debugger.*/

    /*
     * `&read` is not the PLT stub once the dynamic linker has run: the GOT
     * holds the true address inside libc, so this yields a genuine libc
     * pointer. That is what makes leak B useful for ret2libc.
     */
    libc_read = &read;

    /*
     * 0644 octal = "rw-r--r--", the conventional permission bits for a file.
     * %p prints a pointer in the implementation-defined but universally
     * "0x..." form on glibc/x86-64.
     */
    dprintf(fd, "FOOD 1.0 leak stack=%p libc=%p\n",
            (void *)&stack_marker, (void *)libc_read);
}

/* ------------------------------------------------------------------------- */
/* Per-connection handling                                                    */
/* ------------------------------------------------------------------------- */

/*
 * handle_client() -- do everything for one connected attacker.
 *
 * Runs in the forked child. Its job:
 *   1. Send a banner and the two leaks.
 *   2. Call the vulnerable function, which will be overflowed.
 *   3. Never return to the accept loop: if the overflow missed, exit cleanly;
 *      if it hit, we never come back at all -- the CPU is somewhere else now.
 */
static void handle_client(int fd)
{
    static const char banner[] =
        "FOOD 1.0 - deliberately vulnerable service\n"
        "Type 'quit' to disconnect. Buffer = 64 bytes, read accepts 512.\n";

    prepare_client_fds(fd);    /* fds 0,1,2 now all point at the socket.    */

    /*
     * Install the crash reporter *after* the dup2 dance, so its log lines
     * (which go to g_logfd, not to the socket) cannot be seen by the client.
     */
    install_crash_reporter();

    logmsg("client connected (fd %d)", fd);

    /* The banner and the leaks are two separate writes so the client can
     * read them incrementally without needing a length-prefixed protocol. */
    (void)write_all(STDOUT_FILENO, banner, sizeof(banner) - 1);
    send_leaks(STDOUT_FILENO);

    /* Hand control to the vulnerable code. Nothing after this line is
     * guaranteed to run. */
    vulnerable_handler(STDOUT_FILENO);

    /*
     * We only get here if the exploit *missed* its target, or if no exploit
     * was sent. Say goodbye politely so the exploit can tell the difference
     * between "failed" and "succeeded".
     */
    logmsg("vulnerable_handler returned normally -- payload did not hijack RIP");
    (void)write_all(STDOUT_FILENO, "OK: no hijack, disconnecting.\n", 29);
}

/* ------------------------------------------------------------------------- */
/* The server loop                                                           */
/* ------------------------------------------------------------------------- */

/*
 * make_listener() -- create the listening socket.
 *
 * A correct, boring, textbook implementation: it would be the same code in
 * production. Returns the fd, or -1 on failure.
 */
static int make_listener(const char *host, int port)
{
    struct sockaddr_in addr;  /* The TCP address we will bind to.            */
    int fd;                   /* The socket descriptor.                      */
    int one = 1;              /* Value for setsockopt().                     */

    fd = socket(AF_INET, SOCK_STREAM, 0);   /* IPv4, TCP.                    */
    if (fd < 0) {
        logmsg("socket() failed: %s", strerror(errno));
        return -1;
    }

    /* SO_REUSEADDR: let us restart quickly without TIME_WAIT blocking us. */
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) < 0)
        logmsg("setsockopt(SO_REUSEADDR) failed: %s", strerror(errno));

    /*
     * Zero the whole structure first. Leaving uninitialised padding bytes is
     * a real bug (CWE-457) that leaks stack memory to the kernel -- harmless
     * here, but habit-forming in a bad way, so we do it properly.
     */
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;               /* IPv4.                        */
    addr.sin_port   = htons((uint16_t)port);/* Network byte order.           */

    /*
     * inet_pton() parses the dotted-quad text form "127.0.0.1" into the
     * network-byte-order struct in_addr. It returns 1 on success, 0 on a
     * malformed address, -1 on error. This is the correct way to turn a
     * config string into an address -- strtoul() would happily accept things
     * like "0x7f000001" and hide bugs.
     */
    if (inet_pton(AF_INET, host, &addr.sin_addr) != 1) {
        logmsg("bad bind address: %s", host);
        close(fd);
        return -1;
    }

    /* int -> unsigned short is a narrowing cast, so range-check the port
     * before htons() can silently truncate a value like 70000 to 4464. */
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

    if (listen(fd, 16) < 0) {                /* Backlog of 16 connections.   */
        logmsg("listen() failed: %s", strerror(errno));
        close(fd);
        return -1;
    }

    return fd;
}

/* ------------------------------------------------------------------------- */
/* Tiny main()                                                                */
/* ------------------------------------------------------------------------- */

static void usage(const char *argv0)
{
    fprintf(stderr,
            "usage: %s [-h HOST] [-p PORT] [-d]\n"
            "\n"
            "  -h HOST   address to bind (default %s -- keep it on loopback!)\n"
            "  -p PORT   TCP port to listen on (default %d)\n"
            "  -d        daemonise: fork into the background\n"
            "\n"
            "WARNING: this program is intentionally exploitable. Do not run it\n"
            "on any host that matters, and do not bind it to 0.0.0.0.\n",
            argv0, FOOD_HOST, FOOD_PORT);
}

int main(int argc, char **argv)
{
    const char *host = FOOD_HOST;   /* Bind address, overridable with -h.     */
    int         port = FOOD_PORT;   /* Bind port, overridable with -p.        */
    int         daemonise = 0;     /* Set by -d.                              */
    int         lfd;                /* Listening socket fd.                    */
    int         i;                  /* getopt()'s index.                       */

    /* getopt() parses the command line. ":h:p:d" = h/p take args, d does not,
     * leading ':' means "report missing argument as ':'". */
    while ((i = getopt(argc, argv, ":h:p:d")) != -1) {
        switch (i) {
        case 'h': host = optarg; break;                /* host argument.     */
        case 'p': port = atoi(optarg); break;          /* port argument.     */
        case 'd': daemonise = 1; break;                /* background flag.   */
        case ':': fprintf(stderr, "missing argument to -%c\n", optopt);
                  usage(argv[0]);
                  return 2;
        default:  usage(argv[0]);                     /* unknown flag.      */
                  return 2;
        }
    }

    /* Ignore SIGPIPE so a client disconnecting mid-write cannot kill us. */
    signal(SIGPIPE, SIG_IGN);

    /* Reap dead children automatically instead of accumulating zombies. */
    signal(SIGCHLD, SIG_IGN);

    /*
     * Claim a private copy of stdout for logging, BEFORE any accept() can
     * dup2 a client socket over fd 1. Everything logged afterwards goes to
     * the real terminal or wherever stdout was pointed, never to a client.
     * g_logfd is 0 or 1 only if dup() failed, in which case we fall back to
     * the original stdout in logmsg().
     */
    g_logfd = dup(STDOUT_FILENO);
    if (g_logfd < 0) {
        g_logfd = STDOUT_FILENO;
        fprintf(stderr, "food: warning: could not reserve a log descriptor\n");
    }

    lfd = make_listener(host, port);
    if (lfd < 0)
        return 1;

    logmsg("listening on %s:%d (pid %d) -- THIS SERVICE IS INTENTIONALLY VULNERABLE",
         host, port, (int)getpid());

    if (daemonise) {
        /* Standard double-fork daemonisation so we cannot acquire a
         * controlling terminal. Parent exits, intermediate exits, we survive. */
        pid_t p1 = fork();
        if (p1 < 0) { perror("fork"); return 1; }
        if (p1 > 0) _exit(0);           /* Original parent: go away.         */
        if (setsid() < 0) perror("setsid");
        pid_t p2 = fork();
        if (p2 < 0) { perror("fork"); return 1; }
        if (p2 > 0) _exit(0);           /* Session leader: also go away.     */
        if (chdir("/") < 0) perror("chdir");
        umask(022);                     /* New files default to 0644.        */
    }

    /* ---- The accept loop. Runs forever. ---------------------------------- */
    for (;;) {
        struct sockaddr_in peer;   /* Who connected.                          */
        socklen_t       plen = sizeof(peer);
        int             cfd;        /* Client socket.                         */
        pid_t           pid;        /* Child pid.                             */

        /*
         * accept() blocks until a client arrives, then returns a *new* fd
         * connected to that client. The listening fd stays open.
         */
        cfd = accept(lfd, (struct sockaddr *)&peer, &plen);
        if (cfd < 0) {
            if (errno == EINTR || errno == ECONNABORTED)
                continue;               /* Transient: just try again.          */
            logmsg("accept() failed: %s", strerror(errno));
            continue;
        }

        /*
         * Fork per connection. Reason 1: isolation -- a segfault in the
         * exploit's payload kills only the child, so the daemon survives.
         * Reason 2: the child can _exit() without taking the server down.
         */
        pid = fork();
        if (pid < 0) {
            logmsg("fork() failed: %s", strerror(errno));
            close(cfd);
            continue;
        }

        if (pid == 0) {
            /* ---- Child: serve exactly one client, then die. -------------- */
            close(lfd);        /* Release our copy of the listening socket.  */
            handle_client(cfd);
            /* If the exploit worked, we never get here. If it did not, exit. */
            _exit(0);
        }

        /* ---- Parent: close our copy of the client socket and go around. -- */
        close(cfd);
    }

    /* Not reached: the accept loop is infinite. */
}
