# food / fooc — a stack buffer overflow, from both sides

A C99 security lab in two halves:

- **`food.c`** — an intentionally vulnerable TCP daemon. It has a real,
  textbook stack buffer overflow (CWE-120), and a few more bugs besides.
- **`fooc.c`** — an exploit for it. It computes the overflow offset by
  disassembling the target at runtime, reads address leaks from the daemon, and
  gets a shell on the "victim" by overwriting a saved return address.

The point is not the shell. The point is that you can watch, end to end, how a
memory-safety mistake turns into arbitrary code execution — and then see exactly
which mitigations stop each step of that chain. Every line of both programs is
commented, because the mechanism is the lesson.

```
                   your terminal
                         |
                     ./fooc   (exploit)
                         |
                    TCP 127.0.0.1:2342
                         |
                     ./food   (vulnerable daemon)
                         |
                 fork() -> vulnerable_handler() -> overflow -> ret -> your code
```

---

## ⚠️ Read this first

**`food` is a deliberately broken network service. It binds to `127.0.0.1`
only, and that default is deliberate — please leave it there.**

- Do **not** run it on a machine you care about, or on anything with data on it.
- Do **not** bind it to `0.0.0.0` or a real interface. It is remotely
  exploitable by design.
- Pointing `fooc` at a host you do not own or have written permission to test
  is a computer intrusion offence in most jurisdictions, including under the UK
  Computer Misuse Act and the US Computer Fraud and Abuse Act.
- It binds to an unprivileged port (>1024), so you do not need root. Do not
  "improve" it by adding capabilities or running it as a system service.
- Every connection is handled in a `fork()`ed child, and `food` reaps it, so
  crashes do not accumulate. If you find yourself with dozens of stray `sh`
  processes afterwards, `pkill -x sh` is the cleanup.

If in doubt: this lab is for a virtual machine or a container, on a network
you control, on a machine with nothing you would miss.

---

## Quick start

```sh
make            # build food, fooc, and the test harnesses
make run        # start food on 127.0.0.1:2342, detached
make test       # run all three exploit techniques
make stop       # stop the daemon
```

Then, by hand:

```sh
./fooc -t leak        # see the address leaks food hands out
./fooc -t demo -v     # send junk; watch food die with SIGSEGV
./fooc -t ret2win -i  # jump to a function that already exists -> shell
```

### Requirements

| Tool | Needed for | Notes |
|---|---|---|
| `gcc` (or clang) | building | C99. Tested on gcc 16.2 |
| `objdump` | `fooc` | binutils. `fooc` shells out to it at runtime |
| `nasm` | `make verify` | only to cross-check the shellcode; skipped if absent |
| `gdb` | `make debug` | optional |
| Linux, x86-64 | both | the payload and gadget hunting are arch-specific |

`fooc` also needs `-ldl` for `dlsym()`; the Makefile handles that.

---

## The bug

One line in `food.c` is the whole exploit surface:

```c
char buf[FOOD_BUFSZ];                  /* 64 bytes  */
n = read(fd, buf, FOOD_READMAX);       /* up to 512 bytes from the network */
```

64 bytes of destination, 512 bytes accepted. The attacker overwrites 448 bytes
past the end of the buffer, and because the stack grows downwards, "past the
end" means "into the frame above" — which is where the saved frame pointer and
the **saved return address** live.

In a compiled x86-64 function at `-O0`:

```
  high addresses
  +------------------------+  rbp + 16 : caller locals
  |  ...                   |
  +------------------------+  rbp +  8 : SAVED RETURN ADDRESS   <-- becomes RIP
  |  saved rbp (8 bytes)   |
  +------------------------+  rbp      : our frame pointer
  |  line[128]             |
  |  buf[64]               |  <- rsp: what read() fills
  +------------------------+
  low addresses
```

When the function returns, `leave; ret` pops that 8 bytes into `RIP` and the CPU
jumps wherever the attacker chose. Everything else in this lab is arithmetic
about where to point it.

For this build the numbers are: `buf` is 64 bytes, the saved `rbp` is 8, so the
return address sits at offset **88** from the start of `buf`. `fooc` does not
hardcode that — it disassembles `food` and finds the `lea -0x50(%rbp)` that
precedes the `call read@plt`, so it keeps working if you change `FOOD_BUFSZ`.

> gcc already tells you about this. Building `food` prints:
> `warning: 'read' writing 512 bytes into a region of size 64 overflows the
> destination [-Wstringop-overflow=]`. Never suppress that warning in real code.
> It is free security.

---

## The three techniques

`fooc -t <technique>`. They are in the order a real attacker would work
through them, because each one needs what the previous one taught you.

### 1. `ret2win` — control the instruction pointer

```
[ 88 bytes of junk ][ address of food's win() ]
                   ^ saved rbp
                                    ^ becomes RIP
```

`win()` is a function in the target that execs `/bin/sh`. Overwriting the return
address with its address is the entire exploit.

**What it teaches:** you have arbitrary control of the instruction pointer. It
also needs no leak, because the binary is built `-no-pie`, so `win()` sits at a
fixed address forever.

**The real-world equivalent** is not "attacks are easy" but "do not ship
undocumented backdoors in networked binaries." If a function like `win()` exists
in your binary, a buffer overflow will find it. That is literally the Juniper
ScreenOS backdoor CVE class.

**Defence:** `-fPIE` (or ASLR) randomises the load address, so the attacker
must know the address — which usually means they need a leak first. That is why
`ret2win` fails against `food_hardened`.

### 2. `ret2libc` — call anything, by name

```
[ junk ][ pop rdi; ret ][ address of "/bin/sh" ][ address of system() ]
          ^^^^^^^^^^^^     ^^^^^^^^^^^^^^^^^^^    ^^^^^^^^^^^^^^^^^^^^^
          sets rdi         the string to pass     the function to call
```

At execution time: `ret` pops `pop rdi; ret` into RIP; that pops the `"/bin/sh"`
pointer into `RDI`; that `ret` pops `system()` into RIP, with `RDI` still
holding the string. `system("/bin/sh")` runs.

The gadgets (`pop rdi; ret`) are not in `food` — this glibc has no
`__libc_csu_init` — so `fooc` finds them by scanning live libc memory for the
byte pair `5f c3`. It locates libc via `/proc/self/maps`, finds the offsets of
`system` and `"/bin/sh"` with `dlsym()`, and computes the base from the leak
`food` publishes. Nothing is hardcoded, so it survives a libc update.

**What it teaches:** once you can control `RIP`, you can chain *existing*
instructions. This is return-oriented programming, and it is what nearly all
real-world exploitation looks like, because it needs no attacker-supplied
executable memory.

**Defence:** none of the compiler flags stop this on their own. It works
against a PIE binary, with NX, with a canary — as long as the attacker has a
leak. The defences are "do not have the overflow" and "do not leak addresses."
See the table below.

### 3. `shellcode` — run your own machine code

23 bytes, placed at the start of the buffer, with `RIP` pointed at them:

```asm
xor    esi, esi                    ; envp = NULL
xor    edx, edx                    ; argv = NULL
movabs rdi, 0x68732f6e69622f       ; rdi = "/bin/sh\0" as 8 raw bytes
push   rdi                         ; put the string on the stack
mov    rdi, rsp                    ; rdi = &"/bin/sh"
push   0x3b                        ; 59 = __NR_execve
pop    rax
syscall                           ; we are now a shell
```

This is the purest form of the bug: the attacker supplies the *instructions*,
not just the address of instructions that already exist. No libc offsets needed,
so in principle it works against a statically linked, fully randomised target.

`make verify` assembles `shellcode.S` and diffs it against the byte array
embedded in `fooc.c`, so the two cannot drift apart.

**Defence:** **NX** (a.k.a. W^X, "no execute"). Marking the stack
non-executable makes the hardware refuse to fetch instructions from it, and the
`ret` lands on a page that cannot run. This is why `make food` passes
`-z execstack`: a stock Linux stack is `rw-p`, not `rwx`, and the technique
dies with SIGSEGV at `RIP = the payload's address`. The single most important
lesson in the lab is that every one of these bytes only works because the
compiler was told to leave the stack executable. That flag is on for nobody's
benefit.

### Also included

| Mode | What it does |
|---|---|
| `-t leak` | connects, prints the leaks, sends nothing |
| `-t demo` | sends `rip_off + 8` bytes of `0x41`, so `RIP` becomes `0x4141...` and the daemon dies. Proves the bug with no address knowledge at all |
| `-t sled` | a ret sled, deliberately kept as a **failing** example. Without a leak you would brute-force ASLR by filling the buffer with the address of a `ret`. It cannot work here: `food` accepts 512 bytes, so the sled is ~53 slots against ~28 bits of entropy. Implemented so you can watch it fail, and confirm the mechanism really is "the CPU follows a chain of rets" |

---

## The mitigation table

This is the part to remember. Each row is a real defence, and the right-hand
column is what it actually does to the chain of events.

| Mitigation | How to enable | What it stops | What it does *not* stop |
|---|---|---|---|
| **Bound the read** | `n = read(fd, buf, sizeof buf - 1);` | **Everything.** The bug does not exist, so nothing downstream matters | Nothing — this is the only complete fix |
| **Stack canary** | `-fstack-protector-strong` (gcc's default) | The `ret`: the canary is checked on function exit, so the smash is detected and the process aborts before `RIP` is popped | A bug in a function with *no* array (nothing to protect); an overflow that stays under the canary; anything that does not return normally |
| **NX / W^X** | `-z noexecstack` (the default) | Shellcode. The payload's own instructions cannot be fetched | ret2win and ret2libc entirely. These are the *reason* ROP exists |
| **PIE + ASLR** | `-fPIE` + ASLR=2 (both default) | ret2win's hardcoded addresses. Everything moves each run | Anything where the attacker has a leak. ASLR raises the cost of an exploit; it is not a fix. Note that stack, heap and mmap are randomised but the main binary's *contents* are not — that is what ROP chains use |
| **Don't leak** | don't `printf("%p")` to clients; initialise before printing | The information leak that turns ASLR from "expensive" into "free" | — |
| **Don't use `printf(user_data)`** | `printf("%s", buf)` instead of `printf(buf)` | Format-string bugs: `%x` stack reads, `%n` arbitrary writes, which is a *second* way to get RCE | — |
| **Don't use untrusted paths** | validate and `openat()` under a fixed dir | Path traversal (CWE-22) | — |
| **CET / shadow stack** | `-fcf-protection=full`, kernel + CPU support | The `ret` itself: the shadow stack remembers the *real* return address and faults on a mismatch. Catches ROP chains that use hardware `ret` | Attacks that never `ret` (call-oriented, or overwriting a function pointer's target with a gadget chain that does not need a return) |
| **Safe languages** | Rust, Go, C# for new code | The whole class. Bounds checks are checked at runtime, not hoped for at review time | — |

### Seeing it for yourself

```sh
make run            # vulnerable daemon
make test           # all three techniques work

make test-hardened  # same source, mitigations on
```

`test-hardened` builds `food_hardened` with `-fstack-protector-strong -fPIE
-pie -z noexecstack`, swaps it in, re-runs all three, then puts the vulnerable
one back. You will see:

```
### stack segment: 'rw-p' (NOT executable) is what you want to see
--- ret2win   was stopped by the mitigations (as expected)
--- ret2libc  was stopped by the mitigations (as expected)
--- shellcode was stopped by the mitigations (as expected)
```

And in the hardened daemon's log, the canary firing:

```
*** stack smashing detected ***: terminated
```

Read that carefully, because it is the most important line in the whole lab:
**the canary caught ret2win, not PIE.** All three techniques die at the canary,
because all three go through the same `read()` and smash the same frame. NX only
separately stops shellcode's *code*; PIE only separately breaks the hardcoded
address. Turn them on individually and you will find that most single
mitigations leave you exposed to something.

---

## Files

| File | Purpose |
|---|---|
| `food.c` | the vulnerable daemon. 6 numbered bugs, each with its fix in the comment |
| `fooc.c` | the exploit. objdump-based offset discovery, `/proc`-based libc discovery, 4 payload builders |
| `shellcode.S` | the 23 shellcode bytes as assembly, so they can be read and verified. `fooc` carries them inline and does not need this at runtime |
| `Makefile` | builds, tests, and the hardened comparison |
| `tests/pty_test.c` | drives `fooc` through a pseudo-terminal and checks for real shell output |
| `tests/sock_test.c` | independent verifier over a raw socket, so the result does not depend on `fooc` |
| `food.log` | the daemon's log. Your evidence of what happened |

---

## Two bugs in this lab worth understanding

These are not the target's bugs. They are bugs in the exploit and its test
harness, and both produced convincing lies. They are documented in the source
where they live; here they are because the failure modes are instructive.

### Stack alignment: the crash that is not a NULL dereference

**Symptom.** The hijack lands correctly — `gdb` shows you sitting in `win()` —
and then the very first thing `win()` does, a `dprintf()`, dies. `SIGSEGV`
handler reports `RIP` deep inside glibc's formatter and a faulting address of
`(nil)`, which looks exactly like a corrupted pointer.

**Cause.** The System V AMD64 ABI requires 16-byte stack alignment. A normal
`ret` restores `%rsp` to precisely what the matching `call` saved, so the
invariant is preserved for free. Our bare `ret` does not: after it,
`%rsp = buf + rip_off`. Here `buf` is 16-byte aligned and `rip_off` is 88, so
the callee is handed a stack that is 8 mod 16. glibc is compiled with SSE2, and
`movaps` **faults** on a misaligned operand. On x86 that raises `#GP`, not
`#PF`, so the kernel has no faulting address and reports `si_addr = 0`. That
NULL is the tell: an alignment fault dressed up as a NULL dereference.

**Fix.** One `ret` gadget *at offset `rip_off`*, shifting the real target up
8 bytes, since each `ret` adds exactly 8 to `%rsp`. Ordering is critical: an
earlier version appended the `ret` *after* the target, producing
`[ padding | target | ret ]` where the trailing `ret` is never reached and the
fix silently does nothing. A stray `ret` that looks like a mistake is nearly
always deliberate.

### One socket, two readers: the byte that vanished

**Symptom.** Shellcode was reported working. Then the pty harness was made
stricter (turning off `ECHO`, so the terminal stopped echoing the harness's own
command line back at it) and the technique started failing. Underneath, every
technique was dropping exactly one byte from the head of each output chunk:
`uid=1000(hanez)` printed as `id=1000(hanez)`, `PWNED-OK` as `WNED-OK`,
`Linux 7.2.7` as `inux 7.2.7`.

**Cause.** `fooc` used to `dup2()` the socket onto its own stdin/stdout and
`execv()` a *local* `/bin/sh`, while a forked relay child also read that same
socket to move output to the terminal. The kernel does not care that the two
are cooperating. A stream socket has **one** read cursor, and every reader
moves it, so bytes split unpredictably between them. The local shell, being an
interactive login shell, read exactly one byte and discarded it — every single
time. `strace -f` showed it immediately:

```
read(0, "u", 1)                              <- the local shell, eating a byte
read(4, "id=1000(hanez) gid=1000(hanez) g".., 310)   <- the relay, 1 byte short
```

**Fix.** There is no shell on this side at all. There is exactly one shell in
the whole picture and it is on the victim, inside the hijacked process, with the
TCP connection as its stdin/stdout. This side only moves bytes. If you ever need
two consumers of a stream, that stream needs a single reader that deliberately
demultiplexes it.

**The meta-lesson.** The first "working" result was a false positive produced by
the pty echoing the harness's own command line back at it, and the fix for that
false positive is what exposed the real bug. Tests that cannot fail are worse
than no tests, because they convert "I do not know" into "it works." A test
harness deserves the same suspicion as the code it is testing.

---

## Hacking on it

Things worth trying, roughly in order of how much you will learn:

1. **Change `FOOD_BUFSZ` to 128.** Run `fooc` again. It should still work with no
   edits, because it reads the offset out of the disassembly. Then break it by
   hand — hardcode 88 — and watch it crash. Then add a second array between
   `buf` and the saved registers and watch the automatic detection handle it.

2. **Add `-Wformat-security` and look at what the format-string path does.**
   Send `%p %p %p %n` and watch `food` leak the stack.

3. **Use gdb.** `make debug`, then:
   ```gdb
   (gdb) break food.c:393        # the read() that overflows
   (gdb) run -p 2342
   (gdb) info registers rsp rbp
   (gdb) x/24gx $rsp             # note where the return address is
   (gdb) c                        # in another terminal: ./fooc -t ret2win
   ```
   The `SIGSEGV` handler logs `REG_RIP` and `REG_RSP`, so `food.log` tells you
   whether the hijack landed even when the child dies before you can attach.

4. **Delete the alignment fix** in `fooc.c` and watch the `#GP` fault with the
   `si_addr = 0` signature. Then read `/proc/sys/kernel/randomize_va_space` and
   think about what ASLR does and does not randomise.

5. **Break libc symbol resolution** and watch `fooc` adapt. The whole point of
   the `/proc/self/maps` approach is that no offset is hardcoded.

6. **Write a fourth technique.** A `ret2csu`-style chain if you can find
   `__libc_csu_init`, or a SROP chain (`sigreturn` frames let you control every
   register at once). Both are pure ROP and need no executable memory.

7. **Fix `food.c` properly**, one bug at a time, and re-run the exploit after
   each fix. The order in the table at the top of `food.c` is roughly the right
   order to think about them: bound the read first, because nothing else matters
   until the bug is gone.

---

## Cleanup

```sh
make stop        # stops food
make clean       # removes build products; leaves food.log alone
pkill -x sh      # only if you have stray shells from a test that went sideways
```

Note `pkill -x food` matches the process **name** exactly. Do not use
`pkill -f ./food` — that pattern also matches the shell you typed it into, and
kills your own session. That is not a hypothetical; it happened while building
this.
