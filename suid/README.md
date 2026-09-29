# SUID-Root RCE Lab — `foosd` (daemon) + `foosc` (exploit)

A companion to the parent lab (`food` / `fooc`, a plain daemon where a buffer
overflow gives you a *user* shell). This one adds the most dangerous
one-character change in Unix: the **setuid bit**.

> `chmod u+s` turns "the attacker can run code on this host" into "the
> attacker can run code as **root** on this host".

That sentence is the entire lab. Everything below is the mechanism underneath
it, written down so that when you write your own software you know exactly
which two or three filesystem attributes and compiler flags decide whether a
memory-safety bug in your code is a nuisance or a root shell.

The final demo, when `foosd` is setuid-root, is a **root shell** opened over
the network by executing 32 bytes of hand-written shellcode.

---

## 1. What the setuid bit actually does

Every process on Linux carries three user IDs, and the setuid bit tinkers
with the relationship between them:

| ID | Name | Meaning |
|----|------|---------|
| `ruid` | real user ID | the account that *started* the process |
| `euid` | effective user ID | what the kernel checks when enforcing access |
| (saved) | saved set-user-ID | a "slot" a privileged process may return to later |

A normal program has `ruid == euid`. When you execute a binary with the
setuid bit set and owned by root:

```text
ruid = you        (e.g. 1000, "hanez")
euid = the owner  (e.g. 0, "root")
```

The process therefore has **root's authority** even though the user who
launched it is completely ordinary. Every check the kernel performs — can
this process read `/etc/shadow`? write a file? kill another process? — is
answered using `euid`, i.e. "yes, it's root".

`foosd` is a network daemon. It binds a port, then `fork()`s a child per
connection. A fork *inherits* the euid, so every child that handles a
connection is also root. The overflow in `foosd`'s `vulnerable_handler()` is
therefore an overflow *inside a root process*.

**Diagnose it yourself once the daemon runs:**

```console
$ ./foosd ...            # see the log line it prints at startup
[foosd 1234] startup: ruid=1000 euid=0 -> ROOT process
```

and from the exploit:

```console
$ ./foosc -t leak
foosc: target euid=0 ruid=1000
```

---

## 2. The lab at a glance

| File | Role |
|------|------|
| `foosd.c` | The intentionally vulnerable daemon (owns the bugs). Run as a *setuid-root* binary for the root-shell demo. |
| `foosc.c` | The exploit. Defaults to the 32-byte `setreuid + execve` shellcode technique. |
| `shellcode.S` | The reference shellcode; `make verify` diffs it against the byte array in `foosc.c`. |
| `tests/pty_suid_test.c` | Test harness. Drives `foosc` through a pseudo-terminal and proves *both* "a shell ran" *and* "it was root" (`uid=0(`). |
| `Makefile` | Build, `setuid`/`unsetuid` helpers, test matrix. |
| `README.md` | This file. |

> **Why a pty?** The exploit's last act is to relay your terminal to the
> shell executing on the victim. A pipe or here-doc lands on the wrong end of
> that relay; a real terminal is required.

---

## 3. Quick start

```console
$ make                       # build everything, as your normal user
$ make setuid                # one-time, asks for sudo: chown root + chmod u+s
$ make run                   # start foosd on 127.0.0.1:2343
$ make test-suid             # full matrix; shellcode + ret2win-root must give root
```

Interactive smoke test:

```console
$ ./foosc -t shellcode
...
foosc: target euid=0 ruid=1000
foosc: shell is on the victim (root if foosd is SUID); relaying
# id
uid=0(root) gid=0(root) groups=0(root)      <-- you are root, on the victim
# exit
```

When you are done:

```console
$ make stop
$ make unsetuid             # hygiene: never leave a root SUID binary lying around
```

---

## 4. *When should I set the SUID bit?* — the answer you asked for

Exactly **once, after building, before running the daemon for the
root-shell demos** — and only on a machine that is yours, disposable, and
off the network:

```console
$ make            # compile foosd, foosc, tests
$ make setuid     # <-- THE moment. sudo chown root:root foosd && sudo chmod u+s foosd
$ make run        # start AFTER setting the bit
```

Two rules that matter more than the exact timing:

1. **Set it only after the binary is final.** If you rebuild (`make` / `make
   clean`) after setting the bit you will hit a "Permission denied" writing
   the root-owned output file — and if you force the rebuild, the toolchain
   recreates the file **without** the `s`, silently undoing the setup. The
   canonical sequence whenever you rebuild is therefore

   ```console
   $ make unsetuid && make && make setuid
   ```

2. **Remove it when you are done.** `make unsetuid`. A live, root-owned,
   setuid binary with an exploitable bug sitting in your tree is not a
   learning aid, it is a root hole with a compile error between it and
   nowhere. On a shared or production machine: **don't do any of this.**
   The daemon also refuses by default to bind anything but loopback (see
   §7).

If you run the exploit *without* ever setting the bit, nothing breaks — the
payload still lands and you still get a shell. The difference is in one
number, and the exploit says it out loud:

```console
foosc: WARNING: the daemon is NOT running with euid 0.
       The payload will still land, but the shell will be
       a plain user shell, not root.
       Fix:  sudo make setuid
```

That "works, but not root" outcome is itself part of the lab. Keep it in
mind for the next section.

---

## 5. The mechanism — and the twist that makes SUID interesting

### 5.1 The overflow (identical to `food`)

`foosd`'s handler gives a `read()` 512 bytes of trust while handing it a
64-byte stack buffer:

```c
char buf[64];
n = read(fd, buf, 512);        /* <- CWE-120: 448 bytes over the edge */
```

On x86-64 the stack grows down. The exploit writes 64 bytes of junk to fill
`buf`, 8 to fill the saved frame pointer, and 8 more to replace the **saved
return address**. When `vulnerable_handler` executes `ret`, the CPU pops the
attacker's value into `RIP` — attacker-controlled code execution. The
exploit discovers the exact distance (88 bytes for this build) by parsing
`objdump` output rather than hardcoding it, so the number survives rebuilds.

### 5.2 The twist: the shell refuses to be root

Here is where thinking "SUID bug → spawn /bin/sh → root" would go wrong, and
why this lab has the exact shape it has.

When a setuid-root program runs, its `ruid` is still the launching user and
its `euid` is root. If the program — or the attacker — now starts a shell:

* `execve("/bin/sh")` does **not** change the uids; the new process inherits
  `(ruid=1000, euid=0)`.
* bash (and dash) **check exactly that condition at startup**. From the bash
  manual: *"If the shell is started with the effective user (group) id not
  equal to the real user (group) id, and the -p option is not supplied, …
  the effective user id is set to the real user id."*

So the shell takes one look at itself and *drops root* — a defence the shell
authors built specifically against this attack (the historical justification
was the setuid-shell / setuid-script problem). The result is the “works, but
not root” cases:

| Technique | What it executes | Resulting uid |
|-----------|------------------|---------------|
| `ret2win` | `foosd`'s `win()` → `execl("/bin/sh")` | **1000** — shell landed, root reset by bash |
| `ret2libc` | `system("/bin/sh")` → fresh `sh -c '/bin/sh'` | **1000** — same reset, one level down |
| `ret2win-root` | `foosd`'s `win_root()` → `setreuid(0,0); execl("/bin/sh")` | **0** — ruid cleared from C |
| `shellcode` | 32 bytes: `setreuid(0,0); execve("/bin/sh")` | **0** — ruid cleared from machine code |

The two that reach root differ from the two that don't by exactly one
idea: **they clear the *real* uid, not just the effective one.**

```c
setuid(0)          /* changes euid to 0, but ruid stays 1000:
                      bash still sees euid != ruid and STILL resets.  */
setreuid(0, 0)     /* changes BOTH: ruid = euid = 0.
                      bash sees equal uids and keeps root.            */
```

That is why the classic `/bin/sh` shellcode you will find everywhere on the
internet starts with a uid-clearing syscall — and it is the reason the
shellcode here is 32 bytes instead of 23: the first five instructions are

```asm
xor    edi, edi      ; ruid = 0
xor    esi, esi      ; euid = 0
push   0x71          ; 113 = __NR_setreuid
pop    rax
syscall
```

### 5.3 So what is the exploit, end to end?

1. `foosc` reads `foosd`'s banner over the socket. It gets:
   - `ids=0/1000` — euid/ruid (the SUID self-diagnosis)
   - `stack=…` and `libc=…` — pointers (the ASLR leaks)
   - `BUF=…` — the exact address of the buffer it is about to overflow
2. From the target binary (via `objdump`) it learns `rip_off` and the
   addresses of `win()` / `win_root()`.
3. From *its own* libc (via `/proc/self/maps` + `dlsym` + a memory scan) it
   measures the offsets of `system`, `read`, `/bin/sh` and a
   `pop rdi; ret` gadget — nothing is hardcoded.
4. It assembles the payload. For `-t shellcode` that is:
   `[32-byte setreuid+execve code][padding to RIP][ret fix][address of buf]`.
5. `foosd`'s `read()` overflows; `ret` lands on the shellcode; the kernel
   executes `setreuid(0,0)` (fine: euid 0 is privileged) and then `execve`
   of `/bin/sh`. bash starts with `ruid == euid == 0` and stays root.
6. `foosc` relays your terminal to that root shell until you type `exit`.

One sanity detail that costs people a lot of time if missed: the exploit
tests each uid-clearing behaviour **without** needing the setuid bit first.
Run `make test` before `make setuid` and you will watch every technique land
a shell while `ROOT=MISSING`; run `make test-suid` after `make setuid` and
`ROOT=SEEN` appears on the two techniques that clear the real uid. That A/B
is the whole lesson, executable in ten seconds.

---

## 6. The old one-liners — and why most of them are dead

If you have read about SUID, you have read about `PATH` hijacking, `LD_PRELOAD`,
and setuid shells. All three are classic, and all three fail on a modern
system against *this program*. It is worth knowing precisely why, because the
reasons are the defences you get for free:

| Attack class | Old claim | Why it fails on a modern box |
|--------------|-----------|------------------------------|
| `LD_PRELOAD` a malicious library | "The setuid program loads my `.so` and runs my code as root." | The kernel marks a setuid binary as **AT_SECURE**; glibc then ignores `LD_PRELOAD`, `LD_LIBRARY_PATH`, `LD_DEBUG` and friends. The environment is treated as *untrusted input*. `LD_PRELOAD` against a setuid binary is a no-op. |
| `PATH` hijack (`system("ls")` with a poisoned PATH) | "Point PATH at a directory containing my fake `ls`; the root program runs it." | A second face of the same defence: an AT_SECURE process gets a **sanitized `PATH`** (a safe default, `/usr/local/bin:/usr/bin:/bin`-ish) for `system()`/`execvp`, so the poisoned directory is never consulted. |
| Setuid `system()` command injection | "The injected command runs with euid 0." | `system()` runs the command in a fresh `/bin/sh`, and that shell — §5.2 — resets `euid = ruid` on startup. The injected command executes as the *real* uid. (It is still a bug; it just no longer escalates through `/bin/sh`.) |
| Setuid root shell on disk (`cp /bin/sh /tmp; chmod u+s`) | "Run it, get root." | Exactly the defense above, and it is why modern distros ship no setuid root shell. Even when you succeed in making one, bash refuses to keep euid 0 unless started with `-p`. |

What remains alive, and is this lab: **the program is *already* root when it
runs.** You do not need the environment or `system()`; you need the program
to execute *your* code (via a memory-corruption bug) while privileged, and
your code must be careful enough to fix the uid mismatch itself —
`setreuid(0,0)` — before it hands you a shell. Memory corruption + SUID is
the combination that still ends in `uid=0`, which is exactly why memory-safe
languages, canaries, and no-execute stacks are not a fashion choice.

---

## 7. The safety rails built into the daemon

`foosd` is deliberately the *worst* piece of software in this repository, so
it also carries the most guard rails:

1. **Loopback only, enforced.** `foosd` refuses any bind address other than
   loopback unless you pass `-L`. A setuid-root listener on a real
   interface is a remote root service; the refusal is the default so the
   dangerous state has to be typed in deliberately.
2. **Self-diagnosis.** At startup it logs `ruid`/`euid` and whether it is
   running as root, so the console shows the state the exploit depends on.
3. **The log never reaches the client.** The daemon reserves a private log
   descriptor before sockets replace fd 1, so crash reporter output and
   internal paths cannot be read back over the wire by the attacker.
4. **Crash reporter.** A SIGSEGV handler logs `RIP`/`RSP` — the value the
   attacker wrote into the return address — so a successful hijack is
   visible in `foosd.log` instead of being a silent death.
5. **`make unsetuid`.** Removing the bit is scripted, because leaving it set
   is the failure mode people actually have.

---

## 8. Mitigations — what each one does and does *not* stop

Applied to `foosd` via `make hardened`, one at a time or together:

| Mitigation | What it stops | What it does *not* stop |
|------------|---------------|-------------------------|
| `-fstack-protector-strong` (canary) | The overflow: `ret` detects a smashed canary and aborts before the attacker's address is used. Stops **all four** techniques here — they share the one vulnerable `read()`. | Nothing about the *design*: the binary is still setuid root; a different bug (format string `%n`, heap overflow, use-after-free) has no canary to trip. |
| `-fPIE -pie` (ASLR for the binary) | Using predictable `win()`/`win_root()` addresses (the ret2win techniques). | The shellcode technique, if a stack address still leaks (the `BUF=` line). |
| `-z noexecstack` (NX / W^X) | The shellcode: the CPU refuses to fetch instructions from a data-only page, so jumping to `buf` is a SIGSEGV. | ROP — running code that already exists (`ret2libc`). |
| All three together | A hard-to-overflow, randomised, non-executable-stack binary. This is what a normal hardened build looks like. | The setuid bit. **A hardened SUID binary is still a SUID binary.** If any reachable memory-safety bug survives, it is still "bug inside a root process". |

The console proof is `make test-hardened`, which swaps in the hardened build
and shows all techniques dying at the canary while `foosd_hardened.log`
records `*** stack smashing detected ***`.

Two design-level mitigations that no compiler flag delivers, and that the
parent lab (`food`) uses as well:

- **Least privilege.** A daemon for an unprivileged port (2343 > 1024) has
  no legitimate need for root. A correct `foosd` would bind, then
  `setgroups`/`setgid`/`setuid` to an unprivileged account and *verify it
  stuck* (the correct version is in the source as `drop_privs()`, never
  called — the un-called-ness is Bug #3 of the lab).
- **Bound the read.** `n = read(fd, buf, sizeof(buf) - 1)`. One correct
  line outranks every compiler flag in the table.

---

## 9. The wire protocol (so you can read the daemon with netcat)

```text
FOOSD 1.0 - deliberately vulnerable SUID service
Type 'quit' to disconnect. Buffer = 64 bytes, read accepts 512.
FOOSD 1.0 ids=0/1000 leak stack=0x7ffd... libc=0x7f...
BUF=0x7ffd...
```

* `ids=euid/ruid` — could not be printed as `euid=`/`ruid=` because the test
  harness proves a shell by grepping for the literal `uid=` and the banner
  must not contain it (a probe sharing a signature with the answer is a
  classic false-positive trap; see the comment in `foosd.c`). The harness
  additionally requires the strict `id`-output shape — `uid=NNN(...)` — so
  nothing the daemon or the exploit prints can satisfy the check by
  accident: `foosc`'s own "target euid=… ruid=…" chatter contains `uid=` as
  a substring, which once made a hardened-build test report a shell that
  had never run.
* `stack=`, `libc=`, `BUF=` — the ASLR leaks: allow the shellcode and
  ret2libc to compute exact addresses.

---

## 10. Exercises

1. **Watch the non-root demotion.** Run `make test` *before* `make
   setuid`, then again after. Explain the `ROOT=SEEN` change using the
   ruid/euid story in §5.2.
2. **Read the crash.** Run `./foosc -t demo -n` and then read `foosd.log`.
   The `RIP=0x4141414141414141` line is the attacker's padding — the proof
   that the overflow, not bad luck, controls execution.
3. **Add the canary.** `make hardened` and change the `test-hardened` loop
   yourself; the log line `*** stack smashing detected ***` is the defence
   working.
4. **Disable the leak.** Comment out the `BUF=` line in `foosd.c`,
   rebuild, and watch `-t shellcode` go from deterministic to a guessing
   game. That single line is why real ASLR bypasses are a whole field.
5. **The `-p` experiment.** In a copy of `win()`, change `execl("/bin/sh",
   "sh", NULL)` to `execl("/bin/sh", "sh", "-p", NULL)` and observe root.
   `-p` is the documented escape hatch from the shell's guard — and the
   reason "just spawn a shell" advice from old write-ups is incomplete.
6. **Why not `setuid(0)`?** Rewrite the shellcode to call `setuid(0)`
   instead of `setreuid(0,0)` (syscall 105). The shell still lands — and
   still drops to `uid=1000`. This is the single most instructive one-line
   experiment in the whole repository.

---

## 11. Safety and cleanup

- Loopback only, by default and by design; `-L` binds further, and only a
  disposable VM should even consider it.
- This is a root-shell lab. Do not run it on a machine that matters, and do
  not point `foosc -h` at anything you do not own.
- Cleanup ritual: `make stop` then `make unsetuid`, and if you want the tree
  pristine again `sudo make clean`.

```console
$ make stop
$ make unsetuid
```