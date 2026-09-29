# The `wosuid` lab — root RCE with **no** setuid bit

```
  foowosd   an intentionally vulnerable daemon that is root because it was
            *STARTED* as root  (port 2344, loopback-only by default)
  foowosc   the exploit: turns a stack overflow into a **root** shell by
            executing shellcode — same 23 bytes that pwned the user-level
            `food` daemon in the parent lab
```

This is the third lab in the series. Same exploit toolchain, same style, one
fundamental difference:

| lab      | how the target process becomes root            | `uid=0(root)` shell? |
|----------|------------------------------------------------|----------------------|
| food/fooc| never — it is a plain user daemon              | no                   |
| foosd/foosc | the SUID bit (`chmod u+s`) — euid 0, ruid 1000 | yes (needs `setreuid` in the shellcode, because bash resets euid→ruid) |
| **foowosd/foowosc** | **none — root *starts* the daemon** (sudo / systemd `User=root`) | **yes (plain `execve` shellcode)** |

The setuid bit is a *transfer vehicle* for privilege — not the privilege
itself. A daemon launched by root has real, effective and saved uid all equal
to 0. To the kernel that is root, period; it cannot and does not care whether
the process got there via `+s` on a file or via `sudo ./foowosd`. So the
overflow in a root-started daemon is a root exploit — *"I don't have SUID
binaries" is not the same as "I am not exploitable".*

That is the whole lesson of this lab. Everything below is the machinery.

---

## Quick start (what the user requested)

```
cd wosuid
make                 # build the daemon, the exploit, and the test harness
```

### The real thing — run the daemon as **root**

```
sudo make run-root      # starts foowosd as uid 0 (process, not file mode)
make test-root          # every technique must now yield uid=0(root)
```

### No sudo? The identical kernel path via a user namespace

```
make run-root-ns        # uid 0 inside a user namespace — no password needed
make test-root          # same verdicts; used by CI and anyone without sudo
```

### Baseline — daemon as your normal user (no root anywhere)

```
make run                # foowosd runs with your uids
make test               # exploits land shells, but `root` is expected MISSING
```

### Cleanup ritual (always: this is a root-shell lab)

```
make stop
```

`foowosd` is *not* setuid and nothing in this directory ever chmods `+s` —
that is the point. The dangerous state is the **process**, not the file.

---

## When you are told to set the SUID bit

You are **not** going to. This lab deliberately has no SUID bit:

- `foowosd` is built, owned and mode-regular like any other program.
- It becomes root the way real daemons do — by being *started* by root.
- `make run-root` uses `sudo` for exactly that, and `make run-root-ns` gets
  a genuinely uid-0 process without any of it.

The suid bit belongs to the *sibling* lab (`foosd`). The contrast between the
two is the syllabus:

1. SUID lab: the bit gives **euid 0 but ruid 1000** → `execve("/bin/sh")` is
   demoted by bash's guard (`euid != ruid` → reset) → shellcode must call
   `setreuid(0,0)` first (32-byte payload).
2. This lab: root **starts** the process → **ruid == euid == 0** → the guard
   has nothing to reset → the plain 23-byte `execve` shellcode keeps root.

Same overflow. Same technique. Different *origin* of privilege, different
payload shape. That is the lesson in miniature.

---

## The protocol

Whatever kind of client connects, foowosd greets it with:

```
FOOWOSD 1.0 ids=0/0 leak stack=0x7ffd… libc=0x7f…      (the banner + leaks)
BUF=0x7ffd…                                             (the buffer address)
```

`ids=euid/ruid` is the *"am I root?"* side-channel. foowosc prints a loud
warning when euid is not 0 (i.e. you started the daemon as a plain user): the
payload will still land, but the shell will be a user shell, and calling the
exploit "broken" would be wrong — it is merely not escalating.

> Spelling note: `ids=`, not `euid=`/`ruid=`. The test harness proves a live
> `id` ran by matching the literal `uid=NNN(` shape, so the banner must never
> contain a substring that itself satisfies the check. (In the SUID lab this
> exact trap produced a spectacular false positive.)

---

## The exploit techniques (`foowosc -t …`)

All four exploit paths below work against foowosd. When the daemon is root,
**all four that spawn anything yield root** — unlike the SUID lab, where
ret2win/ret2libc were quietly demoted to uid 1000 by bash's guard. Here there
is no mismatch to guard against.

| `-t`          | what happens                                                        | when daemon is root |
|---------------|---------------------------------------------------------------------|---------------------|
| `shellcode`   | 23-byte `execve("/bin/sh", NULL, NULL)` runs on the stack.          | **root shell** (default) |
| `ret2win`     | jump to `win()` → `execl("/bin/sh")`                                | **root shell** |
| `ret2libc`    | ROP: `pop rdi; ret` → `"/bin/sh"` → `system()`                      | **root shell** |
| `demo`        | junk overflow only — expect a SIGSEGV in the daemon log             | crash, by design |
| `leak`        | just print the leaks, send no payload                               | n/a |

```
./foowosc -t shellcode       # interactive; default target 127.0.0.1:2344
./foowosc -t shellcode -n    # send and report, no interactive session
```

A successful interactive session relays your terminal to the shell *on the
victim* — there is exactly one shell in the picture, and it is `/bin/sh`
running as root inside foowosd. Type `id` to see `uid=0(root)`.

### Why there is no `ret2win-root` technique here

foosc had one — it jumped to a `win_root()` that called `setreuid(0,0)`
before exec, because a setuid process ran with a real uid that still said
1000. A root-*started* process has real uid 0 already; there is nothing to
clear, so the extra function and technique would be teaching nothing.
Removed.

---

## What foowosc does, step by step

1. **Static analysis** — `objdump -d` of `./foowosd`. Finds
   `vulnerable_handler`, `win()`, the `lea -0x50(%rbp)` that addresses `buf`,
   and the first bare `ret`. From the displacement it computes
   `rip_off = 80 + 8 = 88`. Nothing is hardcoded; this survives a rebuild.
2. **Self-introspection** — reads its own `/proc/self/maps` and `dlsym()`s
   `system`/`read` to learn libc *offsets*. The target's libc base is
   `leaked_read − off_read`, then `system = base + off_system`, and so on.
   This delta-arithmetic is why exploits stay alive across libc versions.
3. **Connect** — reads the banner/leaks (`ids=`, `stack=`, `libc=`, `BUF=`).
4. **Build the payload** — for `shellcode`: 23 bytes of machine code, padding
   to `rip_off`, then the saved RIP = `buf` (so `ret` jumps onto the code).
   For `ret2win`/`ret2libc`: addresses computed from analysis — no execution
   of the stack needed.
5. **The alignment fix** — a hijacked bare `ret` hands the callee `rsp ≡ 8
   (mod 16)`, and glibc's SSE2 code `movaps`-faults on a misaligned stack (the
   crash reporter logs `si_addr=(nil)` — the tell). foowosc inserts one extra
   `ret` gadget before the real target, restoring the invariant. Kid-gloves
   engineering in a shellcode lab, but it is the difference between a payload
   that "sometimes works" and one that always works.
6. **Send, then relay** — the victim process *is* the shell; this process only
   splices bytes. No local shell, no second reader — the single-read-cursor
   failure (one byte eaten off every chunk) is documented in `become_shell()`.

---

## The daemon's deliberate bugs (all in `foowosd.c`, all real CWE classes)

| # | bug | CWE | note |
|---|-----|-----|------|
| 1 | `read(fd, buf, 512)` into a 64-byte stack buffer | CWE-120 | the overflow: 448 bytes past `buf`, saved RIP at +88 |
| 2 | `snprintf(line, …, "%.*s", …)` only; but attacker `%` in the echo path | CWE-134 | the leak is the real payload here; a `%n` in a *root* process would be write-what-where as root |
| 3 | children keep root while handling untrusted input | CWE-271 | the correct `drop_privs()` (setgroups→setgid→setuid, in that order, with a verify) sits in the file, commented, *deliberately uncalled* |
| 4 | `ids=`, `stack=`, `libc=`, `BUF=` disclosed to every client | CWE-200 | without these leaks the shellcode and ret2libc techniques could not compute addresses (ASLR would defeat them) |

The handler is exactly the same `buf[64]`/`read(512)` shape as the other two
labs, so the shared objdump-based discovery pipeline works unchanged.

---

## How to inspect the daemon (learning path)

```
make status            # is it running? as which uid? file mode shown
make run-root          # or run / run-root-ns
./foowosc -t leak      # see the banner and the leaks, send nothing
./foowosc -t demo      # junk overflow -> SIGSEGV, logged with RIP/rsp
./foowosc -t shellcode # the interactive root shell
make test-root         # full matrix, all techniques, --must-root
```

Crash reporter: on SIGSEGV the daemon logs the faulting address, RIP and RSP.
A `ret` into non-canonical `0x4141…` faults at the `ret` itself (RIP like
`0x4028xx`, `si_addr=(nil)`) — worth knowing before you misread a log line as
a NULL dereference.

---

## Why the shellcode is 23 bytes, not 32

```
31 f6        xor esi, esi            ; argv = NULL
31 d2        xor edx, edx            ; envp = NULL
48 bf 2f62696e2f736800 movabs rdi, "/bin/sh\0"
57           push rdi
48 89 e7     mov rdi, rsp
6a 3b        push 0x3b               ; 59 = execve
58           pop rax
0f 05        syscall
```

The SUID lab needs `setreuid(0,0)` before this. This lab does not, for the
reason repeated throughout: **ruid is already 0** because root started the
process. `make verify` proves the bytes in `foowosc.c` are byte-for-byte what
`shellcode.S` assembles to.

---

## Mitigations — what `make hardened` changes

Hardened build (`-fstack-protector-strong -fPIE -pie -z noexecstack`):

| technique | vulnerable `foowosd` | hardened `foowosd_hardened` |
|-----------|----------------------|------------------------------|
| `shellcode` | root shell (executable stack) | SIGSEGV at the canary check / NX |
| `ret2win` / `ret2libc` | root shell | canary aborts `ret` — but note: a *PIE* build also makes those addresses random |
| `demo` | SIGSEGV, logged | SIGSEGV, logged |

`make test-hardened` demonstrates this live. The important observation is not
just that the mitigations killed the techniques — it is that they did **not**
make the daemon "not root". A hardened build that is still *started* as root
is still a root daemon; the mitigation only raises the bar for the attacker.
Least privilege (`drop_privs()`) and memory safety are two different bugs,
and a daemon that does not need root should not have it.

---

## Safety rails (same policy as the SUID lab)

- **Loopback only.** foowosd refuses any bind other than `127.0.0.1` /
  `localhost` / `::1` unless you pass `-L`. A root daemon on a real interface
  is a *remote* root service. `-L` exists solely to show the guard; do not
  use it on anything that matters.
- **State is logged loudly.** Startup prints `ruid/euid` and whether this is
  a root process, so you always know which exploit outcome to expect.
- **Verdicts come from exit statuses** in `make test*` (the pty harness's
  return code), never from grepping its stdout — greppable output lies.
- **pty must run cooked + ECHO off** or the harness echoes its own command
  line and fakes the marker. The harness turns ECHO off and keeps ECHONL on.
- **Cleanup ritual:** `make stop` after every session. If the daemon is
  root-owned, `stop` tells you to run `sudo pkill -x foowosd`.
- Never run this on any host you care about. It exists to hand out `uid=0`
  shells over the loopback interface.

---

## Exercises

1. Run `make run` (user daemon), then `./foowosc -t shellcode`. Why is the
   shell not root? (Check `ids=` in the banner — foowosc tells you before you
   even connect.)
2. `make stop && sudo make run-root && make test-root`. Explain, from the
   banner line, why all four techniques now yield `uid=0(root)`.
3. In `foowosd.c`, find `drop_privs()` and read *why the order* of
   `setgroups → setgid → setuid` matters. Decide where in `main()` it would
   belong, and what the lab's exploit surface becomes once it is actually
   called.
4. Compute `rip_off` by hand from `objdump -d foowosd`: find `buf`'s
   `lea -0xNN(%rbp)` inside `vulnerable_handler`, then `NN + 8`. foowosc does
   exactly this; check its math against your own.
5. `make hardened && make test-hardened`. Which technique falls to the canary
   and which to NX? Why does hardening not change what `make status` reports
   about the *process*?
6. Compare the two labs' shellcodes: 23 bytes here, 32 for foosd. What does
   the extra 9 bytes do, and why is it only needed in the SUID case?
7. Read `become_shell()`'s comment about the single read cursor. Recreate the
   failure mode mentally: two readers on one socket means the login shell eats
   one byte per chunk — "uid=1000…" arrives as "id=1000…". Why can a relay
   process never have this bug?

---

## Files

```
foowosd.c                 the vulnerable root daemon (every line commented)
foowosc.c                 the exploit (every line commented)
shellcode.S               reference assembly for the 23-byte payload
tests/pty_wosuid_test.c   the pty harness (marker + strict id-shape checks)
Makefile                  build / run / run-root / run-root-ns / test /
                          test-root / verify / hardened / clean …
```

Sibling labs: `../food.c`/`../fooc.c` (user-level baseline, port 2342) and
`../suid/` (SUID-root daemon `foosd`/`foosc`, port 2343). Ports are distinct
on purpose — you can run all three at once and cross-check their banners'
`ids=` lines.