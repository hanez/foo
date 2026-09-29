# ============================================================================
# Makefile -- builds the wosuid lab: foowosd (a daemon that is root because it
# was STARTED as root), foowosc (the exploit), and the test harness.
# ============================================================================
#
#   make               build foowosd, foowosc and the test harness
#   make run           start foowosd as your NORMAL user (baseline: no root)
#   make run-root      start foowosd as ROOT via sudo   (the interesting case)
#   make run-root-ns   start foowosd as uid 0 inside a user namespace --
#                      no sudo needed; uses the same kernel path as real root
#   make status        report what state the daemon is running in
#   make test          technique matrix against a NON-root daemon
#                      (every technique lands a shell; root expected MISSING)
#   make test-root     the matrix with --must-root against a ROOT daemon
#                      (every technique must now yield uid=0)
#   make verify        prove the bytes in foowosc.c equal what shellcode.S makes
#   make hardened      rebuild foowosd with all mitigations ON (expect failure)
#   make test-hardened show which techniques the mitigations kill
#   make stop          stop the daemon (hint if it needs sudo)
#   make clean         remove build products
#
# ---------------------------------------------------------------------------
# THE ONE IDEA OF THIS LAB
# ---------------------------------------------------------------------------
# There is NO setuid bit: nothing in this directory ever chmods +s. foowosd
# becomes root the way real daemons do -- somebody STARTS it as root
# (`sudo make run-root`, or a systemd unit with User=root). The exploit then
# yields `uid=0(root)` shells, because the *process* is root, and the kernel
# honestly cannot tell "root because of the +s bit" from "root because root
# started it". That distinction is the whole lab: memory-safety bugs in
# privileged processes are privilege-escalation bugs, filesystem attributes
# notwithstanding.
#
#   make run           -> ruid=euid=1000   exploit lands a USER shell
#   make run-root      -> ruid=euid=0      exploit lands a ROOT shell (real)
#   make run-root-ns   -> ruid=euid=0      exploit lands a ROOT shell (uid-0
#                                           in a user namespace; for anyone
#                                           without sudo, and for CI)
#
# Because the root state here sets BOTH real and effective uid to 0, no
# setreuid prefix is needed in the shellcode (contrast the suid lab, where
# the +s bit left ruid at 1000). All three techniques -- shellcode, ret2win,
# ret2libc -- yield root when the daemon is root, and user shells when it is
# not. The verdicts are symmetric and honest.
#
# IMPORTANT: the suid lab owned a root binary; this lab owns a root PROCESS.
# The cleanup ritual matters the same way: `make stop` and do not leave a
# root-started daemon from a vulnerable lab listening anywhere.
# ============================================================================

CC      ?= gcc
CSTD    := -std=c99

# We do NOT use -Werror: the deliberate overflow triggers
# -Wstringop-overflow in foowosd.c and that warning is supposed to fire.
WARN    := -Wall -Wextra
DBG     := -O0 -g

# --- the vulnerable build -----------------------------------------------------
# Same deliberate removals as the other two labs: no canary, no PIE, an
# executable stack. None of them has anything to do with HOW the process got
# root; a hardened build of this same source is still a root daemon if root
# started it -- just a harder-to-abuse one.
VULN    := -fno-stack-protector -no-pie -z execstack

# --- the hardened build -------------------------------------------------------
HARDEN  := -fstack-protector-strong -fPIE -pie -z noexecstack

TESTCFLAGS := $(CSTD) $(DBG) $(WARN)

# Port: 2344 keeps this lab clear of food (2342) and foosd (2343).
PORT ?= 2344

all: foowosd foowosc tests/pty_wosuid_test

# -----------------------------------------------------------------------------
# The daemon and the exploit. Note the exploit builds with mitigations ON:
# the attacker gains nothing by self-weakening, and it proves the toolchain
# works in a hardened process too.
# -----------------------------------------------------------------------------
foowosd: foowosd.c
	$(CC) $(CSTD) $(DBG) $(WARN) $(VULN) -o $@ $<

foowosc: foowosc.c
	$(CC) $(CSTD) $(DBG) $(WARN) -fstack-protector-strong -o $@ $< -ldl

tests/pty_wosuid_test: tests/pty_wosuid_test.c
	$(CC) $(TESTCFLAGS) -o $@ $<

# -----------------------------------------------------------------------------
# run: baseline -- the daemon as YOUR user. Useful to prove (a) the exploit
# mechanics are independent of privilege, and (b) that without a root process
# there is no root shell. The exploit prints exactly that warning.
# -----------------------------------------------------------------------------
run: foowosd
	@rm -f foowosd.log
	@echo "=== starting foowosd as $$(id -un) (NOT root; baseline only)"
	@setsid nohup ./foowosd > foowosd.log 2>&1 </dev/null & \
	    disown 2>/dev/null || true
	@sleep 1
	@if pgrep -x foowosd >/dev/null; then \
	    echo "=== foowosd is running (pid $$(pgrep -x foowosd | head -1))"; \
	    echo "=== stack segment -- 'rwxp' means executable (needed for shellcode):"; \
	    grep '\[stack\]' /proc/$$(pgrep -x foowosd | head -1)/maps; \
	    echo "=== startup log line (uid/euid state):"; \
	    grep startup foowosd.log; \
	else \
	    echo "=== foowosd failed to start; see foowosd.log"; exit 1; \
	fi

# -----------------------------------------------------------------------------
# run-root: THE interesting case. Starts the daemon as real root (sudo), so
# the process has ruid == euid == 0 and the exploit yields uid=0(root).
# -----------------------------------------------------------------------------
run-root: foowosd
	@if [ "$$(id -u)" -eq 0 ]; then \
	    rm -f foowosd.log; \
	    echo "=== already root; starting foowosd directly"; \
	    setsid nohup ./foowosd > foowosd.log 2>&1 </dev/null & \
	        disown 2>/dev/null || true; \
	else \
	    echo "=== starting foowosd as ROOT via sudo (process uid will be 0)"; \
	    sudo sh -c 'rm -f foowosd.log; setsid nohup ./foowosd > foowosd.log 2>&1 </dev/null &'; \
	fi
	@sleep 1
	@if pgrep -x foowosd >/dev/null; then \
	    pid=$$(pgrep -x foowosd | head -1); \
	    echo "=== foowosd is running (pid $$pid)"; \
	    echo "=== process euid: $$(ps -o euid= -p $$pid | tr -d ' ') (0 means root)"; \
	    echo "=== startup log line (uid/euid state):"; \
	    grep startup foowosd.log; \
	else \
	    echo "=== foowosd failed to start; see foowosd.log"; exit 1; \
	fi
	@echo
	@echo "=== now:  make test-root"
	@echo "=== when done:  make stop"

# -----------------------------------------------------------------------------
# run-root-ns: the no-password road to a genuinely uid-0 daemon. unshare -r
# maps your ids to 0 inside a fresh user namespace, then execs foowosd, which
# therefore runs with ruid == euid == 0 -- the same uids the kernel hands a
# real root process. Every syscall the exploit touches (bind, read, execve,
# the '# id' proof) behaves identically, so this exercises the ENTIRE root
# path with no sudo. It is a verification tool and CI-friendly; real root via
# run-root is the production-grade final demo.
# -----------------------------------------------------------------------------
run-root-ns: foowosd
	@command -v unshare >/dev/null 2>&1 || { \
	    echo "!!! unshare not available (util-linux); use 'sudo make run-root'"; \
	    exit 1; }
	@rm -f foowosd.log
	@echo "=== starting foowosd inside a user namespace as uid 0 (no sudo)"
	@setsid nohup unshare -r ./foowosd > foowosd.log 2>&1 </dev/null & \
	    disown 2>/dev/null || true
	@sleep 1
	@if pgrep -x foowosd >/dev/null; then \
	    pid=$$(pgrep -x foowosd | head -1); \
	    echo "=== foowosd is running (pid $$pid)"; \
	    echo "=== process euid (namespaced): $$(ps -o euid= -p $$pid | tr -d ' ') (0 means root)"; \
	    echo "=== startup log line (uid/euid state):"; \
	    grep startup foowosd.log; \
	else \
	    echo "=== foowosd failed to start; see foowosd.log"; exit 1; \
	fi
	@echo
	@echo "=== now:  make test-root      (and, when done: make stop)"

stop:
	@if pgrep -x foowosd >/dev/null; then \
	    pkill -x foowosd; sleep 0.5; \
	    if pgrep -x foowosd >/dev/null; then \
	        echo "=== foowosd is root-owned and pkill needs privileges:"; \
	        echo "       sudo pkill -x foowosd"; \
	    else \
	        echo "=== foowosd stopped"; \
	    fi; \
	else \
	    echo "=== foowosd was not running"; \
	fi
	@# Also clean up a leftover hardened daemon; it would hold the port.
	@# Linux comm names are truncated to 15 chars, so -x must match
	@# 'foowosd_hardene', not the full filename.
	@if pgrep -x foowosd_hardene 2>/dev/null; then \
	    pkill -x foowosd_hardene 2>/dev/null; sleep 0.5; \
	    echo "=== foowosd_hardened stopped"; \
	fi

status:
	@if pgrep -x foowosd >/dev/null; then \
	    pid=$$(pgrep -x foowosd | head -1); \
	    euid=$$(ps -o euid= -p $$pid | tr -d ' '); \
	    echo "=== foowosd: running, pid $$pid, euid=$$euid"; \
	    if [ "$$euid" -eq 0 ]; then \
	        echo "=== running as ROOT -> the exploit yields uid=0(root) shells"; \
	    else \
	        echo "=== running as a normal user -> the exploit yields user shells (baseline)"; \
	    fi; \
	else \
	    echo "=== foowosd: not running"; \
	fi
	@echo "=== binary: $$(stat -c '%A %U' foowosd 2>/dev/null || echo 'not built yet')"
	@echo "=== (no setuid bit is involved in this lab; there never is one)"

# -----------------------------------------------------------------------------
# test: baseline matrix against a NON-root daemon. Every technique should land
# a shell; root is expected MISSING. The verdict is pty_wosuid_test's EXIT
# STATUS, never a grep of its output.
# -----------------------------------------------------------------------------
test: tests/pty_wosuid_test
	@pgrep -x foowosd >/dev/null || { \
	    echo "!!! foowosd is not running. Start it first:  make run"; exit 1; }
	@fail=0; \
	echo "=== ret2win   (baseline: shell, root MISSING -- daemon not root)"; \
	./tests/pty_wosuid_test -t ret2win 2>&1 >/dev/null || fail=1; \
	echo "=== ret2libc  (baseline: shell, root MISSING -- daemon not root)"; \
	./tests/pty_wosuid_test -t ret2libc 2>&1 >/dev/null || fail=1; \
	echo "=== shellcode (baseline: shell, root MISSING -- daemon not root)"; \
	./tests/pty_wosuid_test -t shellcode 2>&1 >/dev/null || fail=1; \
	echo; \
	if [ $$fail -eq 0 ]; then \
	    echo "=== all techniques landed shells against the non-root daemon."; \
	    echo "=== To see them land ROOT shells, run the daemon as root:"; \
	    echo "===     make stop && make run-root && make test-root"; \
	else \
	    echo "=== at least one technique failed against the non-root daemon."; \
	    echo "=== Check foowosd.log and the marker= lines above."; \
	fi; \
	exit $$fail

# -----------------------------------------------------------------------------
# test-root: the whole point. Demands the daemon actually run with uid 0
# (checked two ways: a running process, and the log's "ROOT process" line),
# then runs every technique with --must-root. A clean pass means all three
# yielded uid=0(root) shells -- root RCE with no setuid bit anywhere.
# -----------------------------------------------------------------------------
test-root: tests/pty_wosuid_test
	@pgrep -x foowosd >/dev/null || { \
	    echo "!!! foowosd is not running. Start it first:"; \
	    echo "       sudo make run-root    (or: make run-root-ns)"; exit 1; }
	@grep -q -- '-> ROOT process' foowosd.log || { \
	    echo "!!! foowosd is running but NOT as root (see foowosd.log)."; \
	    echo "    Restart it as root: sudo make run-root  (or make run-root-ns)"; \
	    exit 1; }
	@fail=0; \
	for t in ret2win ret2libc shellcode; do \
	    echo "=== $$t (must yield uid=0(root))"; \
	    if ./tests/pty_wosuid_test -t $$t --must-root 2>&1 >/dev/null; then \
	        echo "--- $$t: ROOT shell confirmed"; \
	    else \
	        fail=1; echo "--- $$t: FAILED to get root"; \
	    fi; \
	done; \
	echo; \
	if [ $$fail -eq 0 ]; then \
	    echo "=== ALL techniques yielded uid=0(root) shells."; \
	    echo "=== Root RCE with NO setuid bit: the process was root because"; \
	    echo "=== root started it. See README.md for why this is the whole point."; \
	else \
	    echo "=== root escalation FAILED for at least one technique."; \
	fi; \
	exit $$fail

# -----------------------------------------------------------------------------
# verify: prove the shellcode bytes in foowosc.c are byte-for-byte what nasm
# produces from shellcode.S.
# -----------------------------------------------------------------------------
verify verify-shellcode: shellcode.S foowosc.c
	@command -v nasm >/dev/null 2>&1 || { \
	    echo "verify-shellcode: nasm is not installed; skipping."; \
	    echo "  (Arch:  pacman -S nasm)"; exit 0; }
	@echo "=== Assembling shellcode.S ..."
	@nasm -f bin -o shellcode.bin shellcode.S
	@echo "=== nasm output:"
	@od -An -tx1 -v shellcode.bin | tr -s ' \n' ' ' | sed -e 's/^ //' \
	    -e 's/[[:space:]]*$$//'
	@echo
	@# Pull the hex list out of the C array. Strip the trailing /* */ annotations
	@# first (they mention hex constants like "0x3b"), then grep the literals.
	@sed -n '/^static const unsigned char SHELLCODE\[\] = {/,/^};/p' foowosc.c \
	    | sed -e 's,/\*.*\*/,,' \
	    | grep -o '0x[0-9a-fA-F][0-9a-fA-F]' \
	    | tr 'A-F' 'a-f' | tr '\n' ' ' | sed -e 's/^ //' -e 's/[[:space:]]*$$//' \
	    > .sc_c_raw.txt
	@echo "=== bytes declared in foowosc.c's SHELLCODE[] array:"
	@cat .sc_c_raw.txt
	@echo
	@echo "=== comparing ..."
	@sed -e 's/0x//g' .sc_c_raw.txt > .sc_c.txt
	@od -An -tx1 -v shellcode.bin | tr -s ' \n' ' ' | sed -e 's/^ //' \
	    -e 's/[[:space:]]*$$//' > .sc_asm.txt
	@if cmp -s .sc_c.txt .sc_asm.txt; then \
	    n=$$(wc -c < shellcode.bin); \
	    echo "MATCH: the $$n bytes in foowosc.c are byte-for-byte what"; \
	    echo "       shellcode.S assembles to."; \
	    rm -f .sc_c_raw.txt .sc_c.txt .sc_asm.txt; \
	else \
	    echo "MISMATCH -- the two differ:"; \
	    diff .sc_c.txt .sc_asm.txt || true; \
	    rm -f .sc_c_raw.txt .sc_c.txt .sc_asm.txt; exit 1; \
	fi

# -----------------------------------------------------------------------------
# hardened: same source, all mitigations ON. Every technique should die at the
# canary; the console contrast is the lesson, plus the reminder that a
# hardened build is still a root daemon if root started it.
# -----------------------------------------------------------------------------
hardened: foowosd.c
	$(CC) $(CSTD) $(DBG) $(WARN) $(HARDEN) -o foowosd_hardened $<
	@echo
	@echo "=== foowosd_hardened built with the mitigations ON."
	@echo "=== Stack segment ('RW' is what you want; 'RWE' would be executable):"
	@readelf -W -l foowosd_hardened | grep GNU_STACK

test-hardened: hardened tests/pty_wosuid_test
	@if ! pgrep -x foowosd >/dev/null; then \
	    echo "=== start the daemon first:  make run  (or make run-root)"; exit 1; \
	fi
	@$(MAKE) --no-print-directory stop
	@echo "### starting foowosd_hardened instead"
	@setsid nohup ./foowosd_hardened > foowosd_hardened.log 2>&1 </dev/null \
	    & disown 2>/dev/null || true
	@sleep 1
	@if ! pgrep -x foowosd_hardene 2>/dev/null; then \
	    echo "!!! foowosd_hardened did not start; see foowosd_hardened.log"; \
	    $(MAKE) --no-print-directory stop; exit 1; \
	fi
	@echo "### stack segment: 'rw-p' (NOT executable) is what you want to see"
	@grep '\[stack\]' /proc/$$(pgrep -x foowosd_hardene 2>/dev/null | head -1)/maps || true
	@echo
	@for t in ret2win ret2libc shellcode; do \
	    echo "=================== $$t"; \
	    if ./tests/pty_wosuid_test -t $$t 2>&1 >/dev/null; then \
	        echo "--- $$t: got a shell (report the ROOT= line above)"; \
	    else \
	        echo "--- $$t was stopped by the mitigations (as expected)"; \
	    fi; \
	done
	@echo
	@$(MAKE) --no-print-directory stop
	@echo "### restoring the vulnerable daemon (same uid mode as before: run/run-root/run-root-ns)"
	@setsid nohup ./foowosd > foowosd.log 2>&1 </dev/null & disown 2>/dev/null || true
	@sleep 1
	@echo
	@echo "=== mitigation contrast is above. See README.md."

# -----------------------------------------------------------------------------
# debug: rebuild for gdb and show the first breakpoints to try.
# -----------------------------------------------------------------------------
debug: foowosd.c
	$(CC) $(CSTD) $(DBG) $(WARN) $(VULN) -o foowosd $<
	@echo "=== built ./foowosd for gdb. Try:"
	@echo "    gdb -q ./foowosd"
	@echo "    (gdb) break foowosd.c:345      # the read() that overflows"
	@echo "    (gdb) run -p 2344"
	@echo "    (gdb) info registers rsp rbp"

# -----------------------------------------------------------------------------
# clean. Logs are left: they are your evidence.
# -----------------------------------------------------------------------------
clean:
	rm -f foowosd foowosc foowosd_hardened shellcode.bin
	rm -f .sc_c_raw.txt .sc_c.txt .sc_asm.txt
	rm -f tests/pty_wosuid_test
	@echo "=== cleaned. (foowosd.log / foowosd_hardened.log are left alone.)"

.PHONY: all run run-root run-root-ns stop status test test-root verify \
        verify-shellcode hardened test-hardened debug clean