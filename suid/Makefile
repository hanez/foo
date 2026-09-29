# ============================================================================
# Makefile -- builds the SUID lab: the vulnerable daemon, its exploit, and
# the test harness. Companion to the parent lab's Makefile.
# ============================================================================
#
#   make               build foosd, foosc and the test harness
#   make setuid        ONE-TIME, needs sudo: gives foosd the setuid bit and a
#                      root owner. THIS is what makes the exploit yield root.
#   make unsetuid      remove the setuid bit again when you are done
#   make run           start foosd on loopback (whatever uid it currently has)
#   make status        report the setuid state of ./foosd
#   make test          technique matrix (works with or without the setuid bit)
#   make test-suid     the matrix with --must-root on the techniques that are
#                      SUPPOSED to escalate (needs `make setuid` first)
#   make verify        prove the bytes in foosc.c equal what shellcode.S makes
#   make hardened      rebuild foosd with all mitigations ON (expect failure)
#   make test-hardened show which techniques the mitigations kill
#   make stop          stop the daemon
#   make clean         remove build products
#
# ---------------------------------------------------------------------------
# THE SETUID STATE -- the one thing that makes this lab different
# ---------------------------------------------------------------------------
# A setuid-root binary is `root:root` with the 's' bit in its mode (rwsr-xr-x).
# The whole point of this lab is the difference between running `foosd`
# WITHOUT that state (exploits land, but the shell is a plain user shell)
# and WITH it (shellcode yields uid=0):
#
#     make setuid     # needs sudo, once, after any rebuild
#     make run
#     make test-suid
#     make stop
#     make unsetuid   # hygiene: never leave it set
#
# IMPORTANT BUILD RULE: `make clean` can remove a root-owned binary (delete
# permissions come from the DIRECTORY), but recompiling OVER a root-owned
# file fails with "Permission denied". So after `make setuid`:
#     sudo make clean     # or: make unsetuid, then make, then make setuid
# ============================================================================

CC      ?= gcc
CSTD    := -std=c99

# We do NOT use -Werror: the deliberate overflow triggers
# -Wstringop-overflow in foosd.c and that warning is supposed to fire.
WARN    := -Wall -Wextra
DBG     := -O0 -g

# --- the vulnerable build -----------------------------------------------------
# Same deliberate removals as the parent lab, now with a SUID twist: dropping
# the canary, PIE and NX is what makes the techniques reachable, but NONE of
# them has anything to do with the +s bit. A hardened build of this same
# source is still a SUID binary -- just a harder-to-abuse one.
VULN    := -fno-stack-protector -no-pie -z execstack

# --- the hardened build -------------------------------------------------------
HARDEN  := -fstack-protector-strong -fPIE -pie -z noexecstack

TESTCFLAGS := $(CSTD) $(DBG) $(WARN)

# Port: kept distinct from the parent lab's 2342 so both can run together.
PORT ?= 2343

all: foosd foosc tests/pty_suid_test

# -----------------------------------------------------------------------------
# The daemon. It becomes SUID later via `make setuid`; the build itself is
# ordinary (a setuid bit is a filesystem attribute, not a linker flag).
# -----------------------------------------------------------------------------
foosd: foosd.c
	$(CC) $(CSTD) $(DBG) $(WARN) $(VULN) -o $@ $<

# -----------------------------------------------------------------------------
# The exploit: mitigations ON (the attacker gains nothing by self-weakening).
# -ldl for dlsym(), which measures libc offsets at runtime instead of
# hardcoding numbers that break on the next glibc update.
# -----------------------------------------------------------------------------
foosc: foosc.c
	$(CC) $(CSTD) $(DBG) $(WARN) -fstack-protector-strong -o $@ $< -ldl

tests/pty_suid_test: tests/pty_suid_test.c
	$(CC) $(TESTCFLAGS) -o $@ $<

# -----------------------------------------------------------------------------
# setuid: install the SUID-root state. Requires root (sudo). After this,
# `./foosd` run by ANY user starts with euid 0.
#
# Note the file must be owned by root AND the surrounding directory must not
# be writable by others -- a root-owned SUID binary in a world-writable dir
# is itself a classic bug (anyone can replace or relink it as root later).
# -----------------------------------------------------------------------------
setuid: foosd
	@echo "=== giving foosd the setuid bit (needs your sudo password)"
	@sudo sh -c 'chown root:root foosd && chmod u+s foosd && chmod 755 foosd'
	@echo
	@ls -l foosd
	@echo
	@echo "=== expect the owner 'root' and a mode starting with -rws (the s)."
	@stat -c 'owner=%U  mode=%A' foosd
	@echo "=== now:  make run ; make test-suid"
	@echo "=== when done:  make stop ; make unsetuid"

unsetuid:
	@if [ -f foosd ]; then \
	    sudo chmod u-s foosd; \
	    echo "=== setuid bit removed from foosd."; \
	    echo "=== (It may still be owned by root; rebuild with 'make unsetuid && make' \
or 'sudo make clean && make'.)"; \
	    stat -c 'owner=%U  mode=%A' foosd; \
	else \
	    echo "=== foosd not built; nothing to do"; \
	fi

# -----------------------------------------------------------------------------
# status: what state is the binary in? The daemon also reports this in its log
# at startup, so this is just a convenience.
# -----------------------------------------------------------------------------
status:
	@if [ ! -f foosd ]; then echo "=== foosd is not built yet (make)."; exit 0; fi
	@owner=$$(stat -c %U foosd); mode=$$(stat -c %A foosd); \
	echo "=== foosd: owner=$$owner mode=$$mode"; \
	case "$$mode" in -rws*) \
	    echo "=== SUID state: setuid-root ACTIVE -> shellcode gives root.";; \
	*) \
	    echo "=== SUID state: not setuid (yet) -> run:  sudo make setuid";; \
	esac

# -----------------------------------------------------------------------------
# run / stop. setsid + nohup + </dev/null are all required so the daemon
# survives the invoking shell and never competes with you for the terminal.
# -----------------------------------------------------------------------------
run: foosd
	@echo "=== starting foosd on 127.0.0.1:$(PORT)"
	@setsid nohup ./foosd > foosd.log 2>&1 </dev/null & \
	    disown 2>/dev/null || true
	@sleep 1
	@if pgrep -x foosd >/dev/null; then \
	    echo "=== foosd is running (pid $$(pgrep -x foosd | head -1))"; \
	    echo "=== stack segment -- 'rwxp' means executable (needed for shellcode):"; \
	    grep '\[stack\]' /proc/$$(pgrep -x foosd | head -1)/maps; \
	    echo "=== startup log line (uid/euid state):"; \
	    grep startup foosd.log; \
	else \
	    echo "=== foosd failed to start; see foosd.log"; exit 1; \
	fi

stop:
	@if pgrep -x foosd >/dev/null; then \
	    pkill -x foosd; sleep 0.5; \
	    echo "=== foosd stopped"; \
	else \
	    echo "=== foosd was not running"; \
	fi
	@# Also clean up a leftover hardened daemon; it would hold the port.
	@if pgrep -x foosd_hardened >/dev/null; then \
	    pkill -x foosd_hardened; sleep 0.5; \
	    echo "=== foosd_hardened stopped"; \
	fi

# -----------------------------------------------------------------------------
# test: the technique matrix. Works whether or not the setuid bit is set.
#
#   shellcode / ret2win-root   are the ESCALATING ones: the Makefile demands
#                              root ("--must-root") -- without the setuid bit
#                              these FAIL, which is the correct answer.
#   ret2win / ret2libc          are the DEMOTED ones: they land a shell, but
#                              bash resets euid=ruid, so root is NOT expected.
#                              The harness is used WITHOUT --must-root, and
#                              the ROOT= line printed tells the truth either
#                              way.
#
# The verdict is pty_suid_test's EXIT STATUS, never a grep of its output.
# -----------------------------------------------------------------------------
test: tests/pty_suid_test
	@fail=0; \
	echo "=== ret2libc (expect shell, NOT root: the shell resets euid)"; \
	./tests/pty_suid_test -t ret2libc 2>&1 >/dev/null || fail=1; \
	echo "=== ret2win   (expect shell, NOT root: win() leaves ruid set)"; \
	./tests/pty_suid_test -t ret2win 2>&1 >/dev/null || fail=1; \
	echo "=== ret2win-root (expect ROOT shell: win_root() clears ruid)"; \
	./tests/pty_suid_test -t ret2win-root --must-root 2>&1 >/dev/null || fail=1; \
	echo "=== shellcode (expect ROOT shell: setreuid+execve)"; \
	./tests/pty_suid_test -t shellcode --must-root 2>&1 >/dev/null || fail=1; \
	echo; \
	if [ $$fail -eq 0 ]; then \
	    echo "=== shellcode and ret2win-root escalated to root."; \
	    echo "=== If you expected this WITHOUT running 'make setuid', note"; \
	    echo "=== that foosd must be setuid-root for euid to be 0."; \
	else \
	    echo "=== at least one technique did not behave as expected."; \
	    echo "=== Check the ROOT= value above, foosd.log, and README.md."; \
	fi; \
	exit $$fail

# -----------------------------------------------------------------------------
# test-suid: the same matrix, but it explicitly checks the setuid state first
# so the diagnosis is obvious. Run AFTER  sudo make setuid  and  make run.
# -----------------------------------------------------------------------------
test-suid: tests/pty_suid_test
	@if [ ! -u foosd ] || [ "$$(stat -c %U foosd)" != "root" ]; then \
	    echo "!!! foosd is not setuid-root. Run:  sudo make setuid"; exit 1; \
	fi
	@$(MAKE) --no-print-directory test

# -----------------------------------------------------------------------------
# verify: prove the shellcode bytes in foosc.c are byte-for-byte what nasm
# produces from shellcode.S. A hand-maintained hex array and a hand-written
# .S file are both easy to get wrong; the diff catches it automatically.
# -----------------------------------------------------------------------------
verify verify-shellcode: shellcode.S foosc.c
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
	@# first (they mention hex constants like "0x71"), then grep the literals.
	@sed -n '/^static const unsigned char SHELLCODE\[\] = {/,/^};/p' foosc.c \
	    | sed -e 's,/\*.*\*,,' \
	    | grep -o '0x[0-9a-fA-F][0-9a-fA-F]' \
	    | tr 'A-F' 'a-f' | tr '\n' ' ' | sed -e 's/^ //' -e 's/[[:space:]]*$$//' \
	    > .sc_c_raw.txt
	@echo "=== bytes declared in foosc.c's SHELLCODE[] array:"
	@cat .sc_c_raw.txt
	@echo
	@echo "=== comparing ..."
	@sed -e 's/0x//g' .sc_c_raw.txt > .sc_c.txt
	@od -An -tx1 -v shellcode.bin | tr -s ' \n' ' ' | sed -e 's/^ //' \
	    -e 's/[[:space:]]*$$//' > .sc_asm.txt
	@if cmp -s .sc_c.txt .sc_asm.txt; then \
	    n=$$(wc -c < shellcode.bin); \
	    echo "MATCH: the $$n bytes in foosc.c are byte-for-byte what"; \
	    echo "       shellcode.S assembles to."; \
	    rm -f .sc_c_raw.txt .sc_c.txt .sc_asm.txt; \
	else \
	    echo "MISMATCH -- the two differ:"; \
	    diff .sc_c.txt .sc_asm.txt || true; \
	    rm -f .sc_c_raw.txt .sc_c.txt .sc_asm.txt; exit 1; \
	fi

# -----------------------------------------------------------------------------
# hardened: same source, all mitigations ON. Every technique should die at the
# canary; the point is the console contrast with the vulnerable build, and the
# reminder in README.md that a hardened build is still a SUID binary.
# -----------------------------------------------------------------------------
hardened: foosd.c
	$(CC) $(CSTD) $(DBG) $(WARN) $(HARDEN) -o foosd_hardened $<
	@echo
	@echo "=== foosd_hardened built with the mitigations ON."
	@echo "=== Stack segment ('RW' is what you want; 'RWE' would be executable):"
	@readelf -W -l foosd_hardened | grep GNU_STACK

# test-hardened: swap the hardened daemon in, show every technique failing,
# then put the vulnerable one back exactly as it was.
test-hardened: hardened tests/pty_suid_test
	@if ! pgrep -x foosd >/dev/null; then \
	    echo "=== start the daemon first:  make run"; exit 1; \
	fi
	@$(MAKE) --no-print-directory stop
	@echo "### starting foosd_hardened instead"
	@setsid nohup ./foosd_hardened > foosd_hardened.log 2>&1 </dev/null \
	    & disown 2>/dev/null || true
	@sleep 1
	@if ! pgrep -x foosd_hardened >/dev/null; then \
	    echo "!!! foosd_hardened did not start; see foosd_hardened.log"; \
	    $(MAKE) --no-print-directory stop; exit 1; \
	fi
	@echo "### stack segment: 'rw-p' (NOT executable) is what you want to see"
	@grep '\[stack\]' /proc/$$(pgrep -x foosd_hardened | head -1)/maps || true
	@echo
	@for t in ret2libc ret2win ret2win-root shellcode; do \
	    echo "=================== $$t"; \
	    if ./tests/pty_suid_test -t $$t 2>&1 >/dev/null; then \
	        echo "--- $$t: got a shell (report the ROOT= line above)"; \
	    else \
	        echo "--- $$t was stopped by the mitigations (as expected)"; \
	    fi; \
	done
	@echo
	@$(MAKE) --no-print-directory stop
	@echo "### restoring the vulnerable daemon"
	@setsid nohup ./foosd > foosd.log 2>&1 </dev/null & disown 2>/dev/null || true
	@sleep 1
	@echo
	@echo "=== mitigation contrast is above. See README.md."

# -----------------------------------------------------------------------------
# debug: rebuild for gdb and show the first breakpoints to try.
# -----------------------------------------------------------------------------
debug: foosd.c
	$(CC) $(CSTD) $(DBG) $(WARN) $(VULN) -o foosd $<
	@echo "=== built ./foosd for gdb. Try:"
	@echo "    gdb -q ./foosd"
	@echo "    (gdb) break foosd.c:392      # the read() that overflows"
	@echo "    (gdb) run -p 2343"
	@echo "    (gdb) info registers rsp rbp"

# -----------------------------------------------------------------------------
# clean. NOTE: after `make setuid` the binary is root-owned; rm works (delete
# permission lives on the directory) but recompiling over it does not. If make
# fails with "Permission denied" here, run `sudo make clean` first.
# -----------------------------------------------------------------------------
clean:
	rm -f foosd foosc foosd_hardened shellcode.bin
	rm -f .sc_c_raw.txt .sc_c.txt .sc_asm.txt
	rm -f tests/pty_suid_test
	@echo "=== cleaned. (foosd.log is left alone; it is your evidence.)"

.PHONY: all setuid unsetuid status run stop test test-suid verify \
        verify-shellcode hardened test-hardened debug clean