# ============================================================================
# Makefile -- builds the lab: the vulnerable daemon and its exploit
# ============================================================================
#
#   make            build food, fooc and the test harnesses
#   make run        start food in the background, on loopback
#   make test       run the full technique matrix (needs `make run` first)
#   make verify     prove the shellcode in fooc.c matches shellcode.S
#   make hardened   rebuild food with every mitigation ENABLED
#   make test-hardened  run the matrix against the hardened build
#   make stop       stop the daemon
#   make clean      remove build products
#
# ---------------------------------------------------------------------------
# WHY THESE FLAGS -- the single most important thing in this file
# ---------------------------------------------------------------------------
#
# `food` is built with three protections switched OFF, deliberately:
#
#   -fno-stack-protector   no stack canary
#   -no-pie                fixed load address, so win() is a constant
#   -z execstack           executable stack, so shellcode can run
#
# Each one corresponds to a real defence that a real program gets for free, and
# `make test-hardened` turns them all back on so you can watch the techniques
# fail. That contrast is the entire lesson. Do not copy these flags into
# anything you actually ship.
#
# The exploit (`fooc`) is built with the protections ON. There is no reason for
# an attacker to disable them, and leaving them on is a useful reminder that
# the tool works fine in a hardened process.
#
# ---------------------------------------------------------------------------
# WHY -O0 -g
# ---------------------------------------------------------------------------
#
# -O0  the compiler does not reorder, inline, or elide the code. At -O2 the
#      stack layout the exploit reasons about can change between builds, and
#      variables you were told exist may be gone. For a lab you have to be
#      able to read the disassembly and find the thing the comment promised.
# -g   symbols and line numbers, so gdb is actually usable. `make debug`
#      goes further and stops at the vulnerable read().
# ============================================================================

CC      ?= gcc
CSTD    := -std=c99

# Warnings we always want, even on the vulnerable build. Note that we do NOT
# use -Werror: food.c's deliberate overflow triggers -Wstringop-overflow, and
# that warning is *supposed* to fire (see the comment at the read() call).
WARN    := -Wall -Wextra

# Debug info and no optimisation: see above.
DBG     := -O0 -g

# --- the vulnerable build -----------------------------------------------------
# These are the flags we are trying to defeat. See the header comment.
VULN    := -fno-stack-protector -no-pie -z execstack

# --- the hardened build -------------------------------------------------------
# What a modern project actually does. Note that -fstack-protector-strong is
# gcc's DEFAULT on many distros, and -fPIE is too, so the hardened build is
# really just "stop overriding the defaults". `make test-hardened` shows the
# exploits failing, which is the point.
HARDEN  := -fstack-protector-strong -fPIE -pie -z noexecstack

# Shellcode needs a terminal, and the test harness is the only thing that
# provides one. It is a normal POSIX program, not part of the exploit.
TESTCFLAGS := $(CSTD) $(DBG) $(WARN)

all: food fooc tests/pty_test tests/sock_test

# -----------------------------------------------------------------------------
# The vulnerable daemon.
# -----------------------------------------------------------------------------
food: food.c
	$(CC) $(CSTD) $(DBG) $(WARN) $(VULN) -o $@ $<

# -----------------------------------------------------------------------------
# The exploit. -ldl is needed for dlsym(), which is how it locates libc's
# system() and "/bin/sh" at runtime instead of hardcoding offsets that would
# break the next time glibc is updated.
#
# It gets the mitigations ON, unlike the target.
# -----------------------------------------------------------------------------
fooc: fooc.c
	$(CC) $(CSTD) $(DBG) $(WARN) -fstack-protector-strong -o $@ $< -ldl

# -----------------------------------------------------------------------------
# Test harnesses. These exist because the exploit's last act is to hand its
# process over to a shell; verifying that needs a real terminal, which a pipe
# or a here-doc is not.
# -----------------------------------------------------------------------------
tests/pty_test: tests/pty_test.c
	$(CC) $(TESTCFLAGS) -o $@ $<

tests/sock_test: tests/sock_test.c
	$(CC) $(TESTCFLAGS) -o $@ $<

# -----------------------------------------------------------------------------
# The hardened daemon: same source, protections on. Build it, then run
# `make test-hardened` to see which techniques it survives.
# -----------------------------------------------------------------------------
hardened: food.c
	$(CC) $(CSTD) $(DBG) $(WARN) $(HARDEN) -o food_hardened $<
	@echo
	@echo "=== food_hardened built with the mitigations ON."
	@echo "=== Stack segment permissions ('RWE' would mean executable; you"
	@echo "=== want 'RW', i.e. no-execute):"
	@readelf -W -l food_hardened | grep GNU_STACK
	@echo "=== Now run:  make test-hardened"

# -----------------------------------------------------------------------------
# verify-shellcode: prove the bytes in fooc.c are what nasm produces from
# shellcode.S. This is the check that keeps the inline byte array honest --
# a hand-maintained hex dump and a disassembler are both easy to get wrong, and
# a single wrong byte means a payload that crashes instead of running.
# -----------------------------------------------------------------------------
verify verify-shellcode: shellcode.S fooc.c
	@command -v nasm >/dev/null 2>&1 || { \
	    echo "verify-shellcode: nasm is not installed; skipping."; \
	    echo "  (Arch:  pacman -S nasm)"; exit 0; }
	@echo "=== Assembling shellcode.S ..."
	@nasm -f bin -o shellcode.bin shellcode.S
	@echo "=== nasm output:"
	@od -An -tx1 -v shellcode.bin | tr -s ' \n' ' ' | sed -e 's/^ //' \
	    -e 's/[[:space:]]*$$//'
	@echo
	@# Pull the byte list out of the C array. `sed s,/*.**/,` first strips the
	@# trailing /* ... */ annotations, so a hex constant mentioned inside a
	@# comment (there is one: "push 0x3b (execve)") is not counted as data.
	@# Stripping comments before grepping is the whole trick here.
	@sed -n '/^static const unsigned char SHELLCODE\[\] = {/,/^};/p' fooc.c \
	    | sed -e 's,/\*.*\*,,' \
	    | grep -o '0x[0-9a-fA-F][0-9a-fA-F]' \
	    | tr 'A-F' 'a-f' | tr '\n' ' ' | sed -e 's/^ //' -e 's/[[:space:]]*$$//' \
	    > .sc_c_raw.txt
	@echo "=== bytes declared in fooc.c's SHELLCODE[] array:"
	@cat .sc_c_raw.txt
	@echo
	@echo "=== comparing ..."
	@# Both sides reduced to the same plain "31 f6 31 d2 ..." form, so the
	@# comparison is on VALUES and not on how each tool happens to print them.
	@sed -e 's/0x//g' .sc_c_raw.txt > .sc_c.txt
	@od -An -tx1 -v shellcode.bin | tr -s ' \n' ' ' | sed -e 's/^ //' \
	    -e 's/[[:space:]]*$$//' > .sc_asm.txt
	@if cmp -s .sc_c.txt .sc_asm.txt; then \
	    n=$$(wc -c < shellcode.bin); \
	    echo "MATCH: the $$n bytes in fooc.c are byte-for-byte what"; \
	    echo "       shellcode.S assembles to."; \
	    rm -f .sc_c_raw.txt .sc_c.txt .sc_asm.txt; \
	else \
	    echo "MISMATCH -- the two differ:"; \
	    diff .sc_c.txt .sc_asm.txt || true; \
	    rm -f .sc_c_raw.txt .sc_c.txt .sc_asm.txt; exit 1; \
	fi

# -----------------------------------------------------------------------------
# run: start the daemon in the background.
#
# setsid + nohup + </dev/null are all needed. Without setsid the daemon dies
# when the invoking shell exits; without </dev/null it inherits your terminal
# and competes with you for it; without nohup it gets SIGHUP.
#
# It listens on 127.0.0.1 only. Please keep it that way.
# -----------------------------------------------------------------------------
PORT ?= 2342
run: food
	@echo "=== starting food on 127.0.0.1:$(PORT)"
	@setsid nohup ./food -p $(PORT) > food.log 2>&1 </dev/null & \
	    disown 2>/dev/null || true
	@sleep 1
	@if pgrep -x food >/dev/null; then \
	    echo "=== food is running (pid $$(pgrep -x food | head -1))"; \
	    echo "=== stack segment -- 'rwxp' means executable (needed for shellcode):"; \
	    grep '\[stack\]' /proc/$$(pgrep -x food | head -1)/maps; \
	else \
	    echo "=== food failed to start; see food.log"; exit 1; \
	fi

# -----------------------------------------------------------------------------
# test: the technique matrix. Every technique must print both SEEN.
#
# Note this runs against whatever ./food currently is. If you last ran
# `make hardened`, you are testing the hardened build -- which is what
# test-hardened is for.
# -----------------------------------------------------------------------------
#
# Note on the redirection below. The verdict is the "[pty_test] ..." line the
# harness prints to STDERR, and its EXIT STATUS, so stderr is sent to the
# terminal and the shell's chatter (stdout) is discarded. Piping the two
# together and tailing is what hid a real failure during development: the pty's
# echo of our own command line contains the marker string, so a loose grep on
# the transcript was always going to pass.
test: tests/pty_test
	@fail=0; \
	for t in ret2win ret2libc shellcode; do \
	    echo "=================== $$t"; \
	    if ./tests/pty_test -t $$t 2>&1 >/dev/null; then \
	        :; \
	    else \
	        fail=1; \
	    fi; \
	done; \
	echo; \
	if [ $$fail -eq 0 ]; then \
	    echo "=== all three techniques gave a working shell"; \
	else \
	    echo "=== at least one technique did NOT work."; \
	    echo "=== If food was built with `make hardened`, that is the"; \
	    echo "=== mitigations doing their job. See README.md."; \
	fi; \
	exit $$fail

# -----------------------------------------------------------------------------
# test-hardened: swap in the hardened daemon, prove the mitigations hold, then
# put the vulnerable one back. Leaves your tree exactly as it found it.
# -----------------------------------------------------------------------------
#
# Two things this target has to get right, both of which bit during development:
#
#   * `pgrep -x` matches the process NAME, and the hardened binary is
#     food_hardened, not food. Using the wrong name silently inspects nothing.
#   * The verdict is pty_test's EXIT STATUS (0 = both markers seen), not the
#     presence of its output line. Grepping for a line that is also printed on
#     failure reports success for a run that crashed.
test-hardened: hardened tests/pty_test
	@if ! pgrep -x food >/dev/null; then \
	    echo "=== start the daemon first:  make run"; exit 1; \
	fi
	@echo "### stopping the vulnerable daemon"
	@$(MAKE) --no-print-directory stop
	@echo "### starting food_hardened instead"
	@setsid nohup ./food_hardened -p $(PORT) > food_hardened.log 2>&1 \
	    </dev/null & disown 2>/dev/null || true
	@sleep 1
	@if ! pgrep -x food_hardened >/dev/null; then \
	    echo "!!! food_hardened did not start; see food_hardened.log"; \
	    $(MAKE) --no-print-directory stop; exit 1; \
	fi
	@echo "### stack segment: 'rw-p' (NOT executable) is what you want to see"
	@grep '\[stack\]' /proc/$$(pgrep -x food_hardened | head -1)/maps || true
	@echo
	@for t in ret2win ret2libc shellcode; do \
	    echo "=================== $$t"; \
	    if ./tests/pty_test -t $$t 2>&1 >/dev/null; then \
	        echo "!!! $$t STILL WORKED against the hardened build"; \
	    else \
	        echo "--- $$t was stopped by the mitigations (as expected)"; \
	    fi; \
	done; \
	echo
	@$(MAKE) --no-print-directory stop
	@echo "### restoring the vulnerable daemon"
	@setsid nohup ./food -p $(PORT) > food.log 2>&1 </dev/null \
	    & disown 2>/dev/null || true
	@sleep 1
	@echo
	@echo "=== mitigation comparison is above."
	@echo "=== Read the table in README.md to see which flag stopped what,"
	@echo "=== and note which mitigations are NOT enough on their own."

# -----------------------------------------------------------------------------
# debug: build food and run it under gdb, stopping at the vulnerable read() so
# you can watch the stack frame get overwritten.
# -----------------------------------------------------------------------------
debug: food.c
	$(CC) $(CSTD) $(DBG) $(WARN) $(VULN) -o food $<
	@echo "=== built ./food for gdb. Try:"
	@echo "    gdb -q ./food"
	@echo "    (gdb) break food.c:393      # the read() that overflows"
	@echo "    (gdb) run -p 2342"
	@echo "    (gdb) info registers rsp rbp"
	@echo "    (gdb) x/24gx \$rsp         # watch the return address"

# -----------------------------------------------------------------------------
# stop: kill the daemon.
#
# `pkill -x food` matches the process NAME exactly. Do NOT use
# `pkill -f ./food` -- that pattern also matches the shell you typed it into,
# so it kills your own session. This is not a theoretical risk; it happened
# while building this lab.
# -----------------------------------------------------------------------------
stop:
	@if pgrep -x food >/dev/null; then \
	    pkill -x food; sleep 0.5; \
	    echo "=== food stopped"; \
	else \
	    echo "=== food was not running"; \
	fi
	@# The hardened binary has a different process name, so it needs its own
	@# pkill. A leftover food_hardened keeps port 2342 bound and makes the
	@# next `make run` fail with "Address already in use".
	@if pgrep -x food_hardened >/dev/null; then \
	    pkill -x food_hardened; sleep 0.5; \
	    echo "=== food_hardened stopped"; \
	fi

clean:
	rm -f food fooc food.hardened shellcode.bin
	rm -f .sc_c_raw.txt .sc_c.txt .sc_asm.txt
	rm -f tests/pty_test tests/sock_test
	@echo "=== cleaned. (food.log is left alone; it is your evidence.)"

.PHONY: all run stop test test-hardened verify verify-shellcode hardened debug clean
