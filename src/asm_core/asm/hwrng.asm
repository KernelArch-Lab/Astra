; ============================================================================
; Astra Runtime - M-21 ASM Core
; src/asm_core/asm/hwrng.asm
;
; int asm_rdrand64(uint64_t* out);
;
; 64-bit hardware random number from Intel/AMD's RDRAND. CF=1 means
; the generator delivered a fresh random word; CF=0 means it didn't
; (entropy starvation). Spec recommends ≤10 retries before declaring
; failure.
;
; System V AMD64:
;   rdi = out (uint64_t*)
;   returns: eax = 0 on success, -1 on failure
;
; CPUID feature check is the caller's responsibility; the surrounding
; CMake passes -mrdrnd and the runtime self-test refuses to start on
; a CPU without RDRAND. So we don't pay for a CPUID check on every
; call.
; ============================================================================

default rel
section .text

global asm_rdrand64

asm_rdrand64:
    test    rdi, rdi
    jz      .nullptr

    mov     ecx, 10               ; retry budget
.retry:
    rdrand  rax                   ; CF=1 on success; rax = random word
    jc      .ok
    dec     ecx
    jnz     .retry

    ; All retries exhausted.
    mov     eax, -1
    ret

.ok:
    mov     [rdi], rax
    xor     eax, eax              ; return 0 (success)
    ret

.nullptr:
    mov     eax, -1
    ret

section .note.GNU-stack noalloc noexec nowrite progbits
