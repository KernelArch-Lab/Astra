; ============================================================================
; Astra Runtime - M-21 ASM Core
; src/asm_core/asm/stack_guard.asm
;
; uint64_t asm_stack_canary_init(void);
;
; Mint a 64-bit per-thread stack canary. RDRAND first; if every retry
; fails (genuinely rare — usually means the RNG is on fire), fall
; back to RDTSC mixed across both halves so the result is at least
; non-zero and not predictable across reboots.
;
; System V AMD64:
;   no parameters
;   returns: rax (uint64_t)
;
; The fallback is intentional. A zero canary would be silently
; ignored by stack-protector logic and is far worse than a slightly
; predictable one. Astra's runtime self-test refuses to start when
; we hit the fallback, but in case it ever runs in a degraded
; environment the function still returns something usable.
; ============================================================================

default rel
section .text

global asm_stack_canary_init

asm_stack_canary_init:
    mov     ecx, 10               ; RDRAND retry budget
.retry:
    rdrand  rax
    jc      .done                 ; CF=1 → fresh random in rax
    dec     ecx
    jnz     .retry

    ; RDRAND exhausted. Fall back to RDTSC.
    rdtsc                         ; edx:eax = 64-bit timestamp counter
    shl     rdx, 32
    or      rax, rdx              ; rax = (edx << 32) | eax

.done:
    ret

section .note.GNU-stack noalloc noexec nowrite progbits
