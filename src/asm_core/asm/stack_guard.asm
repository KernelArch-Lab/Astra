; ============================================================================
; Astra Runtime - M-21 ASM Core
; src/asm_core/asm/stack_guard.asm
;
; uint64_t asm_stack_canary_init(void);
;
; Mint a 64-bit per-thread stack canary using RDRAND with 10 retries
; (the conventional kernel-level retry budget for RDRAND).
;
; On total RDRAND exhaustion the function returns 0. Per the M-21
; ABI contract, a zero canary signals "RNG is unusable" — the C++
; self-test (asm_core_stubs.cpp) MUST refuse to start the runtime
; in that case. Returning a predictable RDTSC-derived value, as the
; previous implementation did, silently degraded the entropy from
; 2^64 to a small window around the boot time (audit finding C8,
; 2026-05-31). The fallback was advertised as "Astra refuses to
; start when we hit it" but the detection mechanism did not exist;
; this hard-zero behaviour is what makes the advertised refusal real.
;
; System V AMD64:
;   no parameters
;   returns: rax (uint64_t)
;     non-zero  → fresh RDRAND output
;     zero      → RDRAND exhausted; CALLER MUST FAIL CLOSED
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

    ; RDRAND exhausted. Fail closed: return 0 so the C++ self-test
    ; (which checks canary != 0) rejects runtime startup.
    xor     eax, eax              ; rax = 0
.done:
    ret

section .note.GNU-stack noalloc noexec nowrite progbits
