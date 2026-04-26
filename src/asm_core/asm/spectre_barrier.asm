; ============================================================================
; Astra Runtime - M-21 ASM Core
; src/asm_core/asm/spectre_barrier.asm
;
; void asm_lfence(void);
;
; A single lfence followed by ret. lfence on Intel/AMD x86_64 is a
; serialising instruction that drains the speculative-execution
; pipeline — useful as a Spectre-class barrier after a capability
; check or a bounds check, before the dependent load is allowed to
; proceed.
;
; Why it's a function and not a macro:
;   - The C++ compiler may elide an inline asm("lfence") if it can't
;     see why the surrounding code depends on it. By making it a
;     real function with side effects (memory clobber on the
;     compiler-visible side, lfence on the hardware side), the
;     barrier is preserved through every optimisation level.
; ============================================================================

default rel
section .text

global asm_lfence

asm_lfence:
    lfence
    ret

section .note.GNU-stack noalloc noexec nowrite progbits
