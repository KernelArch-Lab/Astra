; ============================================================================
; Astra Runtime - M-21 ASM Core
; src/asm_core/asm/ct_select.asm
;
; uint64_t asm_ct_select(uint64_t a, uint64_t b, int cond);
;
; Branchless conditional select. Returns `a` if cond != 0, else `b`.
; Implemented with CMOV — there is no branch, no branch predictor
; involvement, no measurable timing difference between the two paths.
;
; System V AMD64:
;   rdi = a, rsi = b, edx = cond
;   returns: rax
;
; Implementation:
;   - test edx, edx sets ZF = (cond == 0).
;   - mov rax, rsi defaults the answer to b.
;   - cmovnz rax, rdi overwrites with a iff ZF is clear (cond != 0).
;
; Both source registers are read on every call; the CPU does not
; speculate one path or the other based on cond. Useful for
; capability-permission bit selection where leaking the boolean
; would leak the cap.
; ============================================================================

default rel
section .text

global asm_ct_select

asm_ct_select:
    test    edx, edx
    mov     rax, rsi              ; default: b
    cmovnz  rax, rdi              ; if cond != 0 → a
    ret

section .note.GNU-stack noalloc noexec nowrite progbits
