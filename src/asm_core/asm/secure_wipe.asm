; ============================================================================
; Astra Runtime - M-21 ASM Core
; src/asm_core/asm/secure_wipe.asm
;
; void asm_secure_wipe(void* buf, size_t len);
;
; Zero a buffer in a way the C++ optimiser cannot eliminate. The compiler
; doesn't see this code, so it can't argue the writes are "dead".
;
; System V AMD64 calling convention:
;   rdi = buf
;   rsi = len
;   returns: void
;
; Implementation:
;   - Null/zero-length guard up front.
;   - Forward direction flag (`cld`) so `rep stosb` increments rdi.
;   - `rep stosb` writes al (= 0) to [rdi] rcx times, advancing rdi.
;   - mfence after the rep guarantees the writes are globally visible
;     before the next instruction. Important when the wiped memory is
;     being reused or freed; otherwise a later thread could observe
;     a partially wiped state.
; ============================================================================

default rel
section .text

global asm_secure_wipe

asm_secure_wipe:
    test    rdi, rdi
    jz      .done
    test    rsi, rsi
    jz      .done

    cld
    xor     eax, eax
    mov     rcx, rsi
    rep     stosb

    mfence

.done:
    ret

; Mark stack as non-executable (standard hardening for ELF objects).
section .note.GNU-stack noalloc noexec nowrite progbits
