; ============================================================================
; Astra Runtime - M-21 ASM Core
; src/asm_core/asm/cache_ops.asm
;
; void asm_cache_flush_range(const void* addr, size_t len);
;
; Flush every cache line that overlaps the byte range [addr, addr+len).
; Uses CLFLUSHOPT (weakly ordered, faster than CLFLUSH) plus a final
; SFENCE so the flushes are globally visible before this function
; returns.
;
; System V AMD64:
;   rdi = addr, rsi = len
;   returns: void
;
; Why use it:
;   - Defending against cache-timing side channels: after using a
;     secret-dependent table lookup, flush the lines so a co-resident
;     attacker can't recover the index from cache state.
;   - Forcing persistent stores in NVDIMM scenarios (Astra doesn't
;     target NVDIMM yet, but the interface is here when it does).
;
; Implementation notes:
;   - Round addr down to a 64-byte cache-line boundary so the first
;     CLFLUSHOPT covers the start of the range.
;   - Walk the range in 64-byte steps. Each CLFLUSHOPT issues
;     concurrently with neighbours (its key advantage over CLFLUSH).
;   - SFENCE at the end is the documented prerequisite for ordering
;     CLFLUSHOPT against subsequent stores.
; ============================================================================

default rel
section .text

global asm_cache_flush_range

asm_cache_flush_range:
    test    rdi, rdi
    jz      .done
    test    rsi, rsi
    jz      .done

    mov     rcx, rdi              ; cursor = addr
    and     rcx, 0xFFFFFFFFFFFFFFC0    ; align down to 64-byte line
    add     rsi, rdi              ; rsi = end byte (exclusive)

.loop:
    clflushopt [rcx]
    add     rcx, 64
    cmp     rcx, rsi
    jb      .loop

    sfence
.done:
    ret

section .note.GNU-stack noalloc noexec nowrite progbits
