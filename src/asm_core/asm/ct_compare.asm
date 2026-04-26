; ============================================================================
; Astra Runtime - M-21 ASM Core
; src/asm_core/asm/ct_compare.asm
;
; int asm_ct_compare(const void* left, const void* right, size_t len);
;
; Constant-time byte comparison. Returns 0 if buffers are equal,
; non-zero otherwise. Critically: execution time depends on `len`
; only — never on which byte differs or how many differ.
;
; System V AMD64:
;   rdi = left, rsi = right, rdx = len
;   returns: eax (int)
;
; Why this matters:
;   - libc memcmp() returns early on the first byte mismatch. An
;     attacker comparing tokens can measure how many bytes match
;     before the early-exit, and recover the secret byte by byte.
;   - This routine has no early exit. Every byte is XORed and the
;     result OR-accumulated. Total work is exactly O(len) loads
;     and arithmetic, regardless of buffer contents.
;
; Loop structure (inner body is data-independent):
;   eax (accumulator) starts at 0.
;   For each byte i in [0, len):
;       eax |= (left[i] ^ right[i])
;   Return eax. If any byte differed, eax has at least one set bit.
;
; The only data-independent control flow is the loop counter — which
; the compiler can see and an attacker cannot influence (len is
; assumed public, e.g. sizeof(token)).
; ============================================================================

default rel
section .text

global asm_ct_compare

asm_ct_compare:
    ; Null-pointer guard. Treat null as comparison error → return -1.
    test    rdi, rdi
    jz      .nullptr
    test    rsi, rsi
    jz      .nullptr

    xor     eax, eax              ; accumulator
    test    rdx, rdx
    jz      .done                 ; len == 0 → return 0 (equal)

    xor     ecx, ecx              ; index = 0
.loop:
    movzx   r8d, byte [rdi + rcx]
    movzx   r9d, byte [rsi + rcx]
    xor     r8d, r9d
    or      eax, r8d
    inc     rcx
    cmp     rcx, rdx
    jb      .loop

.done:
    ret

.nullptr:
    mov     eax, -1
    ret

section .note.GNU-stack noalloc noexec nowrite progbits
