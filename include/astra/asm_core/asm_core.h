// ============================================================================
// Astra Runtime - Hardened Crypto & Memory Core (M-21)
// include/astra/asm_core/asm_core.h
//
// C++ interface to hand-written x86-64 Assembly security primitives.
// All functions use extern "C" linkage for direct ASM interop.
//
// SECURITY NOTE:
//   These routines exist because the C++ compiler CANNOT be trusted
//   to generate correct code for these operations. The compiler may:
//   - Eliminate "dead" stores to sensitive buffers
//   - Introduce timing side-channels via branch prediction
//   - Break constant-time guarantees via speculative execution
//
// Until the actual .asm implementations are written, C++ stub
// implementations are provided. These stubs are NOT security-hardened
// and MUST be replaced before any security testing.
// ============================================================================
#ifndef ASTRA_ASM_CORE_ASM_CORE_H
#define ASTRA_ASM_CORE_ASM_CORE_H

#include <astra/common/types.h>
#include <cstddef>
#include <cstdint>

// -------------------------------------------------------------------------
// All ASM routines exposed via extern "C" for direct linkage.
// The actual implementations will be in .asm files (NASM syntax).
// -------------------------------------------------------------------------
extern "C"
{

// -------------------------------------------------------------------------
// Secure memory wipe
// Zeroes the buffer and issues a memory barrier.
// The compiler CANNOT optimise this away.
//
// Params:
//   aPBuf  - pointer to buffer to wipe
//   aULen  - number of bytes to zero
// -------------------------------------------------------------------------
void asm_secure_wipe(void* aPBuf, std::size_t aULen);

// -------------------------------------------------------------------------
// Constant-time byte comparison
// Compares two buffers without early exit. Execution time is identical
// regardless of where (or whether) the buffers differ.
//
// Returns: 0 if buffers are equal, non-zero otherwise
// -------------------------------------------------------------------------
int asm_ct_compare(
    const void*     aPLeft,
    const void*     aPRight,
    std::size_t     aULen
);

// -------------------------------------------------------------------------
// Constant-time conditional select (branchless)
// Returns aUValA if aBCond is true, aUValB otherwise.
// Uses cmov - no branch prediction involvement.
// -------------------------------------------------------------------------
std::uint64_t asm_ct_select(
    std::uint64_t   aUValA,
    std::uint64_t   aUValB,
    int             aBCond
);

// -------------------------------------------------------------------------
// Hardware random number generation
// Wraps RDRAND with retry logic and health checks.
//
// Returns: 0 on success, -1 on failure after max retries
// -------------------------------------------------------------------------
int asm_rdrand64(std::uint64_t* aPOut);

// -------------------------------------------------------------------------
// Serialise speculative execution (lfence wrapper)
// Prevents Spectre-class attacks at critical code boundaries.
// -------------------------------------------------------------------------
void asm_lfence(void);

// -------------------------------------------------------------------------
// Flush cache lines covering a memory range
// Used to prevent cache-timing side-channel attacks.
// -------------------------------------------------------------------------
void asm_cache_flush_range(const void* aPAddr, std::size_t aULen);

// -------------------------------------------------------------------------
// Per-thread stack canary initialisation
// Returns a random value from RDRAND for use as a stack guard.
// -------------------------------------------------------------------------
std::uint64_t asm_stack_canary_init(void);

} // extern "C"

// -------------------------------------------------------------------------
// C++ wrapper namespace for type-safe access
// -------------------------------------------------------------------------
namespace astra
{
namespace asm_core
{

// Check if the ASM core has been initialised and basic self-tests pass
bool selfTest();

// Wipe a typed buffer - template convenience over the raw C function
template <typename T>
inline void secureWipe(T* aPObj, std::size_t aUCount = 1)
{
    asm_secure_wipe(
        static_cast<void*>(aPObj),
        aUCount * sizeof(T)
    );
}

} // namespace asm_core
} // namespace astra

#endif // ASTRA_ASM_CORE_ASM_CORE_H
