// ============================================================================
// Astra Runtime - Common Type Definitions
// include/astra/common/types.h
//
// Foundation types used across every module in the runtime.
// Keep this header lightweight - no heavy includes.
// ============================================================================
#ifndef ASTRA_COMMON_TYPES_H
#define ASTRA_COMMON_TYPES_H

#include <cstddef>
#include <cstdint>

namespace astra
{

// -------------------------------------------------------------------------
// Fixed-width type aliases for clarity in security-critical code.
// Using explicit widths prevents platform-dependent size surprises.
// -------------------------------------------------------------------------
using U8  = std::uint8_t;
using U16 = std::uint16_t;
using U32 = std::uint32_t;
using U64 = std::uint64_t;

using I8  = std::int8_t;
using I16 = std::int16_t;
using I32 = std::int32_t;
using I64 = std::int64_t;

using SizeT = std::size_t;

// -------------------------------------------------------------------------
// Process and capability identifiers
// -------------------------------------------------------------------------
using ProcessId    = U64;
using CapabilityId = U64;
using ServiceId    = U32;
using ChannelId    = U32;

// -------------------------------------------------------------------------
// Module identifiers - matches the M-XX numbering from the spec
// -------------------------------------------------------------------------
enum class ModuleId : U16
{
    CORE        = 1,    // M-01
    ISOLATION   = 2,    // M-02
    IPC         = 3,    // M-03
    CHECKPOINT  = 4,    // M-04
    REPLAY      = 5,    // M-05
    ALLOCATOR   = 6,    // M-06
    JOB_ENGINE  = 7,    // M-07
    AI          = 8,    // M-08
    EBPF        = 9,    // M-09
    WASM        = 10,   // M-10
    AQL         = 11,   // M-11
    VERIFY      = 12,   // M-12
    NET         = 13,   // M-13
    VFS         = 14,   // M-14
    CONSENSUS   = 15,   // M-15
    HAL         = 16,   // M-16
    PROFILER    = 17,   // M-17
    CRYPTO      = 18,   // M-18
    VTIME       = 19,   // M-19
    LOADER      = 20,   // M-20
    ASM_CORE    = 21,   // M-21

    MODULE_COUNT = 21
};

} // namespace astra

#endif // ASTRA_COMMON_TYPES_H
