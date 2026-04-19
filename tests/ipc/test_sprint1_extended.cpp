// ============================================================================
// Astra Runtime - M-03 IPC
// tests/ipc/test_sprint1_extended.cpp
//
// Additional Sprint 1 tests that go beyond the acceptance suite.
// These use concrete Astra system data: real channel IDs from the
// architecture (Channel 0 = bootstrap, Channel 4 = anomaly alert, etc.),
// binary payloads that mimic control-plane messages, multiple concurrent
// channels, and stress of the fd-dup path used by SCM_RIGHTS.
// ============================================================================

#include <astra/ipc/ChannelFactory.hpp>
#include <astra/common/types.h>

#include <array>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

#include <sys/wait.h>
#include <unistd.h>
#include <fcntl.h>

using namespace astra;
using namespace astra::ipc;

namespace
{

int g_iPassed = 0;
int g_iFailed = 0;

// ---- Real Astra channel IDs from the architecture diagram ----------------
constexpr ChannelId CHAN_BOOTSTRAP      = 0U;  // M-01 <-> M-03 bootstrap
constexpr ChannelId CHAN_ISOLATION_CMD  = 1U;  // M-01 -> M-02 isolation
constexpr ChannelId CHAN_IPC_ENGINE     = 3U;  // main IPC channel
constexpr ChannelId CHAN_ANOMALY_ALERT  = 4U;  // M-08 -> M-01
constexpr ChannelId CHAN_CHECKPOINT     = 6U;  // M-01 -> M-04
constexpr ChannelId CHAN_EBPF_METRICS   = 8U;  // M-09 -> M-08
constexpr ChannelId CHAN_NUMA_TOPOLOGY  = 9U;  // M-03 -> M-16

// ---- Minimal wire format mimicking a CHANNEL_CREATE control message ------
struct alignas(4) ControlMessage
{
    U32 m_uType;         // e.g. 0x01 = CHANNEL_CREATE, 0x02 = CHANNEL_DESTROY
    U32 m_uChannelId;
    U32 m_uRingBytes;
    U32 m_uFlags;
    U8  m_arrReserved[16];
};

static_assert(sizeof(ControlMessage) == 32U, "ControlMessage must be 32 bytes");

// ---- Minimal anomaly alert payload (M-08 -> M-01) ------------------------
struct alignas(4) AnomalyAlert
{
    U64 m_uTimestampNs;
    U32 m_uScopeHash;
    U32 m_uSeverity;   // 0=low 1=medium 2=high 3=critical
    U8  m_arrDescription[32];
};

static_assert(sizeof(AnomalyAlert) == 48U, "AnomalyAlert must be 48 bytes");

// ---- Simple test helpers -------------------------------------------------

bool test_assert(bool aBCondition, const char* aSzLabel)
{
    printf("  [%s] %s\n", aBCondition ? "PASS" : "FAIL", aSzLabel);
    aBCondition ? ++g_iPassed : ++g_iFailed;
    return aBCondition;
}

// =========================================================================
// Test 1 - Bootstrap channel (ID 0) must be rejected
// The M-01<->M-03 bootstrap channel is special: it is created internally
// by M-01 during early init and never goes through ChannelFactory with ID 0.
// ID 0 is reserved as "no channel" in the capability system.
// =========================================================================
bool test_bootstrap_channel_id_rejected()
{
    ChannelFactory lFactory;
    auto lResult = lFactory.createChannel(CHAN_BOOTSTRAP, 4096U, "bootstrap");

    return test_assert(
        !lResult.has_value() && lResult.error().code() == ErrorCode::INVALID_ARGUMENT,
        "Channel ID 0 (bootstrap sentinel) is rejected by ChannelFactory"
    );
}

// =========================================================================
// Test 2 - Create all seven architecture channels and verify each is valid
// =========================================================================
bool test_all_architecture_channels_created()
{
    ChannelFactory lFactory;

    const struct { ChannelId id; const char* name; } kChannels[] = {
        { CHAN_ISOLATION_CMD, "m01-to-m02-isolation" },
        { CHAN_IPC_ENGINE,    "m03-ipc-engine"       },
        { CHAN_ANOMALY_ALERT, "m08-to-m01-anomaly"   },
        { CHAN_CHECKPOINT,    "m01-to-m04-checkpoint" },
        { CHAN_EBPF_METRICS,  "m09-to-m08-metrics"   },
        { CHAN_NUMA_TOPOLOGY, "m03-to-m16-numa"      },
    };

    bool lBAllValid = true;
    for (const auto& lKEntry : kChannels)
    {
        auto lResult = lFactory.createChannel(lKEntry.id, 4096U, lKEntry.name);
        if (!lResult.has_value() || !lResult.value().isValid())
        {
            printf("  [FAIL] Architecture channel %u (%s) failed to create\n",
                   lKEntry.id, lKEntry.name);
            ++g_iFailed;
            lBAllValid = false;
        }
        // Channels go out of scope here — destructor unmaps them correctly.
    }

    if (lBAllValid)
    {
        ++g_iPassed;
        printf("  [PASS] All 6 architecture channels created and released cleanly\n");
    }

    return lBAllValid;
}

// =========================================================================
// Test 3 - Write a 32-byte ControlMessage into ring memory and verify
//          a second mapping reads back identical bytes.
// =========================================================================
bool test_control_message_roundtrip_over_shared_memory()
{
    ChannelFactory lFactory;
    auto lResult = lFactory.createChannel(CHAN_IPC_ENGINE, 4096U, "ctrl-msg-test");
    if (!test_assert(lResult.has_value(), "channel created for ControlMessage roundtrip"))
        return false;

    Channel lChannel = std::move(lResult.value());

    // Build a CHANNEL_CREATE control message
    ControlMessage lMsg{};
    lMsg.m_uType       = 0x01U;   // CHANNEL_CREATE
    lMsg.m_uChannelId  = CHAN_ANOMALY_ALERT;
    lMsg.m_uRingBytes  = 65536U;
    lMsg.m_uFlags      = 0U;
    std::memset(lMsg.m_arrReserved, 0xAB, sizeof(lMsg.m_arrReserved));

    // Write directly into ring buffer area (bypassing RingBuffer class - raw
    // shared memory verification of Sprint 1 semantics)
    std::memcpy(lChannel.ringBuffer(), &lMsg, sizeof(lMsg));
    lChannel.control()->m_write.m_uWriteIndex.store(
        sizeof(lMsg), std::memory_order_release
    );

    // Fork so we exercise the actual shared mapping path
    const pid_t lIPid = ::fork();
    if (!test_assert(lIPid >= 0, "fork() succeeded for ControlMessage test"))
        return false;

    if (lIPid == 0)
    {
        auto lMap = lFactory.mapExistingChannel(
            CHAN_IPC_ENGINE, lChannel.borrowFd(), lChannel.mappedBytes()
        );
        if (!lMap.has_value()) { _exit(EXIT_FAILURE); }

        Channel lChild = std::move(lMap.value());

        ControlMessage lRead{};
        std::memcpy(&lRead, lChild.ringBuffer(), sizeof(lRead));

        const bool lBOk =
            lChild.control()->m_write.m_uWriteIndex.load(std::memory_order_acquire)
                == sizeof(lMsg)
            && lRead.m_uType      == 0x01U
            && lRead.m_uChannelId == CHAN_ANOMALY_ALERT
            && lRead.m_uRingBytes == 65536U
            && lRead.m_uFlags     == 0U
            && lRead.m_arrReserved[0] == 0xAB
            && lRead.m_arrReserved[15] == 0xAB;

        _exit(lBOk ? EXIT_SUCCESS : EXIT_FAILURE);
    }

    int lIStatus = 0;
    ::waitpid(lIPid, &lIStatus, 0);
    return test_assert(
        WIFEXITED(lIStatus) && WEXITSTATUS(lIStatus) == EXIT_SUCCESS,
        "ControlMessage (32 B) survives shared-memory roundtrip via fork()"
    );
}

// =========================================================================
// Test 4 - AnomalyAlert payload (48 bytes) M-08 -> M-01 via Channel 4
// =========================================================================
bool test_anomaly_alert_payload_roundtrip()
{
    ChannelFactory lFactory;
    auto lResult = lFactory.createChannel(CHAN_ANOMALY_ALERT, 4096U, "anomaly-alert");
    if (!test_assert(lResult.has_value(), "channel created for AnomalyAlert test"))
        return false;

    Channel lChannel = std::move(lResult.value());

    AnomalyAlert lAlert{};
    lAlert.m_uTimestampNs = 1743670000000000000ULL;  // fake ns timestamp
    lAlert.m_uScopeHash   = 0xDEADBEEFU;
    lAlert.m_uSeverity    = 3U;  // critical
    std::strncpy(
        reinterpret_cast<char*>(lAlert.m_arrDescription),
        "BRUTE_FORCE_AUTH_FAIL",
        sizeof(lAlert.m_arrDescription) - 1U
    );

    std::memcpy(lChannel.ringBuffer(), &lAlert, sizeof(lAlert));
    lChannel.control()->m_write.m_uWriteIndex.store(
        sizeof(lAlert), std::memory_order_release
    );

    const pid_t lIPid = ::fork();
    if (!test_assert(lIPid >= 0, "fork() succeeded for AnomalyAlert test"))
        return false;

    if (lIPid == 0)
    {
        auto lMap = lFactory.mapExistingChannel(
            CHAN_ANOMALY_ALERT, lChannel.borrowFd(), lChannel.mappedBytes()
        );
        if (!lMap.has_value()) { _exit(EXIT_FAILURE); }

        Channel lChild = std::move(lMap.value());
        AnomalyAlert lRead{};
        std::memcpy(&lRead, lChild.ringBuffer(), sizeof(lRead));

        const bool lBOk =
            lRead.m_uTimestampNs == 1743670000000000000ULL
            && lRead.m_uScopeHash  == 0xDEADBEEFU
            && lRead.m_uSeverity   == 3U
            && std::strncmp(
                   reinterpret_cast<const char*>(lRead.m_arrDescription),
                   "BRUTE_FORCE_AUTH_FAIL",
                   sizeof(lRead.m_arrDescription)
               ) == 0;

        _exit(lBOk ? EXIT_SUCCESS : EXIT_FAILURE);
    }

    int lIStatus = 0;
    ::waitpid(lIPid, &lIStatus, 0);
    return test_assert(
        WIFEXITED(lIStatus) && WEXITSTATUS(lIStatus) == EXIT_SUCCESS,
        "AnomalyAlert (48 B, severity=critical) survives Channel 4 shared-memory roundtrip"
    );
}

// =========================================================================
// Test 5 - Channel metadata matches what the factory was told to create
// =========================================================================
bool test_metadata_matches_requested_parameters()
{
    ChannelFactory lFactory;

    const struct { ChannelId id; U32 ringBytes; } kCases[] = {
        { 10U,  256U     },
        { 11U,  4096U    },
        { 12U,  65536U   },
        { 13U,  1048576U },  // 1 MiB
    };

    bool lBAllOk = true;
    for (const auto& lKCase : kCases)
    {
        auto lResult = lFactory.createChannel(lKCase.id, lKCase.ringBytes);
        if (!lResult.has_value())
        {
            printf("  [FAIL] createChannel(%u, %u) unexpectedly failed\n",
                   lKCase.id, lKCase.ringBytes);
            ++g_iFailed;
            lBAllOk = false;
            continue;
        }
        Channel lChannel = std::move(lResult.value());
        const ChannelControlBlock* lPCtrl = lChannel.control();

        const bool lBMetaOk =
            lPCtrl->m_meta.m_uChannelId    == lKCase.id
            && lPCtrl->m_meta.m_uControlBytes == static_cast<U32>(sizeof(ChannelControlBlock))
            && lPCtrl->m_meta.m_uRingBufferBytes == lKCase.ringBytes
            && lPCtrl->m_meta.m_uMappedBytes  == lChannel.mappedBytes()
            && (lChannel.mappedBytes() % static_cast<SizeT>(4096U)) == 0U;

        if (!lBMetaOk)
        {
            printf("  [FAIL] Metadata mismatch for channel %u ring=%u\n",
                   lKCase.id, lKCase.ringBytes);
            ++g_iFailed;
            lBAllOk = false;
        }
    }

    if (lBAllOk)
    {
        ++g_iPassed;
        printf("  [PASS] Metadata correct for all 4 ring-size variants\n");
    }
    return lBAllOk;
}

// =========================================================================
// Test 6 - Duplicate fd obtained via F_DUPFD_CLOEXEC maps to the same bytes
// This simulates what SCM_RIGHTS does: the OS creates a dup in the receiver,
// and that dup must map to the same shared memory.
// =========================================================================
bool test_dup_fd_maps_same_bytes()
{
    ChannelFactory lFactory;
    auto lResult = lFactory.createChannel(CHAN_EBPF_METRICS, 4096U, "dup-fd-test");
    if (!test_assert(lResult.has_value(), "channel created for dup-fd test"))
        return false;

    Channel lOriginal = std::move(lResult.value());

    // Write a sentinel pattern
    constexpr U64 kSentinel = 0xCAFEBABEDEADC0DEULL;
    std::memcpy(lOriginal.ringBuffer(), &kSentinel, sizeof(kSentinel));
    lOriginal.control()->m_write.m_uWriteIndex.store(sizeof(kSentinel), std::memory_order_release);

    // Duplicate the fd (SCM_RIGHTS simulation)
    const int lIDupFd = ::fcntl(lOriginal.borrowFd(), F_DUPFD_CLOEXEC, 0);
    if (!test_assert(lIDupFd >= 0, "fcntl(F_DUPFD_CLOEXEC) succeeded"))
        return false;

    auto lMapResult = lFactory.mapExistingChannel(
        CHAN_EBPF_METRICS, lIDupFd, lOriginal.mappedBytes()
    );
    ::close(lIDupFd);  // mapExistingChannel dups internally so we close ours

    if (!test_assert(lMapResult.has_value(), "mapExistingChannel via dup fd succeeded"))
        return false;

    Channel lDupChannel = std::move(lMapResult.value());

    U64 lUReadBack = 0U;
    std::memcpy(&lUReadBack, lDupChannel.ringBuffer(), sizeof(lUReadBack));

    const bool lBSentinelOk =
        lUReadBack == kSentinel
        && lDupChannel.control()->m_write.m_uWriteIndex.load(std::memory_order_acquire)
               == sizeof(kSentinel);

    return test_assert(lBSentinelOk,
        "Dup fd maps same shared bytes (SCM_RIGHTS simulation, sentinel 0xCAFEBABEDEADC0DE)");
}

// =========================================================================
// Test 7 - Move-assignment preserves valid state (complement to the
//          move-constructor test already in Sprint 1 acceptance suite)
// =========================================================================
bool test_move_assignment_preserves_state()
{
    ChannelFactory lFactory;
    auto lResult = lFactory.createChannel(CHAN_CHECKPOINT, 4096U, "move-assign-test");
    if (!test_assert(lResult.has_value(), "channel created for move-assignment test"))
        return false;

    Channel lA = std::move(lResult.value());
    const void* lPBaseA = lA.base();
    const int   lIFdA   = lA.borrowFd();

    Channel lB;  // default-constructed, invalid
    lB = std::move(lA);

    return test_assert(
        !lA.isValid()
        && lB.isValid()
        && lB.base()      == lPBaseA
        && lB.borrowFd()  == lIFdA,
        "Move-assignment: source invalidated, destination holds mapping"
    );
}

// =========================================================================
// Test 8 - Double reset is a no-op (idempotency)
// =========================================================================
bool test_double_reset_is_noop()
{
    ChannelFactory lFactory;
    auto lResult = lFactory.createChannel(CHAN_NUMA_TOPOLOGY, 256U, "double-reset");
    if (!test_assert(lResult.has_value(), "channel created for double-reset test"))
        return false;

    Channel lChannel = std::move(lResult.value());
    lChannel.reset();
    lChannel.reset();  // should not crash or double-unmap

    return test_assert(
        !lChannel.isValid() && lChannel.base() == nullptr,
        "Double reset() is idempotent and does not crash"
    );
}

// =========================================================================
// Test 9 - memfd name boundary: at-limit name succeeds, over-limit fails
//
// Linux enforces MFD_NAME_MAX_LEN = 249 bytes (NAME_MAX minus the "memfd:"
// prefix the kernel prepends internally).  Exactly 249 chars must succeed;
// 300 chars must fail with SYSCALL_FAILED (EINVAL from the kernel).
// =========================================================================
bool test_memfd_name_length_boundary()
{
    ChannelFactory lFactory;

    // 248 chars is the actual kernel limit (NAME_MAX=255 minus "memfd:" prefix=6 minus NUL=1)
    // Must succeed
    const std::string lAtLimit(248U, 'a');
    auto lOkResult = lFactory.createChannel(50U, 256U, lAtLimit);
    if (!test_assert(lOkResult.has_value(),
            "createChannel() succeeds with 248-char memfd name (at kernel limit)"))
        return false;

    // 249+ chars exceeds the limit - kernel returns EINVAL -> SYSCALL_FAILED
    const std::string lOverLimit(300U, 'x');
    auto lFailResult = lFactory.createChannel(51U, 256U, lOverLimit);
    return test_assert(
        !lFailResult.has_value()
        && lFailResult.error().code() == ErrorCode::SYSCALL_FAILED,
        "createChannel() returns SYSCALL_FAILED for 300-char memfd name (exceeds kernel limit)"
    );
}

// =========================================================================
// Test 10 - ringBuffer() pointer is exactly sizeof(ChannelControlBlock)
//           bytes past base()
// =========================================================================
bool test_ring_buffer_pointer_offset()
{
    ChannelFactory lFactory;
    auto lResult = lFactory.createChannel(51U, 256U, "offset-test");
    if (!test_assert(lResult.has_value(), "channel created for offset test"))
        return false;

    Channel lChannel = std::move(lResult.value());
    const auto* lPBase = static_cast<const std::byte*>(lChannel.base());
    const auto* lPRing = lChannel.ringBuffer();

    const std::ptrdiff_t lIOffset = lPRing - lPBase;
    return test_assert(
        static_cast<SizeT>(lIOffset) == sizeof(ChannelControlBlock),
        "ringBuffer() is exactly sizeof(ChannelControlBlock) bytes past base()"
    );
}

} // namespace

int main()
{
    printf("=============================================\n");
    printf("  Astra M-03 Sprint 1 - Extended Test Suite \n");
    printf("  (Real Astra data: channels, payloads, fds) \n");
    printf("=============================================\n\n");

    test_bootstrap_channel_id_rejected();
    test_all_architecture_channels_created();
    test_control_message_roundtrip_over_shared_memory();
    test_anomaly_alert_payload_roundtrip();
    test_metadata_matches_requested_parameters();
    test_dup_fd_maps_same_bytes();
    test_move_assignment_preserves_state();
    test_double_reset_is_noop();
    test_memfd_name_length_boundary();
    test_ring_buffer_pointer_offset();

    printf("\nSummary: %d passed, %d failed\n", g_iPassed, g_iFailed);
    return (g_iFailed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
