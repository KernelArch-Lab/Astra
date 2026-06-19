# Sprint 13 Completion — Latency Histogram

**Branch:** `feature/m03-sprint4-5`
**Date:** 2026-06-19
**Status:** DONE — 15/15 IPC sprint tests passing

## What was built

Two new classes for write-to-read latency measurement.

### `LatencyHistogram`

Lock-free 64-bucket power-of-two histogram. Bucket `i` accumulates samples whose latency falls in `[2^(i-1), 2^i)` nanoseconds (bucket 0 catches 0 ns).

| Method | Description |
|--------|-------------|
| `record(latencyNs)` | Three `fetch_add(relaxed)` — bucket counter, total samples, total ns |
| `snapshot()` | Returns `Snapshot{counts[64], totalSamples, totalNs}` via relaxed loads |
| `reset()` | Zeroes all counters |
| `Snapshot::minBucket()` | First non-empty bucket |
| `Snapshot::maxBucket()` | Last non-empty bucket |
| `Snapshot::medianBucket()` | Bucket containing the 50th-percentile sample |
| `print()` | Compact text histogram to stdout |

Bucket assignment: `i = 63 - __builtin_clzll(latency_ns)` (floor log2), clamped to `[0, 63]`.

### `LatencyTracker`

Wraps a `RingBuffer`. Embeds the write timestamp as an invisible 8-byte prefix in the ring payload:

```
[MessageHeader 8B | m_uPayloadBytes = sizeof(U64) + appLen]
[WriteTimestampNs  U64]
[App Payload       N bytes]
```

| Method | Description |
|--------|-------------|
| `write(data, len)` | Timestamps with `CLOCK_MONOTONIC_RAW`, prepends to payload, calls `ring.write()` |
| `read(buf, bufLen)` | Reads, strips timestamp, records `nowNs - writeNs` in histogram, returns app payload |
| `histogram()` | Access to the internal `LatencyHistogram` |

**Constraint:** max tracked payload = 4096 bytes (stack-allocated combined buffer). LatencyTracker is a monitoring-only API, not a hot-path replacement for `RingBuffer::write/read`.

**Transparency:** callers of `write(data, N)` / `read(buf, N)` see exactly N bytes. The 8-byte timestamp is invisible.

## What changed

| File | Change |
|------|--------|
| `include/astra/ipc/LatencyTracker.hpp` | New — `LatencyHistogram` + `LatencyTracker` |
| `src/ipc/LatencyTracker.cpp` | New — implementations |
| `src/ipc/CMakeLists.txt` | Added `LatencyTracker.cpp` to `astra_ipc` |
| `tests/ipc/test_sprint13_latency.cpp` | New — 4 test cases |
| `tests/ipc/CMakeLists.txt` | Added `test_ipc_sprint13` / `Sprint13IpcLatencyTest` |

## Test cases

- **T1 `T1_WriteThenRead_OneSampleRecorded`** — one write/read pair; histogram shows `totalSamples=1`, exactly one non-empty bucket, `totalNs < 1 s`.
- **T2 `T2_MultipleRoundTrips_SampleCountMatches`** — 8 write/read pairs; `totalSamples == 8`.
- **T3 `T3_PayloadTransparency`** — payload bytes written and read are identical byte-for-byte.
- **T4 `T4_HistogramConsistency_AndReset`** — after 5 samples, `totalSamples == sum(bucket counts)`; `minBucket/maxBucket/medianBucket` return valid values; `reset()` zeroes everything and `minBucket()` returns -1.

## Up next: S14 — Throughput Benchmark

Add a `ThroughputBenchmark` that drives `RingBuffer::write/read` in a tight loop for N iterations, measures wall-clock throughput (messages/sec and bytes/sec), and reports via `LatencyHistogram`.
