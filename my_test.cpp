// ============================================================================
// my_test.cpp — hands-on demo of the M-03 ring buffer
//
// Compile:
//   g++ -std=c++23 -O0 -g -I include \
//       src/ipc/ChannelFactory.cpp src/ipc/RingBuffer.cpp \
//       my_test.cpp -o my_test -lpthread
//
// Run:
//   ./my_test
// ============================================================================

#include <astra/ipc/ChannelFactory.hpp>
#include <astra/ipc/RingBuffer.hpp>

#include <cstdio>
#include <cstring>
#include <thread>
#include <chrono>

using namespace astra;
using namespace astra::ipc;

// ── The message you want to send ────────────────────────────────────────────
// You can put ANYTHING here — a struct, a string, raw bytes.
// This is a simple example using a plain struct.

struct MyMessage
{
    int   id;
    float value;
    char  text[32];
};

// ── Helper: print what came back ─────────────────────────────────────────────
void printMessage(const MyMessage& msg)
{
    printf("  id    = %d\n",  msg.id);
    printf("  value = %.2f\n", msg.value);
    printf("  text  = \"%s\"\n\n", msg.text);
}

// ============================================================================
// Test 1 — Write a message and read it back in the same process
// ============================================================================
void test_simple_write_and_read()
{
    printf("=== Test 1: simple write + read ===\n\n");

    // 1. Create a channel with a 4096-byte ring
    ChannelFactory factory;
    auto result = factory.createChannel(1, 4096, "my-channel");
    if (!result.has_value())
    {
        printf("ERROR: createChannel failed\n");
        return;
    }

    Channel channel = std::move(result.value());

    // 2. Wrap it in a RingBuffer
    RingBuffer ring(channel.control(), channel.ringBuffer(), channel.ringBufferBytes());

    // 3. Build a message — change anything you like here
    MyMessage outMsg{};
    outMsg.id    = 42;
    outMsg.value = 3.14f;
    std::strncpy(outMsg.text, "hello from producer", sizeof(outMsg.text) - 1);

    printf("Writing message:\n");
    printMessage(outMsg);

    // 4. Write it into the ring
    auto writeResult = ring.write(&outMsg, sizeof(outMsg));
    if (!writeResult.has_value())
    {
        printf("ERROR: write failed: %s\n",
               std::string(writeResult.error().message()).c_str());
        return;
    }

    printf("Ring state after write:\n");
    printf("  write_idx = %llu\n", (unsigned long long)ring.writeIndex());
    printf("  read_idx  = %llu\n", (unsigned long long)ring.readIndex());
    printf("  used bytes = %u  (8 header + %zu payload)\n\n",
           ring.usedBytes(), sizeof(outMsg));

    // 5. Read it back
    MyMessage inMsg{};
    auto readResult = ring.read(&inMsg, sizeof(inMsg));
    if (!readResult.has_value())
    {
        printf("ERROR: read failed: %s\n",
               std::string(readResult.error().message()).c_str());
        return;
    }

    printf("Read back message (%u bytes):\n", readResult.value());
    printMessage(inMsg);

    printf("Ring state after read:\n");
    printf("  isEmpty = %s\n\n", ring.isEmpty() ? "true" : "false");
}

// ============================================================================
// Test 2 — Write multiple messages and drain them in order
// ============================================================================
void test_multiple_messages()
{
    printf("=== Test 2: multiple messages, FIFO order ===\n\n");

    ChannelFactory factory;
    auto result = factory.createChannel(2, 4096, "multi-channel");
    if (!result.has_value()) { printf("ERROR\n"); return; }

    Channel channel = std::move(result.value());
    RingBuffer ring(channel.control(), channel.ringBuffer(), channel.ringBufferBytes());

    // Write 3 messages
    for (int i = 1; i <= 3; ++i)
    {
        MyMessage msg{};
        msg.id    = i * 10;
        msg.value = i * 1.5f;
        std::snprintf(msg.text, sizeof(msg.text), "message number %d", i);

        (void)ring.write(&msg, sizeof(msg));
        printf("Wrote: id=%d  text=\"%s\"\n", msg.id, msg.text);
    }

    printf("\nReading them back:\n");

    // Read them all back — they must come in the same order
    for (int i = 0; i < 3; ++i)
    {
        MyMessage msg{};
        auto rd = ring.read(&msg, sizeof(msg));
        if (rd.has_value())
            printf("  Read: id=%d  text=\"%s\"\n", msg.id, msg.text);
        else
            printf("  ERROR reading message %d\n", i);
    }

    printf("\n");
}

// ============================================================================
// Test 3 — Producer thread writes, consumer thread reads via blocking readWait
// ============================================================================
void test_blocking_read_across_threads()
{
    printf("=== Test 3: producer thread + consumer thread (blocking) ===\n\n");

    ChannelFactory factory;
    auto result = factory.createChannel(3, 4096, "threaded-channel");
    if (!result.has_value()) { printf("ERROR\n"); return; }

    Channel channel = std::move(result.value());
    RingBuffer ring(channel.control(), channel.ringBuffer(), channel.ringBufferBytes());

    // Consumer thread — blocks until the producer writes something
    std::thread consumer([&]() {
        printf("  [consumer] waiting for message...\n");

        MyMessage msg{};
        auto rd = ring.readWait(&msg, sizeof(msg));
        if (rd.has_value())
            printf("  [consumer] received: id=%d  text=\"%s\"\n\n", msg.id, msg.text);
        else
            printf("  [consumer] ERROR: %s\n",
                   std::string(rd.error().message()).c_str());
    });

    // Producer — sleeps 1 second then writes
    std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    printf("  [producer] writing message after 1 second delay...\n");

    MyMessage msg{};
    msg.id    = 99;
    msg.value = 9.99f;
    std::strncpy(msg.text, "woke you up!", sizeof(msg.text) - 1);

    (void)ring.writeNotify(&msg, sizeof(msg));

    consumer.join();
}

// ============================================================================
// Test 4 — What happens when the ring is full (backpressure)
// ============================================================================
void test_ring_full_backpressure()
{
    printf("=== Test 4: ring full → RESOURCE_EXHAUSTED ===\n\n");

    // Small 256-byte ring so it fills up quickly
    // Each MyMessage write costs: 8 (header) + sizeof(MyMessage) bytes
    ChannelFactory factory;
    auto result = factory.createChannel(4, 256, "small-channel");
    if (!result.has_value()) { printf("ERROR\n"); return; }

    Channel channel = std::move(result.value());
    RingBuffer ring(channel.control(), channel.ringBuffer(), channel.ringBufferBytes());

    MyMessage msg{};
    msg.id = 1;
    std::strncpy(msg.text, "filling the ring", sizeof(msg.text) - 1);

    int written = 0;
    while (true)
    {
        auto wr = ring.write(&msg, sizeof(msg));
        if (!wr.has_value())
        {
            printf("  Ring full after %d messages.\n", written);
            printf("  Error: %s\n\n", std::string(wr.error().message()).c_str());
            break;
        }
        ++written;
    }

    printf("  Ring: used=%u bytes, free=%u bytes\n\n",
           ring.usedBytes(), ring.freeBytes());
}

// ============================================================================
// main
// ============================================================================
int main()
{
    printf("\n");
    test_simple_write_and_read();
    test_multiple_messages();
    test_blocking_read_across_threads();
    test_ring_full_backpressure();

    printf("All tests done.\n");
    return 0;
}
