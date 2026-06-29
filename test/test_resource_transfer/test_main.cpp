/// Resource transfer tests — validates advertisement pack/unpack, map hashes,
/// chunking, reassembly, and proof computation.

#include <unity.h>
#include "Identity.h"
#include "Resource.h"
#include "Link.h"
#include "Compression/BZ2.h"
#include "Cryptography/Hashes.h"

#include <string.h>
#include <stdio.h>
#include <cmath>
#include <vector>

static void printHex(const char* label, const uint8_t* data, size_t len) {
    printf("  %s = ", label);
    for (size_t i = 0; i < len; i++) printf("%02x", data[i]);
    printf("\n");
}

// ── Test 1: ResourceAdvertisement pack/unpack roundtrip ─────────────

void testResourceAdvertisementPackUnpack() {
    RNS::ResourceAdvertisement adv;
    adv.transfer_size = 1024;
    adv.data_size = 900;
    adv.num_parts = 4;
    memset(adv.resource_hash, 0xAA, 32);
    memset(adv.random_hash, 0xBB, 4);
    memset(adv.original_hash, 0xCC, 32);
    adv.segment_index = 1;
    adv.total_segments = 1;
    adv.flags.encrypted = true;
    adv.flags.compressed = false;

    // Build a fake hashmap (4 hashes × 4 bytes = 16 bytes)
    uint8_t hm[16];
    for (int i = 0; i < 16; i++) hm[i] = i;
    adv.hashmap = RNS::Bytes(hm, 16);

    // Pack
    RNS::Bytes packed = adv.pack();
    TEST_ASSERT_TRUE(packed.size() > 0);

    printf("\n=== RESOURCE_ADV_PACK ===\n");
    printHex("packed", packed.data(), packed.size());

    // Unpack
    RNS::ResourceAdvertisement unpacked;
    bool ok = RNS::ResourceAdvertisement::unpack(packed, unpacked);
    TEST_ASSERT_TRUE(ok);
    TEST_ASSERT_EQUAL(1024, unpacked.transfer_size);
    TEST_ASSERT_EQUAL(900, unpacked.data_size);
    TEST_ASSERT_EQUAL(4, unpacked.num_parts);
    TEST_ASSERT_EQUAL_MEMORY(adv.resource_hash, unpacked.resource_hash, 32);
    TEST_ASSERT_EQUAL_MEMORY(adv.random_hash, unpacked.random_hash, 4);
    TEST_ASSERT_EQUAL(1, unpacked.segment_index);
    TEST_ASSERT_EQUAL(1, unpacked.total_segments);
    TEST_ASSERT_TRUE(unpacked.flags.encrypted);
    TEST_ASSERT_FALSE(unpacked.flags.compressed);
    TEST_ASSERT_EQUAL(16, unpacked.hashmap.size());
}

// ── Test 2: Map hash computation matches Python/Rust ────────────────

void testMapHashComputation() {
    // Known test: SHA256("test_data" + "\xBB\xBB\xBB\xBB")[:4]
    const char* str = "test_data";
    uint8_t random_hash[] = {0xBB, 0xBB, 0xBB, 0xBB};
    uint8_t mh[4];

    RNS::get_map_hash((const uint8_t*)str, 9, random_hash, 4, mh);

    // Verify it's deterministic
    uint8_t mh2[4];
    RNS::get_map_hash((const uint8_t*)str, 9, random_hash, 4, mh2);
    TEST_ASSERT_EQUAL_MEMORY(mh, mh2, 4);

    printf("\n=== MAP_HASH ===\n");
    printHex("hash", mh, 4);

    // Verify by manual SHA256 computation
    RNS::Bytes input((const uint8_t*)str, 9);
    input.append(random_hash, 4);
    RNS::Bytes expected = RNS::Identity::full_hash(input);
    TEST_ASSERT_EQUAL_MEMORY(expected.data(), mh, 4);
}

// ── Test 3: Resource hash computation ───────────────────────────────

void testResourceHashComputation() {
    RNS::Bytes data("Hello resource world!");
    uint8_t rh[4] = {0x11, 0x22, 0x33, 0x44};

    RNS::Bytes hash = RNS::compute_resource_hash(data, rh);
    TEST_ASSERT_EQUAL(32, hash.size());

    // Verify deterministic
    RNS::Bytes hash2 = RNS::compute_resource_hash(data, rh);
    TEST_ASSERT_EQUAL_MEMORY(hash.data(), hash2.data(), 32);

    printf("\n=== RESOURCE_HASH ===\n");
    printHex("hash", hash.data(), 32);
}

// ── Test 4: Expected proof computation ──────────────────────────────

void testExpectedProof() {
    RNS::Bytes data("Resource data for proof");
    uint8_t rh[32];
    memset(rh, 0xDD, 32);

    RNS::Bytes proof = RNS::compute_expected_proof(data, rh);
    TEST_ASSERT_EQUAL(32, proof.size());

    // Verify: SHA256(data || resource_hash)
    RNS::Bytes input(data.data(), data.size());
    input.append(rh, 32);
    RNS::Bytes expected = RNS::Identity::full_hash(input);
    TEST_ASSERT_EQUAL_MEMORY(expected.data(), proof.data(), 32);
}

// ── Test 5: ResourceAdvertisement get_map_hashes ────────────────────

void testGetMapHashes() {
    RNS::ResourceAdvertisement adv;
    uint8_t hm[] = {0x01, 0x02, 0x03, 0x04,
                     0x05, 0x06, 0x07, 0x08,
                     0x09, 0x0A, 0x0B, 0x0C};
    adv.hashmap = RNS::Bytes(hm, 12);

    auto hashes = adv.get_map_hashes();
    TEST_ASSERT_EQUAL(3, hashes.size());
    TEST_ASSERT_EQUAL_UINT8(0x01, hashes[0][0]);
    TEST_ASSERT_EQUAL_UINT8(0x05, hashes[1][0]);
    TEST_ASSERT_EQUAL_UINT8(0x09, hashes[2][0]);
}

// ── Test 6: ResourceFlags byte roundtrip ────────────────────────────

void testResourceFlags() {
    RNS::ResourceFlags f;
    f.encrypted = true;
    f.compressed = true;
    f.split = false;
    f.is_request = true;
    f.is_response = false;
    f.has_metadata = true;

    uint8_t b = f.to_byte();
    // encrypted=0x01, compressed=0x02, is_request=0x08, has_metadata=0x20
    TEST_ASSERT_EQUAL_UINT8(0x01 | 0x02 | 0x08 | 0x20, b);

    RNS::ResourceFlags f2 = RNS::ResourceFlags::from_byte(b);
    TEST_ASSERT_TRUE(f2.encrypted);
    TEST_ASSERT_TRUE(f2.compressed);
    TEST_ASSERT_FALSE(f2.split);
    TEST_ASSERT_TRUE(f2.is_request);
    TEST_ASSERT_FALSE(f2.is_response);
    TEST_ASSERT_TRUE(f2.has_metadata);
}

// ── Test 7: Advertisement with nil request_id ───────────────────────

void testAdvertisementNilRequestId() {
    RNS::ResourceAdvertisement adv;
    adv.transfer_size = 256;
    adv.data_size = 200;
    adv.num_parts = 1;
    memset(adv.resource_hash, 0x11, 32);
    memset(adv.random_hash, 0x22, 4);
    memset(adv.original_hash, 0x11, 32);
    adv.hashmap = RNS::Bytes((uint8_t*)"\x01\x02\x03\x04", 4);

    // Pack with nil request_id (default)
    RNS::Bytes packed = adv.pack();

    RNS::ResourceAdvertisement unpacked;
    TEST_ASSERT_TRUE(RNS::ResourceAdvertisement::unpack(packed, unpacked));
    TEST_ASSERT_EQUAL(0, unpacked.request_id.size());
    TEST_ASSERT_EQUAL(256, unpacked.transfer_size);
}

// ── Test 8: Advertisement with request_id ───────────────────────────

void testAdvertisementWithRequestId() {
    RNS::ResourceAdvertisement adv;
    adv.transfer_size = 512;
    adv.data_size = 400;
    adv.num_parts = 2;
    memset(adv.resource_hash, 0x33, 32);
    memset(adv.random_hash, 0x44, 4);
    memset(adv.original_hash, 0x33, 32);
    adv.request_id = RNS::Bytes((uint8_t*)"\xDE\xAD\xBE\xEF", 4);
    adv.hashmap = RNS::Bytes((uint8_t*)"\x01\x02\x03\x04\x05\x06\x07\x08", 8);

    RNS::Bytes packed = adv.pack();

    RNS::ResourceAdvertisement unpacked;
    TEST_ASSERT_TRUE(RNS::ResourceAdvertisement::unpack(packed, unpacked));
    TEST_ASSERT_EQUAL(4, unpacked.request_id.size());
    TEST_ASSERT_EQUAL_MEMORY("\xDE\xAD\xBE\xEF", unpacked.request_id.data(), 4);
}

// ── Regression: InboundResource must complete transfers larger than one
// request window (Type::Resource::WINDOW == 4) ──────────────────────────
//
// Before the windowed-retry fix, InboundResource only ever sent ONE request
// (for the first WINDOW parts) right after accepting the advertisement, and
// nothing ever asked for the remaining parts. Any resource needing more
// than WINDOW parts could therefore never become complete -- this directly
// reproduces and verifies the fix for that, end to end at the protocol
// level (no real Link/encryption needed: receive_part() matches purely by
// map hash, and init()/this test never call assemble(), which is the only
// place link decryption happens).
void testInboundResourceCompletesAcrossMultipleWindows() {
    const size_t kNumParts = 10;  // > Type::Resource::WINDOW (4) on purpose
    TEST_ASSERT_TRUE(kNumParts > RNS::Type::Resource::WINDOW);

    uint8_t random_hash[4] = {0xAA, 0xBB, 0xCC, 0xDD};
    std::vector<RNS::Bytes> chunks;
    RNS::Bytes hashmap;
    for (size_t i = 0; i < kNumParts; i++) {
        uint8_t data[16];
        memset(data, (uint8_t)(0x10 + i), sizeof(data));
        RNS::Bytes chunk(data, sizeof(data));
        chunks.push_back(chunk);

        uint8_t mh[4];
        RNS::get_map_hash(chunk.data(), chunk.size(), random_hash, 4, mh);
        hashmap.append(mh, 4);
    }

    RNS::ResourceAdvertisement adv;
    adv.transfer_size = kNumParts * 16;
    adv.data_size = adv.transfer_size;
    adv.num_parts = kNumParts;
    memset(adv.resource_hash, 0x55, 32);
    memcpy(adv.random_hash, random_hash, 4);
    memset(adv.original_hash, 0x55, 32);
    adv.hashmap = hashmap;

    RNS::Link noneLink({RNS::Type::NONE});  // init() never dereferences this
    RNS::InboundResource inbound;
    TEST_ASSERT_TRUE(inbound.init(adv, noneLink));
    TEST_ASSERT_FALSE(inbound.is_complete());

    int rounds = 0;
    while (!inbound.is_complete()) {
        RNS::Bytes req = inbound.next_request();
        TEST_ASSERT_TRUE(req.size() > 0);
        rounds++;
        TEST_ASSERT_TRUE(rounds <= 10);  // safety net against an infinite loop bug

        // Parse [exhausted(1)][?last_map_hash(4)][resource_hash(32)][wanted(N*4)]
        // -- mirrors OutboundResource::handle_request()'s own parse.
        size_t pos = 0;
        uint8_t exhausted = req.data()[pos++];
        if (exhausted == 0xFF) pos += 4;
        TEST_ASSERT_TRUE(pos + 32 <= req.size());
        TEST_ASSERT_EQUAL_MEMORY(adv.resource_hash, req.data() + pos, 32);
        pos += 32;

        size_t requested_in_round = 0;
        while (pos + 4 <= req.size()) {
            uint8_t wanted[4];
            memcpy(wanted, req.data() + pos, 4);
            pos += 4;
            requested_in_round++;

            bool matched = false;
            for (size_t i = 0; i < kNumParts; i++) {
                uint8_t mh[4];
                RNS::get_map_hash(chunks[i].data(), chunks[i].size(), random_hash, 4, mh);
                if (memcmp(mh, wanted, 4) == 0) {
                    matched = true;
                    TEST_ASSERT_TRUE(inbound.receive_part(chunks[i]));
                    break;
                }
            }
            TEST_ASSERT_TRUE(matched);
        }
        TEST_ASSERT_TRUE(requested_in_round <= RNS::Type::Resource::WINDOW);
    }

    // 10 parts at a window of 4 must take more than one round (4 + 4 + 2) --
    // the exact bug: a single-round implementation would have given up here.
    TEST_ASSERT_TRUE(rounds >= 3);
    TEST_ASSERT_EQUAL(kNumParts, inbound.received_count());
    TEST_ASSERT_TRUE(inbound.is_complete());
    TEST_ASSERT_EQUAL(0, inbound.next_request().size());  // nothing left to ask for
}

// ── Test 9: bz2 compress/decompress roundtrip ───────────────────────

void testBz2CompressDecompress() {
    // Create compressible data (repeated pattern)
    std::string repeated(1000, 'A');
    RNS::Bytes data((const uint8_t*)repeated.data(), repeated.size());

    RNS::Bytes compressed = RNS::Compression::bz2_compress(data);
    TEST_ASSERT_TRUE(compressed.size() > 0);
    TEST_ASSERT_TRUE(compressed.size() < data.size());  // Should compress well

    printf("\n=== BZ2_COMPRESS ===\n");
    printf("  original: %d bytes, compressed: %d bytes\n", (int)data.size(), (int)compressed.size());

    RNS::Bytes decompressed = RNS::Compression::bz2_decompress(compressed);
    TEST_ASSERT_EQUAL(data.size(), decompressed.size());
    TEST_ASSERT_EQUAL_MEMORY(data.data(), decompressed.data(), data.size());
}

// ── Test 10: try_compress only compresses if beneficial ─────────────

void testTryCompress() {
    // Highly compressible data
    std::string big(2000, 'X');
    RNS::Bytes compressible((const uint8_t*)big.data(), big.size());
    auto result = RNS::Compression::try_compress(compressible);
    TEST_ASSERT_TRUE(result.compressed);
    TEST_ASSERT_TRUE(result.data.size() < compressible.size());

    // Small random-like data (may not compress)
    uint8_t random_data[50];
    for (int i = 0; i < 50; i++) random_data[i] = (uint8_t)(i * 37 + 13);
    RNS::Bytes small_data(random_data, 50);
    auto result2 = RNS::Compression::try_compress(small_data);
    // Either compressed or not — both are valid
    TEST_ASSERT_TRUE(result2.data.size() > 0);
}

// ── Test 11: bz2 output matches Python/Rust format ──────────────────

void testBz2CrossPlatformFormat() {
    // bz2 compressed data always starts with "BZh" magic bytes
    std::string test_data = "Hello from C++ bz2 test!";
    RNS::Bytes data((const uint8_t*)test_data.data(), test_data.size());

    // Need larger data for compression to be beneficial
    RNS::Bytes big_data;
    for (int i = 0; i < 50; i++) big_data.append(data.data(), data.size());

    RNS::Bytes compressed = RNS::Compression::bz2_compress(big_data);
    TEST_ASSERT_TRUE(compressed.size() >= 3);

    // BZ2 magic: "BZh" (0x42, 0x5A, 0x68)
    TEST_ASSERT_EQUAL_UINT8(0x42, compressed.data()[0]);  // 'B'
    TEST_ASSERT_EQUAL_UINT8(0x5A, compressed.data()[1]);  // 'Z'
    TEST_ASSERT_EQUAL_UINT8(0x68, compressed.data()[2]);  // 'h'

    printf("\n=== BZ2_CROSS_PLATFORM ===\n");
    printf("  original: %d bytes, compressed: %d bytes\n", (int)big_data.size(), (int)compressed.size());
    printf("  magic: %c%c%c (BZh)\n", compressed.data()[0], compressed.data()[1], compressed.data()[2]);

    // Verify roundtrip
    RNS::Bytes decompressed = RNS::Compression::bz2_decompress(compressed);
    TEST_ASSERT_EQUAL(big_data.size(), decompressed.size());
    TEST_ASSERT_EQUAL_MEMORY(big_data.data(), decompressed.data(), big_data.size());
}

// ── Runner ──────────────────────────────────────────────────────────

void setUp() {}
void tearDown() {}

int main(int argc, char **argv) {
    UNITY_BEGIN();
    RUN_TEST(testResourceAdvertisementPackUnpack);
    RUN_TEST(testMapHashComputation);
    RUN_TEST(testResourceHashComputation);
    RUN_TEST(testExpectedProof);
    RUN_TEST(testGetMapHashes);
    RUN_TEST(testResourceFlags);
    RUN_TEST(testAdvertisementNilRequestId);
    RUN_TEST(testAdvertisementWithRequestId);
    RUN_TEST(testInboundResourceCompletesAcrossMultipleWindows);
    RUN_TEST(testBz2CompressDecompress);
    RUN_TEST(testTryCompress);
    RUN_TEST(testBz2CrossPlatformFormat);
    return UNITY_END();
}
