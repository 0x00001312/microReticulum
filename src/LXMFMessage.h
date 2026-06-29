#pragma once

#include "Bytes.h"
#include "Identity.h"
#include <string>
#include <vector>
#include <cstdint>

// STAMPING is appended after FAILED, not inserted alongside QUEUED/SENDING
// where it conceptually belongs -- MessageStore persists this enum as a
// raw (int) cast (see MessageStore.cpp's saveMessage/loadConversation), so
// renumbering an existing value would silently corrupt status on disk for
// any message saved by a firmware before this one. New values only ever
// get added at the end.
enum class LXMFStatus : uint8_t {
    DRAFT = 0, QUEUED, SENDING, SENT, DELIVERED, FAILED, STAMPING
};

struct LXMFMessage {
    RNS::Bytes sourceHash;
    RNS::Bytes destHash;
    double timestamp = 0;
    std::string content;
    std::string title;
    RNS::Bytes signature;

    // Anti-spam proof-of-work stamp (see LXStamper.{h,cpp}). Empty = none
    // attached. Set this *before* calling packFull() if the recipient (or
    // propagation node) requires one -- packFull() appends it as the wire
    // format's optional 5th payload element when non-empty, exactly as the
    // Python reference does, but never generates it itself (that's a
    // potentially slow background operation owned by the caller).
    RNS::Bytes stamp;

    LXMFStatus status = LXMFStatus::DRAFT;
    bool incoming = false;
    bool read = false;
    int retries = 0;
    unsigned long lastRetryMs = 0;
    uint32_t savedCounter = 0;
    uint32_t receiveCounter = 0;  // Monotonic receive order (used by Ratcom)
    RNS::Bytes messageId;

    static std::vector<uint8_t> packContent(double timestamp, const std::string& content, const std::string& title);
    std::vector<uint8_t> packFull(const RNS::Identity& signingIdentity);
    static bool unpackFull(const uint8_t* data, size_t len, LXMFMessage& msg);
    const char* statusStr() const;

    // Exposed for testing independent of signing/Identity -- see
    // native_test cross-checks under docs/lxmf-stamps.md. Not part of the
    // stable internal API otherwise; packFull()/unpackFull() are.
    static std::vector<uint8_t> appendStampToPacked(const std::vector<uint8_t>& packed4, const RNS::Bytes& stamp);
    static std::vector<uint8_t> canonicalHashInput(const uint8_t* destAndSrc32, const uint8_t* content, size_t fieldsEnd);
};
