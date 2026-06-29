// LXMF message format — MsgPack wire codec
// Shared between microReticulum (library) and Ratdeck (firmware).
// Matches Python LXMF LXMessage.py and Rust lxmf-core message.rs wire format.
#include "LXMFMessage.h"
#include <cstring>

static void mpPackFloat64(std::vector<uint8_t>& buf, double val) {
    buf.push_back(0xCB);
    uint64_t bits;
    memcpy(&bits, &val, 8);
    for (int i = 7; i >= 0; i--) {
        buf.push_back((bits >> (i * 8)) & 0xFF);
    }
}

static void mpPackString(std::vector<uint8_t>& buf, const std::string& str) {
    size_t len = str.size();
    if (len < 32) {
        buf.push_back(0xA0 | (uint8_t)len);
    } else if (len < 256) {
        buf.push_back(0xD9);
        buf.push_back((uint8_t)len);
    } else {
        buf.push_back(0xDA);
        buf.push_back((len >> 8) & 0xFF);
        buf.push_back(len & 0xFF);
    }
    buf.insert(buf.end(), str.begin(), str.end());
}

// MsgPack bin format — Python LXMF expects title/content as bytes, not str
static void mpPackBin(std::vector<uint8_t>& buf, const std::string& str) {
    size_t len = str.size();
    if (len < 256) {
        buf.push_back(0xC4);
        buf.push_back((uint8_t)len);
    } else {
        buf.push_back(0xC5);
        buf.push_back((len >> 8) & 0xFF);
        buf.push_back(len & 0xFF);
    }
    buf.insert(buf.end(), str.begin(), str.end());
}

static bool mpReadFloat64(const uint8_t* data, size_t len, size_t& pos, double& val) {
    if (pos >= len || data[pos] != 0xCB) return false;
    pos++;
    if (pos + 8 > len) return false;
    uint64_t bits = 0;
    for (int i = 0; i < 8; i++) { bits = (bits << 8) | data[pos++]; }
    memcpy(&val, &bits, 8);
    return true;
}

static bool mpReadString(const uint8_t* data, size_t len, size_t& pos, std::string& str) {
    if (pos >= len) return false;
    uint8_t b = data[pos];
    size_t slen = 0;
    // MsgPack str formats
    if ((b & 0xE0) == 0xA0) { slen = b & 0x1F; pos++; }
    else if (b == 0xD9) { pos++; if (pos >= len) return false; slen = data[pos++]; }
    else if (b == 0xDA) { pos++; if (pos + 2 > len) return false; slen = ((size_t)data[pos] << 8) | data[pos + 1]; pos += 2; }
    // MsgPack bin formats (Python LXMF sends title/content as bin)
    else if (b == 0xC4) { pos++; if (pos >= len) return false; slen = data[pos++]; }
    else if (b == 0xC5) { pos++; if (pos + 2 > len) return false; slen = ((size_t)data[pos] << 8) | data[pos + 1]; pos += 2; }
    else return false;
    if (pos + slen > len) return false;
    str.assign((const char*)&data[pos], slen);
    pos += slen;
    return true;
}

static bool mpSkipValue(const uint8_t* data, size_t len, size_t& pos) {
    if (pos >= len) return false;
    uint8_t b = data[pos];
    if ((b & 0xE0) == 0xA0) { pos += 1 + (b & 0x1F); return pos <= len; }
    if ((b & 0xF0) == 0x80) { size_t c = b & 0x0F; pos++; for (size_t i = 0; i < c * 2; i++) { if (!mpSkipValue(data, len, pos)) return false; } return true; }
    if ((b & 0xF0) == 0x90) { size_t c = b & 0x0F; pos++; for (size_t i = 0; i < c; i++) { if (!mpSkipValue(data, len, pos)) return false; } return true; }
    if (b == 0xCB) { pos += 9; return pos <= len; }
    if (b == 0xD9) { if (pos + 2 > len) return false; size_t s = data[pos + 1]; pos += 2 + s; return pos <= len; }
    if (b == 0xDA) { if (pos + 3 > len) return false; size_t s = ((size_t)data[pos+1] << 8) | data[pos+2]; pos += 3 + s; return pos <= len; }
    if ((b & 0x80) == 0x00 || (b & 0xE0) == 0xE0 || b == 0xC0 || b == 0xC2 || b == 0xC3) { pos++; return true; }
    if (b == 0xCC || b == 0xD0) { pos += 2; return pos <= len; }
    if (b == 0xCD || b == 0xD1) { pos += 3; return pos <= len; }
    if (b == 0xCE || b == 0xD2 || b == 0xCA) { pos += 5; return pos <= len; }
    if (b == 0xCF || b == 0xD3) { pos += 9; return pos <= len; }
    if (b == 0xC4) { if (pos + 2 > len) return false; pos += 2 + data[pos+1]; return pos <= len; }
    if (b == 0xC5) { if (pos + 3 > len) return false; pos += 3 + (((size_t)data[pos+1] << 8) | data[pos+2]); return pos <= len; }
    return false;
}

std::vector<uint8_t> LXMFMessage::packContent(double timestamp, const std::string& content, const std::string& title) {
    std::vector<uint8_t> buf;
    buf.reserve(32 + content.size() + title.size());
    buf.push_back(0x94);
    mpPackFloat64(buf, timestamp);
    mpPackBin(buf, title);      // LXMF spec: [ts, title, content, fields] — must be bin, not str
    mpPackBin(buf, content);
    buf.push_back(0x80);
    return buf;
}

std::vector<uint8_t> LXMFMessage::appendStampToPacked(const std::vector<uint8_t>& packed4, const RNS::Bytes& stamp) {
    // `packed4` is a packContent()-style buffer: [0x94][ts][title][content][fields].
    // Only the leading array-count byte changes (0x94 -> 0x95); everything
    // else is reused byte-for-byte, then the stamp is appended as a
    // msgpack bin value -- exactly what re-encoding [ts,title,content,
    // fields,stamp] as a 5-element array would produce, without needing a
    // general-purpose msgpack array re-encoder.
    std::vector<uint8_t> wireContent;
    wireContent.reserve(packed4.size() + 2 + stamp.size());
    wireContent.push_back(0x95);
    wireContent.insert(wireContent.end(), packed4.begin() + 1, packed4.end());
    mpPackBin(wireContent, std::string((const char*)stamp.data(), stamp.size()));
    return wireContent;
}

std::vector<uint8_t> LXMFMessage::canonicalHashInput(const uint8_t* destAndSrc32, const uint8_t* content, size_t fieldsEnd) {
    // Reconstructs the canonical 4-element form ([ts,title,content,fields],
    // no stamp) that the hash/signature were computed over on the sending
    // side, regardless of whether a 5th (stamp) element followed on the
    // wire -- see appendStampToPacked() for why only the leading
    // array-count byte ever differs.
    std::vector<uint8_t> hashInput;
    hashInput.reserve(32 + fieldsEnd);
    hashInput.insert(hashInput.end(), destAndSrc32, destAndSrc32 + 32);
    hashInput.push_back(0x94);
    hashInput.insert(hashInput.end(), content + 1, content + fieldsEnd);
    return hashInput;
}

std::vector<uint8_t> LXMFMessage::packFull(const RNS::Identity& signingIdentity) {
    std::vector<uint8_t> packed = packContent(timestamp, content, title);
    if (sourceHash.size() < 16 || destHash.size() < 16) return {};

    // Sign: dest_hash || source_hash || packed_content || message_hash (LXMF spec)
    std::vector<uint8_t> hashed_part;
    hashed_part.reserve(32 + packed.size());
    hashed_part.insert(hashed_part.end(), destHash.data(), destHash.data() + 16);
    hashed_part.insert(hashed_part.end(), sourceHash.data(), sourceHash.data() + 16);
    hashed_part.insert(hashed_part.end(), packed.begin(), packed.end());

    RNS::Bytes hashedBytes(hashed_part.data(), hashed_part.size());
    RNS::Bytes msgHash = RNS::Identity::full_hash(hashedBytes);

    // Store messageId = SHA256(dest + src + payload), matching Python LXMessage.pack()
    messageId = msgHash;

    std::vector<uint8_t> signed_part;
    signed_part.reserve(hashed_part.size() + msgHash.size());
    signed_part.insert(signed_part.end(), hashed_part.begin(), hashed_part.end());
    signed_part.insert(signed_part.end(), msgHash.data(), msgHash.data() + msgHash.size());

    RNS::Bytes signableBytes(signed_part.data(), signed_part.size());
    RNS::Bytes sig = signingIdentity.sign(signableBytes);
    if (sig.size() < 64) return {};

    // If a stamp is attached, the wire payload's array grows from 4 to 5
    // elements ([ts,title,content,fields,stamp]) -- but the stamp is never
    // part of what's hashed/signed above (it can't be: a stamp is computed
    // *from* messageId, which is itself derived from the hash, so it has
    // to sit outside the signed envelope).
    std::vector<uint8_t> wireContent = stamp.size() > 0 ? appendStampToPacked(packed, stamp) : packed;

    // Wire (opportunistic): [src_hash:16][signature:64][packed_content]
    // dest_hash is carried by the RNS packet header, not the LXMF payload
    std::vector<uint8_t> payload;
    payload.reserve(16 + 64 + wireContent.size());
    payload.insert(payload.end(), sourceHash.data(), sourceHash.data() + 16);
    payload.insert(payload.end(), sig.data(), sig.data() + 64);
    payload.insert(payload.end(), wireContent.begin(), wireContent.end());
    return payload;
}

bool LXMFMessage::unpackFull(const uint8_t* data, size_t len, LXMFMessage& msg) {
    // Wire: [dest_hash:16][src_hash:16][signature:64][packed_content]
    if (len < 97) return false;  // 16+16+64+1 minimum
    msg.destHash = RNS::Bytes(data, 16);
    msg.sourceHash = RNS::Bytes(data + 16, 16);
    msg.signature = RNS::Bytes(data + 32, 64);

    const uint8_t* content = data + 96;
    size_t contentLen = len - 96;
    size_t pos = 0;

    if (pos >= contentLen) return false;
    uint8_t arrHeader = content[pos];
    if ((arrHeader & 0xF0) != 0x90) return false;
    size_t arrLen = arrHeader & 0x0F;
    if (arrLen < 3) return false;
    pos++;

    // LXMF spec: [timestamp, title, content, fields, stamp?]
    if (!mpReadFloat64(content, contentLen, pos, msg.timestamp)) return false;
    if (!mpReadString(content, contentLen, pos, msg.title)) return false;
    if (!mpReadString(content, contentLen, pos, msg.content)) return false;
    if (arrLen >= 4 && pos < contentLen) { mpSkipValue(content, contentLen, pos); }

    // Everything up to here (minus the leading array-count byte) is the
    // canonical 4-element form the hash/signature were computed over on
    // the sending side -- record where it ends before optionally reading
    // a 5th (stamp) element, which sits *outside* the hashed envelope.
    size_t fieldsEnd = pos;

    if (arrLen >= 5) {
        std::string stampStr;
        if (mpReadString(content, contentLen, pos, stampStr)) {
            msg.stamp = RNS::Bytes((const uint8_t*)stampStr.data(), stampStr.size());
        }
    }

    // messageId = SHA256(dest + src + canonical_4elem_packed_content),
    // matching Python/Rust.
    std::vector<uint8_t> hashInput = canonicalHashInput(data, content, fieldsEnd);
    RNS::Bytes hashable(hashInput.data(), hashInput.size());
    msg.messageId = RNS::Identity::full_hash(hashable);
    msg.incoming = true;
    msg.status = LXMFStatus::DELIVERED;
    return true;
}

const char* LXMFMessage::statusStr() const {
    switch (status) {
        case LXMFStatus::DRAFT: return "draft";
        case LXMFStatus::QUEUED: return "queued";
        case LXMFStatus::STAMPING: return "stamping";
        case LXMFStatus::SENDING: return "sending";
        case LXMFStatus::SENT: return "sent";
        case LXMFStatus::DELIVERED: return "delivered";
        case LXMFStatus::FAILED: return "failed";
        default: return "?";
    }
}
