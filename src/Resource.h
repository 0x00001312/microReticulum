#pragma once

/// Resource transfer protocol — chunked, windowed data transfer over Links.
///
/// Matches Python Resource.py and Rust rns-protocol/resource.rs wire format.
/// Supports both sender (outbound) and receiver (inbound) roles.

#include "Bytes.h"
#include "Type.h"
#include "Cryptography/Hashes.h"
#include "Utilities/OS.h"

#include <memory>
#include <vector>
#include <cstdint>
#include <cassert>
#include <functional>

namespace RNS {

class Link;
class Packet;

// ---- Resource flags byte ----
struct ResourceFlags {
    bool encrypted = true;
    bool compressed = false;
    bool split = false;
    bool is_request = false;
    bool is_response = false;
    bool has_metadata = false;

    uint8_t to_byte() const {
        uint8_t b = 0;
        if (encrypted) b |= 0x01;
        if (compressed) b |= 0x02;
        if (split) b |= 0x04;
        if (is_request) b |= 0x08;
        if (is_response) b |= 0x10;
        if (has_metadata) b |= 0x20;
        return b;
    }
    static ResourceFlags from_byte(uint8_t b) {
        return { (b & 0x01) != 0, (b & 0x02) != 0, (b & 0x04) != 0,
                 (b & 0x08) != 0, (b & 0x10) != 0, (b & 0x20) != 0 };
    }
};

// ---- Resource Advertisement ----
// Msgpack map: {t,d,n,h,r,o,i,l,q,f,m}
struct ResourceAdvertisement {
    size_t transfer_size = 0;       // encrypted blob size
    size_t data_size = 0;           // original (uncompressed) size
    size_t num_parts = 0;
    uint8_t resource_hash[32] = {};
    uint8_t random_hash[4] = {};
    uint8_t original_hash[32] = {};
    size_t segment_index = 1;
    size_t total_segments = 1;
    Bytes request_id;               // nil if not a request/response
    ResourceFlags flags;
    Bytes hashmap;                  // concatenated 4-byte map hashes

    Bytes pack() const;
    static bool unpack(const Bytes& data, ResourceAdvertisement& adv);

    /// Extract map hashes as 4-byte arrays.
    std::vector<std::array<uint8_t, 4>> get_map_hashes() const;
};

// ---- Map hash computation ----
/// SHA256(data || random_hash)[:MAPHASH_LEN]
void get_map_hash(const uint8_t* data, size_t data_len,
                  const uint8_t* random_hash, size_t random_len,
                  uint8_t out[4]);

/// SHA256(data || random_hash) full 32 bytes
Bytes compute_resource_hash(const Bytes& data, const uint8_t random_hash[4]);

/// SHA256(data || resource_hash) — expected proof
Bytes compute_expected_proof(const Bytes& data, const uint8_t resource_hash[32]);

// ---- Resource status ----
enum class ResourceStatus : uint8_t {
    NONE = 0,
    QUEUED = 1,
    ADVERTISED = 2,
    TRANSFERRING = 3,
    AWAITING_PROOF = 4,
    ASSEMBLING = 5,
    COMPLETE = 6,
    FAILED = 7,
    CORRUPT = 8,
};

// ---- Outbound Resource (sender) ----
class OutboundResource {
public:
    OutboundResource() = default;

    /// Initialize from raw data. Encrypts, chunks, computes hashmap.
    /// auto_compress is accepted for API parity but ignored — see Resource.cpp.
    bool init(const Bytes& plaintext, Link& link, bool auto_compress = false);

    /// Get the advertisement to send.
    ResourceAdvertisement get_advertisement() const;

    /// Get part data by index (raw encrypted chunk).
    Bytes get_part(size_t index) const;

    /// Handle a request from receiver (list of wanted map hashes).
    /// Returns indices of parts to send.
    std::vector<size_t> handle_request(const Bytes& request_data);

    /// Handle proof from receiver.
    bool handle_proof(const Bytes& proof_data);

    /// Number of parts.
    size_t num_parts() const { return _parts.size(); }
    bool is_complete() const { return _status == ResourceStatus::COMPLETE; }

    ResourceStatus status() const { return _status; }
    const uint8_t* resource_hash() const { return _resource_hash; }
    const uint8_t* random_hash() const { return _random_hash; }

    // ── Retransmission (see Link::__watchdog_job()) ─────────────────────
    // Nothing about this class times itself out on its own -- there's no
    // thread/timer here, just state. Link is responsible for noticing no
    // RESOURCE_REQ/RESOURCE_PRF has arrived in too long and re-sending the
    // advertisement, bounded by these counters.
    double last_activity_at() const { return _last_activity_at; }
    void mark_activity() { _last_activity_at = Utilities::OS::time(); }
    int retries() const { return _retries; }
    void increment_retries() { _retries++; }
    void mark_failed() { _status = ResourceStatus::FAILED; }

private:
    std::vector<Bytes> _parts;          // encrypted chunks
    Bytes _hashmap;                     // concatenated 4-byte map hashes
    uint8_t _resource_hash[32] = {};
    uint8_t _random_hash[4] = {};
    uint8_t _original_hash[32] = {};
    size_t _transfer_size = 0;
    size_t _data_size = 0;
    ResourceFlags _flags;
    Bytes _expected_proof;
    ResourceStatus _status = ResourceStatus::NONE;
    double _last_activity_at = 0.0;
    int _retries = 0;
};

// ---- Inbound Resource (receiver) ----
class InboundResource {
public:
    InboundResource() = default;

    /// Create from a received advertisement.
    bool init(const ResourceAdvertisement& adv, Link& link);

    /// Receive a part (raw data from Resource context packet).
    /// Returns true if part was accepted (map hash matched).
    bool receive_part(const Bytes& data);

    /// Check if all parts have been received.
    bool is_complete() const;

    /// Assemble the resource: concatenate parts → decrypt → decompress.
    /// Returns the original plaintext data.
    Bytes assemble(Link& link);

    /// Generate the proof to send back to sender.
    Bytes generate_proof() const;

    /// Builds a request for the next batch (up to _window) of still-missing
    /// parts, in order. Idempotent when nothing new has arrived since the
    /// last call -- recomputes from scratch each time rather than tracking
    /// a separate watermark, so calling it again (e.g. on a retry timeout,
    /// see Link::__watchdog_job()) naturally re-requests the same batch if
    /// nothing arrived, and naturally advances once parts do. Returns an
    /// empty Bytes once nothing is missing (complete, or assembly pending).
    Bytes next_request();

    /// True once enough parts have arrived since the last request was sent
    /// to justify asking for the next batch (event-driven advance, as
    /// opposed to next_request()'s timeout-driven retry of the same batch
    /// -- see Link's RESOURCE packet handler).
    bool should_request_more() const { return _received_since_request >= _window && !is_complete(); }

    size_t num_parts() const { return _total_parts; }
    size_t received_count() const { return _received; }
    const uint8_t* resource_hash() const { return _resource_hash; }

    ResourceStatus status() const { return _status; }

    // ── Retransmission (see Link::__watchdog_job()) ─────────────────────
    double last_request_at() const { return _last_request_at; }
    int retries() const { return _retries; }
    void increment_retries() { _retries++; }
    void mark_failed() { _status = ResourceStatus::FAILED; }

private:
    std::vector<Bytes> _parts;          // received chunks (indexed by part number)
    std::vector<std::array<uint8_t, 4>> _map_hashes;
    uint8_t _resource_hash[32] = {};
    uint8_t _random_hash[4] = {};
    uint8_t _original_hash[32] = {};
    size_t _transfer_size = 0;
    size_t _data_size = 0;
    size_t _total_parts = 0;
    size_t _received = 0;
    ResourceFlags _flags;
    ResourceStatus _status = ResourceStatus::NONE;
    size_t _window = 4;                 // current receive window
    size_t _received_since_request = 0;
    double _last_request_at = 0.0;
    int _retries = 0;
};

// ---- Legacy Resource class (compatibility wrapper) ----
// Preserves existing API used by Link.cpp
class ResourceData;

class Resource {
public:
    class Callbacks {
    public:
        using concluded = void(*)(const Resource& resource);
        using progress = void(*)(const Resource& resource);
    public:
        concluded _concluded = nullptr;
        progress _progress = nullptr;
    };

    Resource(Type::NoneConstructor none) {}
    Resource(const Resource& resource) : _object(resource._object) {}
    Resource(const Bytes& data, const Link& link, const Bytes& request_id, bool is_response, double timeout = 0.0);
    Resource(const Bytes& data, const Link& link, bool advertise = true, bool auto_compress = false,
             Callbacks::concluded callback = nullptr, Callbacks::progress progress_callback = nullptr,
             double timeout = 0.0, int segment_index = 1, const Bytes& original_hash = {Type::NONE},
             const Bytes& request_id = {Type::NONE}, bool is_response = false);
    virtual ~Resource() {}

    Resource& operator=(const Resource& resource) { _object = resource._object; return *this; }
    operator bool() const { return _object.get() != nullptr; }
    bool operator<(const Resource& resource) const { return _object.get() < resource._object.get(); }

    void validate_proof(const Bytes& proof_data);
    void cancel();
    float get_progress() const;
    void set_concluded_callback(Callbacks::concluded callback);
    void set_progress_callback(Callbacks::progress callback);
    std::string toString() const;

    const Bytes& hash() const;
    const Bytes& request_id() const;
    const Bytes& data() const;
    const Type::Resource::status status() const;
    const size_t size() const;
    const size_t total_size() const;

protected:
    std::shared_ptr<ResourceData> _object;
};

} // namespace RNS
