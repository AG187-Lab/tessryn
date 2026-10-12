/* Provisional Tessryn ABI v1.0. Apache-2.0. Host contract evidence only. */
#ifndef TESSRYN_ABI_V1_NATIVE_H
#define TESSRYN_ABI_V1_NATIVE_H
#include <stddef.h>
#include <stdint.h>

/* Struct layout is not a byte codec. Encode/decode every scalar explicitly in
 * little-endian order. Never cast an untrusted byte buffer to these types.
 * All reserved and flags fields are zero. Resolve capability authority after
 * structural validation. No object field contains a host pointer. */
#define TESSRYN_ABI_MAJOR UINT16_C(1)
#define TESSRYN_ABI_MINOR UINT16_C(0)
#define TESSRYN_ABI_FEATURE_MASK UINT64_C(0)

#define TESSRYN_ABI_KIND_NEGOTIATION UINT16_C(1)
#define TESSRYN_ABI_KIND_REGION UINT16_C(2)
#define TESSRYN_ABI_KIND_SUBMISSION UINT16_C(3)
#define TESSRYN_ABI_KIND_COMPLETION UINT16_C(4)

#define TESSRYN_ABI_OP_COPY UINT32_C(1)
#define TESSRYN_ABI_OP_EXECUTE UINT32_C(2)
#define TESSRYN_ABI_OP_TRANSFER UINT32_C(3)
#define TESSRYN_ABI_OP_CANCEL UINT32_C(4)
#define TESSRYN_ABI_OP_FENCE UINT32_C(5)
#define TESSRYN_ABI_OP_RELEASE UINT32_C(6)

#define TESSRYN_ABI_STATUS_OK UINT32_C(0)
#define TESSRYN_ABI_STATUS_INVALID_DESCRIPTOR UINT32_C(1)
#define TESSRYN_ABI_STATUS_UNSUPPORTED_VERSION UINT32_C(2)
#define TESSRYN_ABI_STATUS_INVALID_AUTHORITY UINT32_C(3)
#define TESSRYN_ABI_STATUS_STALE_HANDLE UINT32_C(4)
#define TESSRYN_ABI_STATUS_OUT_OF_BOUNDS UINT32_C(5)
#define TESSRYN_ABI_STATUS_INSUFFICIENT_CAPACITY UINT32_C(6)
#define TESSRYN_ABI_STATUS_ADMISSION_REJECTED UINT32_C(7)
#define TESSRYN_ABI_STATUS_DEADLINE_EXPIRED UINT32_C(8)
#define TESSRYN_ABI_STATUS_DEVICE_FAULT UINT32_C(9)
#define TESSRYN_ABI_STATUS_CANCELLED UINT32_C(10)
#define TESSRYN_ABI_STATUS_STALE_EPOCH UINT32_C(11)
#define TESSRYN_ABI_STATUS_INCOMPATIBLE_FORMAT UINT32_C(12)
#define TESSRYN_ABI_STATUS_PARTIAL_STREAM UINT32_C(13)
#define TESSRYN_ABI_STATUS_BACKPRESSURE UINT32_C(14)
#define TESSRYN_ABI_STATUS_PEER_FAULT UINT32_C(15)

#define TESSRYN_ABI_MILESTONE_NONE UINT32_C(0)
#define TESSRYN_ABI_MILESTONE_SUBMISSION_ACCEPTED UINT32_C(1)
#define TESSRYN_ABI_MILESTONE_EXECUTION_COMPLETED UINT32_C(2)
#define TESSRYN_ABI_MILESTONE_CANCELLATION_RECEIVED UINT32_C(3)
#define TESSRYN_ABI_MILESTONE_LAUNCHES_STOPPED UINT32_C(4)
#define TESSRYN_ABI_MILESTONE_OUTPUT_FENCED UINT32_C(5)
#define TESSRYN_ABI_MILESTONE_MEMORY_RECLAIMED UINT32_C(6)
#define TESSRYN_ABI_MILESTONE_FAULT_REPORTED UINT32_C(7)

typedef struct {
    uint16_t major;
    uint16_t minor;
    uint32_t size;
    uint16_t kind;
    uint16_t flags;
    uint32_t reserved;
} tessryn_abi_header;

_Static_assert(sizeof(tessryn_abi_header) == 16, "Header size");
_Static_assert(_Alignof(tessryn_abi_header) == 4, "Header alignment");
_Static_assert(offsetof(tessryn_abi_header, major) == 0, "Header.major offset");
_Static_assert(offsetof(tessryn_abi_header, minor) == 2, "Header.minor offset");
_Static_assert(offsetof(tessryn_abi_header, size) == 4, "Header.size offset");
_Static_assert(offsetof(tessryn_abi_header, kind) == 8, "Header.kind offset");
_Static_assert(offsetof(tessryn_abi_header, flags) == 10, "Header.flags offset");
_Static_assert(offsetof(tessryn_abi_header, reserved) == 12, "Header.reserved offset");

typedef struct {
    uint32_t slot;
    uint32_t generation;
    uint64_t domain;
} tessryn_abi_capability_ref;

_Static_assert(sizeof(tessryn_abi_capability_ref) == 16, "CapabilityRef size");
_Static_assert(_Alignof(tessryn_abi_capability_ref) == 8, "CapabilityRef alignment");
_Static_assert(offsetof(tessryn_abi_capability_ref, slot) == 0, "CapabilityRef.slot offset");
_Static_assert(offsetof(tessryn_abi_capability_ref, generation) == 4, "CapabilityRef.generation offset");
_Static_assert(offsetof(tessryn_abi_capability_ref, domain) == 8, "CapabilityRef.domain offset");

typedef struct {
    tessryn_abi_header header;
    uint16_t min_major;
    uint16_t min_minor;
    uint16_t max_major;
    uint16_t max_minor;
    uint64_t required_features;
    uint64_t supported_features;
    uint64_t domain;
} tessryn_abi_negotiation;

_Static_assert(sizeof(tessryn_abi_negotiation) == 48, "Negotiation size");
_Static_assert(_Alignof(tessryn_abi_negotiation) == 8, "Negotiation alignment");
_Static_assert(offsetof(tessryn_abi_negotiation, header) == 0, "Negotiation.header offset");
_Static_assert(offsetof(tessryn_abi_negotiation, min_major) == 16, "Negotiation.min_major offset");
_Static_assert(offsetof(tessryn_abi_negotiation, min_minor) == 18, "Negotiation.min_minor offset");
_Static_assert(offsetof(tessryn_abi_negotiation, max_major) == 20, "Negotiation.max_major offset");
_Static_assert(offsetof(tessryn_abi_negotiation, max_minor) == 22, "Negotiation.max_minor offset");
_Static_assert(offsetof(tessryn_abi_negotiation, required_features) == 24, "Negotiation.required_features offset");
_Static_assert(offsetof(tessryn_abi_negotiation, supported_features) == 32, "Negotiation.supported_features offset");
_Static_assert(offsetof(tessryn_abi_negotiation, domain) == 40, "Negotiation.domain offset");

typedef struct {
    tessryn_abi_header header;
    tessryn_abi_capability_ref capability;
    uint64_t owner_task;
    uint64_t length;
    uint64_t budget_id;
    uint64_t placement_epoch;
} tessryn_abi_region;

_Static_assert(sizeof(tessryn_abi_region) == 64, "Region size");
_Static_assert(_Alignof(tessryn_abi_region) == 8, "Region alignment");
_Static_assert(offsetof(tessryn_abi_region, header) == 0, "Region.header offset");
_Static_assert(offsetof(tessryn_abi_region, capability) == 16, "Region.capability offset");
_Static_assert(offsetof(tessryn_abi_region, owner_task) == 32, "Region.owner_task offset");
_Static_assert(offsetof(tessryn_abi_region, length) == 40, "Region.length offset");
_Static_assert(offsetof(tessryn_abi_region, budget_id) == 48, "Region.budget_id offset");
_Static_assert(offsetof(tessryn_abi_region, placement_epoch) == 56, "Region.placement_epoch offset");

typedef struct {
    tessryn_abi_header header;
    uint64_t request_id;
    uint64_t task_id;
    uint64_t placement_epoch;
    uint32_t operation;
    uint32_t reserved;
    tessryn_abi_capability_ref region;
    uint64_t offset;
    uint64_t length;
    tessryn_abi_capability_ref completion;
    tessryn_abi_capability_ref dependency;
    uint64_t budget_id;
    uint64_t deadline_ns;
} tessryn_abi_submission;

_Static_assert(sizeof(tessryn_abi_submission) == 128, "Submission size");
_Static_assert(_Alignof(tessryn_abi_submission) == 8, "Submission alignment");
_Static_assert(offsetof(tessryn_abi_submission, header) == 0, "Submission.header offset");
_Static_assert(offsetof(tessryn_abi_submission, request_id) == 16, "Submission.request_id offset");
_Static_assert(offsetof(tessryn_abi_submission, task_id) == 24, "Submission.task_id offset");
_Static_assert(offsetof(tessryn_abi_submission, placement_epoch) == 32, "Submission.placement_epoch offset");
_Static_assert(offsetof(tessryn_abi_submission, operation) == 40, "Submission.operation offset");
_Static_assert(offsetof(tessryn_abi_submission, reserved) == 44, "Submission.reserved offset");
_Static_assert(offsetof(tessryn_abi_submission, region) == 48, "Submission.region offset");
_Static_assert(offsetof(tessryn_abi_submission, offset) == 64, "Submission.offset offset");
_Static_assert(offsetof(tessryn_abi_submission, length) == 72, "Submission.length offset");
_Static_assert(offsetof(tessryn_abi_submission, completion) == 80, "Submission.completion offset");
_Static_assert(offsetof(tessryn_abi_submission, dependency) == 96, "Submission.dependency offset");
_Static_assert(offsetof(tessryn_abi_submission, budget_id) == 112, "Submission.budget_id offset");
_Static_assert(offsetof(tessryn_abi_submission, deadline_ns) == 120, "Submission.deadline_ns offset");

typedef struct {
    tessryn_abi_header header;
    uint64_t request_id;
    uint64_t sequence;
    uint64_t placement_epoch;
    uint32_t status;
    uint32_t milestone;
    tessryn_abi_capability_ref region;
    uint64_t produced_length;
    uint32_t ownership_generation;
    uint32_t reserved;
} tessryn_abi_completion;

_Static_assert(sizeof(tessryn_abi_completion) == 80, "Completion size");
_Static_assert(_Alignof(tessryn_abi_completion) == 8, "Completion alignment");
_Static_assert(offsetof(tessryn_abi_completion, header) == 0, "Completion.header offset");
_Static_assert(offsetof(tessryn_abi_completion, request_id) == 16, "Completion.request_id offset");
_Static_assert(offsetof(tessryn_abi_completion, sequence) == 24, "Completion.sequence offset");
_Static_assert(offsetof(tessryn_abi_completion, placement_epoch) == 32, "Completion.placement_epoch offset");
_Static_assert(offsetof(tessryn_abi_completion, status) == 40, "Completion.status offset");
_Static_assert(offsetof(tessryn_abi_completion, milestone) == 44, "Completion.milestone offset");
_Static_assert(offsetof(tessryn_abi_completion, region) == 48, "Completion.region offset");
_Static_assert(offsetof(tessryn_abi_completion, produced_length) == 64, "Completion.produced_length offset");
_Static_assert(offsetof(tessryn_abi_completion, ownership_generation) == 72, "Completion.ownership_generation offset");
_Static_assert(offsetof(tessryn_abi_completion, reserved) == 76, "Completion.reserved offset");

/* Helpers accept only already-bounds-checked scalar spans. */
static inline uint16_t tessryn_abi_read_le16(const uint8_t b[2]) {
    return (uint16_t)((uint16_t)b[0] | ((uint16_t)b[1] << 8));
}
static inline uint32_t tessryn_abi_read_le32(const uint8_t b[4]) {
    return (uint32_t)b[0] | ((uint32_t)b[1] << 8) | ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24);
}
static inline uint64_t tessryn_abi_read_le64(const uint8_t b[8]) {
    return (uint64_t)tessryn_abi_read_le32(b) | ((uint64_t)tessryn_abi_read_le32(b + 4) << 32);
}
static inline void tessryn_abi_write_le16(uint8_t b[2], uint16_t v) {
    b[0] = (uint8_t)v; b[1] = (uint8_t)(v >> 8);
}
static inline void tessryn_abi_write_le32(uint8_t b[4], uint32_t v) {
    for (unsigned i = 0; i < 4; ++i) b[i] = (uint8_t)(v >> (8 * i));
}
static inline void tessryn_abi_write_le64(uint8_t b[8], uint64_t v) {
    for (unsigned i = 0; i < 8; ++i) b[i] = (uint8_t)(v >> (8 * i));
}
#endif /* TESSRYN_ABI_V1_NATIVE_H */
