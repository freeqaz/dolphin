/*
 * MiloTrace_mtr_format.h — VENDORED COPY of milo-trace's mtr_format.h (W7).
 *
 * Source of truth: milo-trace/milo_trace/trace_format/mtr_format.h (task F1).
 * Byte-for-byte vendored so the Dolphin W7 interpreter hook (MiloTrace.cpp)
 * serializes the IDENTICAL packed layout the Python codec (codec.py) reads.
 * Do NOT edit here — re-vendor from the milo-trace tree if the format changes
 * (FROZEN per schema.md §C2; only additive section types may appear).
 *
 * ---------------------------------------------------------------------------
 *
 * mtr_format.h — packed C struct mirror of the milo-trace (.mtr) record format.
 *
 * This header is the SHARED contract between the Python codec (codec.py) and the
 * in-emulator C++ trace emitters (xenia/src/xenia/cpu/milo_trace.cc, and the
 * future Dolphin hook). Both sides serialize/parse the identical byte layout.
 *
 * Role in the DAG: task F1 (mtr_format.h + Python codec round-trip).
 * Frozen contract: trace_format/schema.md (task C2). Do not change a field's
 * type/offset after C2 — add a new section type instead (additive evolution).
 *
 * Endianness: framing fields are LITTLE-endian (host); captured guest memory
 * blobs in MEM_NODE/WRITES payloads are BIG-endian guest-native byte-exact. The
 * file header declares this so a reader on either endianness is unambiguous.
 * Register scalars (gpr/fpr-u64/cr/xer/ctr/lr/msr) are written in the framing
 * endianness (LE); an fpr u64 carries the guest's RAW doubleword bit pattern.
 *
 * ===========================================================================
 * ON-WIRE TLV LAYOUT (authoritative sketch — schema.md §3 is the frozen spec;
 * F1 implements the actual packed structs to match this byte-for-byte).
 * ===========================================================================
 *
 *   FILE := mtr_file_header_t  RECORD*
 *
 *   RECORD := mtr_header_t  SECTION*  mtr_footer_t
 *
 *   SECTION := mtr_section_t (type,flags,length)  payload[length]
 *
 *   Section payloads by type id (mtr_section_type_t):
 *     2 REGS_IN     : mtr_regs_t                              (full reg file, entry)
 *     3 REGS_OUT    : mtr_regs_t                              (full reg file, exit)
 *     4 STACK       : mtr_stack_hdr_t  data[hi-lo]            (Tier A, BE blob)
 *     5 MEM_NODE    : mtr_mem_node_hdr_t  data[len]           (Tier B node, BE blob)
 *     6 WRITES      : u32 count; { mtr_write_entry_t  data[len] } *count   (mem_out)
 *     7 EDGES       : u32 count; mtr_edge_entry_t *count      (Tier B ptr graph)
 *     8 GEKKO_EXT   : mtr_gekko_ext_t                         (fpr_ps1[]/gqr[], F6)
 *     9 CALLS       : u32 count; <CallEdge, schema.md §3.5> *count   (call oracle)
 *    10 ACCESS_LOG  : u32 count; mtr_access_entry_t *count    (Tier C, opt)
 *    11 NOTE        : u32 len; utf8[len]                      (diagnostic, non-auth)
 *    12..31         : RESERVED (e.g. VMX_IN/VMX_OUT for VMX128 v2)
 *
 *   The fixed RecordHeader is mtr_header_t (NOT itself a TLV section). A reader
 *   walks: file header -> per record: mtr_header_t, then section_count TLV
 *   sections, then mtr_footer_t (crc32 over [magic..last section], magic2='mtre').
 *   Unknown section types MUST be skipped via their length (forward-compat, §8).
 *
 * F1 STATUS: IMPLEMENTED. The packed structs below are the exact byte layout the
 * Python codec (codec.py) reads/writes via `struct` format strings. Every struct
 * is pack(1); the codec's MTR_*_FMT comments cite the matching `struct` format so
 * the two stay in lockstep. sizeof() values are asserted at the bottom via
 * MTR_STATIC_ASSERT and mirrored in codec.py's round-trip test.
 */

#ifndef MILO_TRACE_MTR_FORMAT_H
#define MILO_TRACE_MTR_FORMAT_H

#include <stdint.h>

/* Compile-time sizeof check so the packed layout can never silently drift from
 * codec.py's struct format strings. C++ (the xenia/dolphin emitters) uses the
 * static_assert keyword; C11 uses _Static_assert; older C gets a typedef trick. */
#if defined(__cplusplus)
#  define MTR_STATIC_ASSERT(cond, msg) static_assert(cond, msg)
#elif defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
#  define MTR_STATIC_ASSERT(cond, msg) _Static_assert(cond, msg)
#else
#  define MTR_CONCAT_(a, b) a##b
#  define MTR_CONCAT(a, b) MTR_CONCAT_(a, b)
#  define MTR_STATIC_ASSERT(cond, msg) \
       typedef char MTR_CONCAT(mtr_static_assert_, __LINE__)[(cond) ? 1 : -1]
#endif

/* Mirror of milo_trace.MTR_SCHEMA_VERSION. Keep these two in sync. */
#define MTR_SCHEMA_VERSION 1u

/* Per-RECORD header magic: 'M','T','R','\0' (LE-read as a u32). schema.md §3.2. */
#define MTR_MAGIC 0x0052544Du

/* Per-record footer trailing magic: 'm','t','r','e' (LE-read as a u32). */
#define MTR_MAGIC2 0x6572746Du

/* FILE-level header magic: 'M','T','R','F' (LE-read as a u32). schema.md §3.3. */
#define MTR_FILE_MAGIC 0x4652544Du

/* arch tags (mtr_header_t.arch / file header arch). schema.md §3.2. */
typedef enum {
    MTR_ARCH_GEKKO = 1, /* Wii Gekko/Broadway PPC32-BE (ppc-gekko) */
    MTR_ARCH_XENON = 2, /* Xbox 360 Xenon in PPC32 mode (ppc-xenon) */
} mtr_arch_t;

/* framing_endian values for the file header. Framing ints are LE (host); the
 * captured guest memory blobs are always BE guest-native regardless. */
typedef enum {
    MTR_FRAMING_LE = 0, /* little-endian framing (the only value emitted in v1) */
    MTR_FRAMING_BE = 1, /* reserved (a BE-host emitter would set this) */
} mtr_framing_endian_t;

/* TLV section type tags. Additive only — never repurpose an existing value.
 * FROZEN by schema.md §3.2: EDGES (the Tier-B pointer graph) and CALLS (the
 * outbound call oracle) are DISTINCT ids — they were conflated in the pre-freeze
 * stub. Ids 12..31 are reserved for future additive sections (e.g. VMX128). */
typedef enum {
    MTR_SEC_RECORD_HEADER = 1,  /* per-record header (func_va, symbol, flags) */
    MTR_SEC_REGS_IN       = 2,  /* full register file at entry  (regs_in)  */
    MTR_SEC_REGS_OUT      = 3,  /* full register file at exit   (regs_out) */
    MTR_SEC_STACK         = 4,  /* Tier A stack window          (mem_in)   */
    MTR_SEC_MEM_NODE      = 5,  /* Tier B pointer-chase node    (mem_in)   */
    MTR_SEC_WRITES        = 6,  /* memory write delta           (mem_out)  */
    MTR_SEC_EDGES         = 7,  /* Tier B pointer graph (from_node,off,to_node) */
    MTR_SEC_GEKKO_EXT     = 8,  /* fpr_ps1[]/gqr[] (F6, default-zero off-Gekko) */
    MTR_SEC_CALLS         = 9,  /* ordered outbound call oracle (calls[])  */
    MTR_SEC_ACCESS_LOG    = 10, /* Tier C observed (va,size,is_write) log   */
    MTR_SEC_NOTE          = 11, /* free-form UTF-8 diagnostic (non-authoritative) */
} mtr_section_type_t;

/* The mangled func_symbol (schema.md §2.1) is NOT a field of the fixed
 * mtr_header_t (the binary record is keyed by func_va; the symbol lives in the
 * symbol map / trace.sqlite). To round-trip the symbol byte-exactly inside a
 * standalone .mtr, the codec stores it as a NOTE (type 11) section whose UTF-8
 * payload is prefixed with this 4-byte tag. A NOTE without the tag is a plain
 * diagnostic note and never repopulates func_symbol. Tag = 'S','Y','M',':'. */
#define MTR_NOTE_SYMBOL_TAG "SYM:"

/* mem_flags bits in mtr_header_t (schema.md §3.2). */
typedef enum {
    MTR_MF_TIER_A          = 1u << 0, /* stack window present              */
    MTR_MF_TIER_B          = 1u << 1, /* pointer-chase nodes present       */
    MTR_MF_TIER_C          = 1u << 2, /* access log present                */
    MTR_MF_WRITES_COMPLETE = 1u << 3, /* writes_complete == strict         */
    MTR_MF_HAS_GEKKO_EXT   = 1u << 4, /* GEKKO_EXT section present          */
    MTR_MF_TRUNCATED       = 1u << 5, /* chase budget (nodes/bytes) hit    */
    MTR_MF_NOISY           = 1u << 6, /* cross-thread/DMA write in post     */
    /* bit7 reserved (zero) */
} mtr_mem_flags_t;

/* capture_method tags (trust gating + divergence class hints). */
typedef enum {
    MTR_CAP_UNICORN_FULL   = 1,
    MTR_CAP_XENIA_JIT      = 2,
    MTR_CAP_XENIA_OVERRIDE = 3,
    MTR_CAP_DOLPHIN_GDB    = 4,
    MTR_CAP_DOLPHIN_HOOK   = 5,
    MTR_CAP_RB3_NATIVE     = 6,
} mtr_capture_method_t;

/* writes_complete semantics for a WRITES section. */
typedef enum {
    MTR_WRITES_SCOPED = 0, /* compare only captured intervals (legacy comparator) */
    MTR_WRITES_STRICT = 1, /* assert nothing else changed */
} mtr_writes_mode_t;

/* All on-wire structs are byte-packed (no compiler padding). The codec relies on
 * this: its `struct` format strings use '<' (LE, no alignment) to match exactly. */
#pragma pack(push, 1)

/* File-level header (once per .mtr). schema.md §3.3.
 * codec MTR_FILE_HDR_FMT == "<4sHBBQQ20sBBH" (48 bytes). */
typedef struct {
    uint32_t file_magic;     /* MTR_FILE_MAGIC ('MTRF') */
    uint16_t schema_version; /* == MTR_SCHEMA_VERSION */
    uint8_t  arch;           /* mtr_arch_t */
    uint8_t  framing_endian; /* mtr_framing_endian_t (0 = LE) */
    uint64_t session_id;
    uint64_t created_unix;
    uint8_t  target_sha1[20];/* xex/dol/main.dol hash (provenance) */
    uint8_t  capture_method; /* mtr_capture_method_t */
    uint8_t  pool_present;    /* 1 iff a sibling .mtrpool exists (§3.4) */
    uint16_t reserved;
} mtr_file_header_t;

/* Per-record fixed header (NOT a TLV section). schema.md §3.2 RecordHeader.
 * codec MTR_HDR_FMT == "<IIQIIIHBBBBIHH" (42 bytes). */
typedef struct {
    uint32_t magic;          /* MTR_MAGIC */
    uint32_t record_len;     /* total bytes incl header + sections + footer */
    uint64_t call_seq;       /* monotonic per-session counter */
    uint32_t func_va;        /* callee_addr — PC at entry */
    uint32_t caller_va;      /* = regs_in.lr - 4 */
    uint32_t thread_id;      /* DECISION D3 */
    uint16_t depth_hint;     /* approx call-stack depth at entry */
    uint8_t  arch;           /* 1=ppc-gekko, 2=ppc-xenon */
    uint8_t  mem_flags;      /* mtr_mem_flags_t */
    uint8_t  capture_method; /* mtr_capture_method_t */
    uint8_t  _pad0;
    uint32_t insn_count;     /* instructions executed entry->exit */
    uint16_t section_count;  /* number of TLV sections following */
    uint16_t reserved;
} mtr_header_t;

/* Per-record footer. schema.md §3.2 RecordFooter. */
typedef struct {
    uint32_t crc32;  /* over [magic .. last section] */
    uint32_t magic2; /* 'mtre' read LE */
} mtr_footer_t;

/* Generic TLV section prefix. */
typedef struct {
    uint16_t type;   /* mtr_section_type_t */
    uint16_t flags;  /* per-section flags (e.g. writes_complete in WRITES,
                      *  node flags in MEM_NODE — schema.md §2.3) */
    uint32_t length; /* payload bytes following this prefix */
    /* uint8_t payload[length]; */
} mtr_section_t;

/* STACK payload header (Tier A); data[hi-lo] follows, BIG-endian guest bytes. */
typedef struct {
    uint32_t sp;  /* = r1 at capture (redundant but explicit) */
    uint32_t lo;  /* base guest VA of the window */
    uint32_t hi;  /* end guest VA (exclusive); data length = hi - lo */
} mtr_stack_hdr_t;

/* MEM_NODE payload header (Tier B); data[len] follows, BIG-endian guest bytes. */
typedef struct {
    uint16_t node_id; /* BFS-assigned id, referenced by mtr_edge_entry_t */
    uint16_t flags;   /* bit0 is_vtable, bit1 is_string_buf, bit2 reached_via_stack,
                       *  bit3 pooled, bits6-7 ptr_test (schema.md §2.3) */
    uint32_t base;    /* guest VA */
    uint32_t len;     /* byte count of data[] (or, if pooled, a sha1 ref) */
} mtr_mem_node_hdr_t;

/* WRITES entry header (mem_out); data[len] follows, BIG-endian guest bytes. */
typedef struct {
    uint32_t addr;  /* guest VA written */
    uint16_t len;   /* span length */
    uint8_t  kind;  /* 0=snapshot, 1=observed */
    uint8_t  _pad;
} mtr_write_entry_t;

/* EDGES entry (Tier B pointer graph). */
typedef struct {
    uint16_t from_node; /* node holding the pointer */
    uint16_t from_off;  /* byte offset within from_node */
    uint16_t to_node;   /* node pointed at */
    uint16_t _pad;
} mtr_edge_entry_t;

/* ACCESS_LOG entry (Tier C); values omitted — write values live in WRITES. */
typedef struct {
    uint32_t addr;
    uint8_t  size;
    uint8_t  is_write;
    uint16_t _pad;
} mtr_access_entry_t;

/* REGS payload: full PPC32 architectural register file (schema.md §2.2).
 * Field order is FROZEN: gpr[32], fpr[32], cr, xer, ctr, lr, msr — mirrored by
 * codec MTR_REGS_FMT == "<32I32QIIIII" (404 bytes). */
typedef struct {
    uint32_t gpr[32];
    uint64_t fpr[32]; /* raw u64 bit patterns — NEVER host doubles */
    uint32_t cr;
    uint32_t xer;
    uint32_t ctr;
    uint32_t lr;
    uint32_t msr;
} mtr_regs_t;

/* GEKKO_EXT payload (F6). default-zero on Xenon/DC3.
 * codec MTR_GEKKO_EXT_FMT == "<32Q8I" (288 bytes). */
typedef struct {
    uint64_t fpr_ps1[32]; /* paired-single partner half */
    uint32_t gqr[8];      /* graphics quantization registers */
} mtr_gekko_ext_t;

/* CALLS entry header (schema.md §3.5). The variable-length args/ret/writes that
 * follow are gated by arg_mask/ret_mask/nwrites and so are NOT a fixed struct;
 * the codec encodes them per §3.5. This header is the fixed prefix.
 * codec MTR_CALL_HDR_FMT == "<IIHBB" (12 bytes). */
typedef struct {
    uint32_t src_offset; /* bl_site_va - func_va */
    uint32_t target_va;  /* RESOLVED callee VA (indirect bctrl already resolved) */
    uint16_t arg_mask;   /* bit n (0..7) => gpr r(3+n) present; high byte => f-args */
    uint8_t  ret_mask;   /* bit0 r3, bit1 f1, bit2 cr present */
    uint8_t  nwrites;    /* number of callee mem_writes that follow */
} mtr_call_hdr_t;

#pragma pack(pop)

/* ---- Static sizeof guards (codec.py struct format strings must agree) ---- */
MTR_STATIC_ASSERT(sizeof(mtr_file_header_t)  == 48,  "mtr_file_header_t must be 48 bytes");
MTR_STATIC_ASSERT(sizeof(mtr_header_t)       == 42,  "mtr_header_t must be 42 bytes");
MTR_STATIC_ASSERT(sizeof(mtr_footer_t)       == 8,   "mtr_footer_t must be 8 bytes");
MTR_STATIC_ASSERT(sizeof(mtr_section_t)      == 8,   "mtr_section_t must be 8 bytes");
MTR_STATIC_ASSERT(sizeof(mtr_stack_hdr_t)    == 12,  "mtr_stack_hdr_t must be 12 bytes");
MTR_STATIC_ASSERT(sizeof(mtr_mem_node_hdr_t) == 12,  "mtr_mem_node_hdr_t must be 12 bytes");
MTR_STATIC_ASSERT(sizeof(mtr_write_entry_t)  == 8,   "mtr_write_entry_t must be 8 bytes");
MTR_STATIC_ASSERT(sizeof(mtr_edge_entry_t)   == 8,   "mtr_edge_entry_t must be 8 bytes");
MTR_STATIC_ASSERT(sizeof(mtr_access_entry_t) == 8,   "mtr_access_entry_t must be 8 bytes");
MTR_STATIC_ASSERT(sizeof(mtr_regs_t)         == 404, "mtr_regs_t must be 404 bytes");
MTR_STATIC_ASSERT(sizeof(mtr_gekko_ext_t)    == 288, "mtr_gekko_ext_t must be 288 bytes");
MTR_STATIC_ASSERT(sizeof(mtr_call_hdr_t)     == 12,  "mtr_call_hdr_t must be 12 bytes");

#endif /* MILO_TRACE_MTR_FORMAT_H */
