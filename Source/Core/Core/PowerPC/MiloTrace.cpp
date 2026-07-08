// SPDX-License-Identifier: GPL-2.0-or-later
//
// MiloTrace — Dolphin interpreter capture hook (milo-trace task W7). See
// MiloTrace.h for the contract. Emits the FROZEN F1 .mtr record format
// (MiloTrace_mtr_format.h, vendored from milo-trace; schema.md §C2).

#include "Core/PowerPC/MiloTrace.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <mutex>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <zlib.h>  // crc32() — identical polynomial/init to Python's zlib.crc32

#include "Common/Logging/Log.h"
#include "Common/Thread.h"
#include "Core/HW/Memmap.h"
#include "Core/PowerPC/Gekko.h"
#include "Core/PowerPC/PowerPC.h"

#include "Core/PowerPC/MiloTrace_mtr_format.h"

namespace MiloTrace
{
namespace
{
// ----------------------------------------------------------------------------
// Little-endian framing helpers — the .mtr framing fields are LE (schema §3.1).
// Captured guest RAM blobs are appended verbatim (already BE guest-native).
// ----------------------------------------------------------------------------
void PutU8(std::vector<u8>& b, u8 v)
{
  b.push_back(v);
}
void PutU16(std::vector<u8>& b, u16 v)
{
  b.push_back(static_cast<u8>(v & 0xFF));
  b.push_back(static_cast<u8>((v >> 8) & 0xFF));
}
void PutU32(std::vector<u8>& b, u32 v)
{
  for (int i = 0; i < 4; ++i)
    b.push_back(static_cast<u8>((v >> (8 * i)) & 0xFF));
}
void PutU64(std::vector<u8>& b, u64 v)
{
  for (int i = 0; i < 8; ++i)
    b.push_back(static_cast<u8>((v >> (8 * i)) & 0xFF));
}

// One captured architectural register file (the contract's mtr_regs_t, §2.2).
struct RegFile
{
  u32 gpr[32]{};
  u64 fpr[32]{};  // ps0 halves (raw u64 bit patterns)
  u32 cr = 0;
  u32 xer = 0;
  u32 ctr = 0;
  u32 lr = 0;
  u32 msr = 0;
  // Gekko ext (F6): ps1 partner halves + GQRs.
  u64 fpr_ps1[32]{};
  u32 gqr[8]{};
};

void SnapshotRegs(const PowerPC::PowerPCState& s, RegFile& out)
{
  for (int i = 0; i < 32; ++i)
  {
    out.gpr[i] = s.gpr[i];
    out.fpr[i] = s.ps[i].PS0AsU64();
    out.fpr_ps1[i] = s.ps[i].PS1AsU64();
  }
  out.cr = s.cr.Get();
  out.xer = s.GetXER().Hex;
  out.ctr = CTR(s);
  out.lr = LR(s);
  out.msr = s.msr.Hex;
  for (int i = 0; i < 8; ++i)
    out.gqr[i] = GQR(s, i);
}

// Serialize a RegFile as the mtr_regs_t payload (404 bytes): gpr[32] u32, fpr[32]
// u64, cr, xer, ctr, lr, msr — all LE framing. The ps1/gqr live in GEKKO_EXT.
void PackRegsPayload(std::vector<u8>& b, const RegFile& r)
{
  for (int i = 0; i < 32; ++i)
    PutU32(b, r.gpr[i]);
  for (int i = 0; i < 32; ++i)
    PutU64(b, r.fpr[i]);
  PutU32(b, r.cr);
  PutU32(b, r.xer);
  PutU32(b, r.ctr);
  PutU32(b, r.lr);
  PutU32(b, r.msr);
}

// A TLV section: type, flags, length, payload. (mtr_section_t prefix + payload.)
void EmitSection(std::vector<u8>& rec, u16 type, u16 flags, const std::vector<u8>& payload)
{
  PutU16(rec, type);
  PutU16(rec, flags);
  PutU32(rec, static_cast<u32>(payload.size()));
  rec.insert(rec.end(), payload.begin(), payload.end());
}

// ----------------------------------------------------------------------------
// Open-frame bookkeeping (one per in-flight traced call, per stack depth).
// ----------------------------------------------------------------------------
struct OpenFrame
{
  u32 func_va = 0;       // entry PC
  u32 caller_va = 0;     // lr_in - 4
  u32 return_addr = 0;   // lr_in: PC value the function returns to
  u32 entry_sp = 0;      // r1 at entry (frame is "returned" when pc==return_addr
                         // and r1 has unwound back to >= entry_sp)
  u32 fixed_exit = 0;    // entry_va + size - 4 (last insn) when size known, else 0
  RegFile regs_in;
  u32 stack_lo = 0;      // captured Tier-A window [stack_lo, stack_hi)
  u32 stack_hi = 0;
  std::vector<u8> stack_in;  // entry snapshot of the window (BE bytes)
  u32 insn_count = 0;
};

// ----------------------------------------------------------------------------
// Global trace state (single capture session; the CPU thread is the only writer
// to the file but a mutex keeps it safe if a second thread ever traces too).
// ----------------------------------------------------------------------------
struct State
{
  bool initialized = false;
  bool active = false;
  std::ofstream out;
  std::unordered_map<u32, u32> entries;  // va -> size (0 = unknown)
  std::vector<OpenFrame> open;           // shadow stack of in-flight frames
  u64 call_seq = 0;
  u32 stack_lo_bytes = 256;
  u32 stack_hi_bytes = 512;
  std::mutex mu;
};

State& G()
{
  static State s;
  return s;
}

u32 ParseHex(const std::string& tok)
{
  return static_cast<u32>(std::strtoul(tok.c_str(), nullptr, 16));
}

// Lazy one-time init from env vars. Returns true if tracing is active afterwards.
bool EnsureInit()
{
  State& g = G();
  if (g.initialized)
    return g.active;
  g.initialized = true;

  const char* out_path = std::getenv("MILO_TRACE_OUT");
  const char* entries_path = std::getenv("MILO_TRACE_ENTRIES");
  if (!out_path || !entries_path)
    return false;

  if (const char* lo = std::getenv("MILO_TRACE_STACK_LO"))
    g.stack_lo_bytes = static_cast<u32>(std::strtoul(lo, nullptr, 0));
  if (const char* hi = std::getenv("MILO_TRACE_STACK_HI"))
    g.stack_hi_bytes = static_cast<u32>(std::strtoul(hi, nullptr, 0));

  // Parse the traced-entry set: "<hex_va> [hex_size]" per line, '#' comments.
  std::ifstream ef(entries_path);
  if (!ef)
  {
    ERROR_LOG_FMT(POWERPC, "MiloTrace: cannot open MILO_TRACE_ENTRIES={}", entries_path);
    return false;
  }
  std::string line;
  while (std::getline(ef, line))
  {
    const auto hash = line.find('#');
    if (hash != std::string::npos)
      line = line.substr(0, hash);
    // tokenize on whitespace
    size_t i = 0;
    auto next_tok = [&](std::string& t) {
      while (i < line.size() && (line[i] == ' ' || line[i] == '\t'))
        ++i;
      size_t start = i;
      while (i < line.size() && line[i] != ' ' && line[i] != '\t')
        ++i;
      if (start == i)
        return false;
      t = line.substr(start, i - start);
      return true;
    };
    std::string va_tok, size_tok;
    if (!next_tok(va_tok))
      continue;
    u32 va = ParseHex(va_tok);
    u32 size = 0;
    if (next_tok(size_tok))
      size = ParseHex(size_tok);
    g.entries[va] = size;
  }
  if (g.entries.empty())
  {
    ERROR_LOG_FMT(POWERPC, "MiloTrace: MILO_TRACE_ENTRIES had no entries ({})", entries_path);
    return false;
  }

  g.out.open(out_path, std::ios::binary | std::ios::trunc);
  if (!g.out)
  {
    ERROR_LOG_FMT(POWERPC, "MiloTrace: cannot open MILO_TRACE_OUT={}", out_path);
    return false;
  }

  // File-level header (mtr_file_header_t, 48 bytes — schema §3.3). arch=gekko,
  // capture_method=dolphin_hook. target_sha1 left zero (provenance only).
  std::vector<u8> fh;
  PutU32(fh, MTR_FILE_MAGIC);
  PutU16(fh, MTR_SCHEMA_VERSION);
  PutU8(fh, MTR_ARCH_GEKKO);
  PutU8(fh, MTR_FRAMING_LE);
  PutU64(fh, 0);  // session_id
  PutU64(fh, 0);  // created_unix
  for (int i = 0; i < 20; ++i)
    PutU8(fh, 0);  // target_sha1
  PutU8(fh, MTR_CAP_DOLPHIN_HOOK);
  PutU8(fh, 0);   // pool_present
  PutU16(fh, 0);  // reserved
  g.out.write(reinterpret_cast<const char*>(fh.data()), static_cast<std::streamsize>(fh.size()));

  g.active = true;
  NOTICE_LOG_FMT(POWERPC, "MiloTrace: ACTIVE — {} traced entries, out={}", g.entries.size(),
                 out_path);
  return true;
}

// Read a guest RAM window [lo, hi) into BE-native bytes via Memory. Returns false
// if the range is not contiguously mapped (the window is then skipped, not faked).
bool ReadGuestRange(Memory::MemoryManager& memory, u32 lo, u32 hi, std::vector<u8>& out)
{
  if (hi <= lo)
    return false;
  const u32 len = hi - lo;
  u8* host = memory.GetPointerForRange(lo, len);
  if (!host)
    return false;
  out.assign(host, host + len);  // verbatim BE guest bytes
  return true;
}

// Compute the Tier-A stack window [lo, hi) around r1, 4-byte aligned.
void StackWindow(const State& g, u32 sp, u32& lo, u32& hi)
{
  lo = (sp - g.stack_lo_bytes) & ~3u;
  hi = (sp + g.stack_hi_bytes + 3u) & ~3u;
}

// Emit a finished record (entry + exit paired) to the output file.
void FlushRecord(State& g, OpenFrame& f, const RegFile& regs_out,
                 const std::vector<u8>& stack_out)
{
  std::vector<u8> body;  // header + sections (footer appended after CRC)

  // --- Fixed record header (mtr_header_t, 42 bytes — schema §3.2). ---
  u8 mem_flags = MTR_MF_HAS_GEKKO_EXT;
  if (!f.stack_in.empty())
    mem_flags |= MTR_MF_TIER_A;
  // mem_out is a scoped snapshot-diff over the Tier-A window (writes_complete=0).

  // record_len is patched after sections are built; reserve the header now.
  const size_t hdr_pos = body.size();
  PutU32(body, MTR_MAGIC);
  PutU32(body, 0);  // record_len placeholder (patched below)
  PutU64(body, g.call_seq);
  PutU32(body, f.func_va);
  PutU32(body, f.caller_va);
  PutU32(body, static_cast<u32>(Common::CurrentThreadId()));
  PutU16(body, static_cast<u16>(g.open.size() & 0xFFFF));  // depth_hint
  PutU8(body, MTR_ARCH_GEKKO);
  PutU8(body, mem_flags);
  PutU8(body, MTR_CAP_DOLPHIN_HOOK);
  PutU8(body, 0);  // _pad0
  PutU32(body, f.insn_count);
  const size_t section_count_pos = body.size();
  PutU16(body, 0);  // section_count placeholder (patched below)
  PutU16(body, 0);  // reserved

  u16 section_count = 0;

  // --- REGS_IN ---
  {
    std::vector<u8> p;
    PackRegsPayload(p, f.regs_in);
    EmitSection(body, MTR_SEC_REGS_IN, 0, p);
    ++section_count;
  }
  // --- REGS_OUT ---
  {
    std::vector<u8> p;
    PackRegsPayload(p, regs_out);
    EmitSection(body, MTR_SEC_REGS_OUT, 0, p);
    ++section_count;
  }

  // --- STACK (Tier A): {sp, lo, hi, data[hi-lo]} ---
  if (!f.stack_in.empty())
  {
    std::vector<u8> p;
    PutU32(p, f.entry_sp);  // sp
    PutU32(p, f.stack_lo);  // lo
    PutU32(p, f.stack_hi);  // hi
    p.insert(p.end(), f.stack_in.begin(), f.stack_in.end());
    EmitSection(body, MTR_SEC_STACK, 0, p);
    ++section_count;
  }

  // --- WRITES (mem_out): snapshot-diff the Tier-A window entry vs exit. Scoped
  //     (writes_complete=0): only captured intervals are compared on replay. Each
  //     changed contiguous run becomes a Write entry (BE bytes). ---
  if (!f.stack_in.empty() && stack_out.size() == f.stack_in.size())
  {
    std::vector<u8> p;
    // Build the entries first to know the count, then prepend it.
    std::vector<u8> entries;
    u32 count = 0;
    const size_t n = f.stack_in.size();
    size_t i = 0;
    while (i < n)
    {
      if (f.stack_in[i] == stack_out[i])
      {
        ++i;
        continue;
      }
      const size_t run_start = i;
      while (i < n && f.stack_in[i] != stack_out[i])
        ++i;
      const u16 run_len = static_cast<u16>(i - run_start);
      const u32 addr = f.stack_lo + static_cast<u32>(run_start);
      PutU32(entries, addr);
      PutU16(entries, run_len);
      PutU8(entries, 0);  // kind = snapshot
      PutU8(entries, 0);  // _pad
      entries.insert(entries.end(), stack_out.begin() + run_start,
                     stack_out.begin() + run_start + run_len);
      ++count;
    }
    if (count > 0)
    {
      PutU32(p, count);
      p.insert(p.end(), entries.begin(), entries.end());
      EmitSection(body, MTR_SEC_WRITES, MTR_WRITES_SCOPED, p);
      ++section_count;
    }
  }

  // --- GEKKO_EXT (F6): fpr_ps1[32] u64 + gqr[8] u32 (288 bytes). This is the
  //     whole point of the W7 hook vs the GDB stub. ---
  {
    std::vector<u8> p;
    for (int i = 0; i < 32; ++i)
      PutU64(p, regs_out.fpr_ps1[i]);
    for (int i = 0; i < 8; ++i)
      PutU32(p, regs_out.gqr[i]);
    EmitSection(body, MTR_SEC_GEKKO_EXT, 0, p);
    ++section_count;
  }

  // Patch section_count (LE u16) and record_len (LE u32).
  body[section_count_pos] = static_cast<u8>(section_count & 0xFF);
  body[section_count_pos + 1] = static_cast<u8>((section_count >> 8) & 0xFF);

  const u32 record_len = static_cast<u32>(body.size() + sizeof(mtr_footer_t));
  body[hdr_pos + 4] = static_cast<u8>(record_len & 0xFF);
  body[hdr_pos + 5] = static_cast<u8>((record_len >> 8) & 0xFF);
  body[hdr_pos + 6] = static_cast<u8>((record_len >> 16) & 0xFF);
  body[hdr_pos + 7] = static_cast<u8>((record_len >> 24) & 0xFF);

  // Footer: crc32 over [magic .. last section] (the whole body), then magic2.
  const u32 crc =
      static_cast<u32>(crc32(0L, reinterpret_cast<const Bytef*>(body.data()),
                             static_cast<uInt>(body.size())));
  std::vector<u8> footer;
  PutU32(footer, crc);
  PutU32(footer, MTR_MAGIC2);

  g.out.write(reinterpret_cast<const char*>(body.data()),
              static_cast<std::streamsize>(body.size()));
  g.out.write(reinterpret_cast<const char*>(footer.data()),
              static_cast<std::streamsize>(footer.size()));
  g.out.flush();
  ++g.call_seq;
}

}  // namespace

bool IsActive()
{
  return G().active;
}

void OnStep(PowerPC::PowerPCState& ppc_state, Memory::MemoryManager& memory)
{
  State& g = G();
  // Fast path: once init has resolved to "inactive", this is a single bool test
  // per interpreter step. Before init resolves (first steps), run EnsureInit once.
  if (!g.active)
  {
    if (g.initialized)
      return;  // permanently inactive (env not set / parse failed)
    if (!EnsureInit())
      return;
  }

  std::lock_guard<std::mutex> lock(g.mu);
  const u32 pc = ppc_state.pc;

  // (1) Exit check FIRST: if pc is the pending return address (or fixed-size last
  //     insn) of the innermost open frame, the call has returned — snapshot exit.
  //     Loop in case multiple frames unwind to the same PC (tail-chains).
  while (!g.open.empty())
  {
    OpenFrame& top = g.open.back();
    const u32 sp = ppc_state.gpr[1];
    const bool lr_return = (top.return_addr != 0 && pc == top.return_addr && sp >= top.entry_sp);
    const bool fixed_return = (top.fixed_exit != 0 && pc == top.fixed_exit);
    if (!lr_return && !fixed_return)
      break;

    RegFile regs_out;
    SnapshotRegs(ppc_state, regs_out);
    std::vector<u8> stack_out;
    if (top.stack_hi > top.stack_lo)
      ReadGuestRange(memory, top.stack_lo, top.stack_hi, stack_out);

    OpenFrame finished = std::move(top);
    g.open.pop_back();
    // For fixed-size exit, the last instruction itself executes this step; the
    // captured regs_out are pre-blr but post-body (acceptable for a leaf value
    // gate). LR-return captures the true post-return state. Prefer LR-return.
    FlushRecord(g, finished, regs_out, stack_out);
  }

  // (2) Entry check: if pc is a traced entry VA, open a new frame.
  auto it = g.entries.find(pc);
  if (it != g.entries.end())
  {
    OpenFrame f;
    f.func_va = pc;
    f.return_addr = LR(ppc_state);
    f.caller_va = f.return_addr - 4;
    f.entry_sp = ppc_state.gpr[1];
    const u32 size = it->second;
    f.fixed_exit = (size >= 4) ? (pc + size - 4) : 0;
    SnapshotRegs(ppc_state, f.regs_in);
    StackWindow(g, f.entry_sp, f.stack_lo, f.stack_hi);
    ReadGuestRange(memory, f.stack_lo, f.stack_hi, f.stack_in);
    g.open.push_back(std::move(f));
  }

  // (3) Per-step instruction count attribution for the innermost open frame.
  if (!g.open.empty())
    ++g.open.back().insn_count;
}

void Shutdown()
{
  State& g = G();
  std::lock_guard<std::mutex> lock(g.mu);
  if (!g.active)
    return;
  // Best-effort: drop any still-open frames (no exit observed — short boot).
  g.open.clear();
  g.out.flush();
  g.out.close();
  g.active = false;
  g.initialized = true;  // stay inert; do not re-init.
}

}  // namespace MiloTrace
