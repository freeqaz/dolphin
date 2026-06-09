// SPDX-License-Identifier: GPL-2.0-or-later
//
// MiloTrace — Dolphin interpreter capture hook (milo-trace task W7).
//
// Snapshots full Gekko ppcState (gpr, ps[] BOTH halves, GQRs/spr, lr/cr/msr/xer/
// ctr) + a Tier-A stack RAM window at the entry and exit of every function whose
// entry VA is in a traced-entry set, and writes an F1 ".mtr" record (the FROZEN
// milo-trace record contract, schema.md §C2). The Gekko-superset fields
// (fpr_ps1[]/gqr[]) are exactly what the GDB stub (W4) cannot expose — this is the
// only Wii path that captures paired-singles + GQRs.
//
// Config (no Dolphin ini coupling — driven by env vars so the headless boot needs
// no extra flags):
//   MILO_TRACE_ENTRIES  path to a text file; each non-comment line is
//                       "<hex_va> <hex_size>" (size optional, defaults to 0 which
//                       falls back to LR-return exit detection). '#' starts a
//                       comment. The set of VAs is the traced-entry set.
//   MILO_TRACE_OUT      path to the output .mtr file (created/truncated on first
//                       traced entry). If unset, tracing is disabled.
//   MILO_TRACE_STACK_LO bytes of stack below r1 to snapshot (default 256).
//   MILO_TRACE_STACK_HI bytes of stack at/above r1 to snapshot (default 512).
//
// The hook is a single PC check per interpreter step (MiloTrace::OnStep), cheap
// when the traced set is empty / unmatched. It only sees the interpreter core
// (CPUCore=0), which is what W7 requires.

#pragma once

#include "Common/CommonTypes.h"

namespace PowerPC
{
struct PowerPCState;
}
namespace Memory
{
class MemoryManager;
}

namespace MiloTrace
{
// True once a traced-entry set + output path are loaded (i.e. MILO_TRACE_OUT and
// MILO_TRACE_ENTRIES were both set and parsed). Cheap to check per step.
bool IsActive();

// Called once per interpreter instruction step, BEFORE the instruction at
// ppc_state.pc executes. If pc is a traced entry, snapshots the entry state; if pc
// is the pending return address of an open traced frame (LR-return or fixed-size
// exit), snapshots the exit state and flushes a record. `memory` is used for the
// Tier-A stack RAM read (Memory::GetPointerForRange — byte-exact BE bytes).
void OnStep(PowerPC::PowerPCState& ppc_state, Memory::MemoryManager& memory);

// Flush + close the output file (drain any still-open frames as best-effort). Safe
// to call when inactive. Call at emulation teardown.
void Shutdown();
}  // namespace MiloTrace
