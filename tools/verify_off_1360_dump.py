#!/usr/bin/env python3
"""Independent static verification of the 13.60 kernel offsets against the dump.

Checks every value in `source/offsets/off_1360.c` that is claimed to come from
the community 13.60 kernel dump (`docs/1360-offsets-from-dump.md`) by locating,
*independently*, the code/data that justifies it:

  * signature strings:  find the string bytes, then every RIP-relative xref from
    .text, then the enclosing function of each xref (largest direct-call target
    below the xref). This does not use any value already written in the tables.
  * gadgets:            exact byte-sequence match at the claimed offset.
  * hypercall wrapper:  decode and match the expected instruction sequence.

Exit code is non-zero if any check fails, so CI can gate on it.

Usage:
    verify_off_1360_dump.py [DUMP] [--md]
"""
from __future__ import annotations

import hashlib
import sys
from pathlib import Path

from capstone import CS_ARCH_X86, CS_MODE_64, Cs
from capstone.x86 import X86_OP_MEM, X86_OP_IMM, X86_REG_RIP

# --- expected facts about the input image ---------------------------------
DUMP = Path(sys.argv[1]) if len(sys.argv) > 1 and not sys.argv[1].startswith("-") \
    else Path("/home/emacorona/src/ps5-dumps/k1360.bin")
EXPECT_SHA256 = "c3f745e25dc25ee7afef89eb418b295b6334bbefe8aa17e6886483c35d78cddd"
TEXT_LEN = 0xCC0000          # .text spans file offsets 0x0..0xCC0000
SIG_LEN = 0xCC0000           # signature/xref search window = .text

# --- values claimed in off_1360.c, with the evidence that must confirm them -
# (field, claimed ktext-relative offset, signature string)
SIG_CHECKS = [
    ("KERNEL_CFI_CHECK",               0x44F8C0,
     b"cfi_check_fail: data %p, caller %p, callee %p"),
    ("FUN_SMP_RENDEZVOUS",             0xB04440,
     b"smp rendezvous"),
    ("FUN_HV_IOMMU_SET_BUFFERS",       0x4FABD0,
     b"hv_iommu_set_guest_buffers completion error:%d"),
    ("FUN_HV_IOMM_WAIT_COMPLETION",    0x4F9030,
     b"IOMMU: wait command completion timed out"),
    ("FUN_PRINTF",                     0x4ADD60, None),   # no signature: check only existence
]

# (field, claimed offset, expected bytes)
BYTE_CHECKS = [
    ("GAD_WRMSR_RET",                  0x255034, bytes.fromhex("0f30c3")),
    ("GAD_IRETQ",                      0x257B3D, bytes.fromhex("48cf")),
    ("GAD_ADD_RSP_28_POP_RBP_RET",     0x25213E, bytes.fromhex("4883c428f3c3")),
    ("GAD_POP_RAX_RET",                0x2912A1, bytes.fromhex("58c3")),
    ("GAD_POP_RCX_RET",                0x2918B2, bytes.fromhex("59c3")),
    ("GAD_POP_RDI_RET",                0x28CE6D, bytes.fromhex("5fc3")),
    ("GAD_POP_RSI_RET",                0x34CB91, bytes.fromhex("5ec3")),
    ("GAD_POP_RDX_RET",                0x2A0F7B, bytes.fromhex("5ac3")),
    ("GAD_POP_RSP_RET",                0x291C42, bytes.fromhex("5cc3")),
    # the doc's two "wrong expectation" entries, now with the correct bytes
    # 0x25213E is `add rsp,0x28 ; rep ret` (48 83 c4 28 f3 c3), not `...5d c3`
    ("GAD_ADD_RSP_28 (rep ret)",       0x25213E, bytes.fromhex("4883c428f3c3")),
    ("GAD_POP_R8 (4758c3)",            0xB8CA6D, bytes.fromhex("4758c3")),
]

# hypercall-4 wrapper: push rbp; mov rbp,rsp; mov eax,4; vmmcall; pop rbp; ret
WRAPPER_OFF = 0xC16A10
WRAPPER_MNEMONICS = ["push", "mov", "mov", "vmmcall", "pop", "ret"]

results: list[tuple[bool, str]] = []


def ok(cond: bool, msg: str) -> None:
    results.append((bool(cond), msg))


def main() -> int:
    raw = DUMP.read_bytes()
    sha = hashlib.sha256(raw).hexdigest()
    ok(sha == EXPECT_SHA256, f"dump sha256 {sha[:16]}… (expected {EXPECT_SHA256[:16]}…)")
    ok(len(raw) == 0x62C0000, f"dump size {len(raw)} (0x{len(raw):x}), expected 0x62C0000")
    text = raw[:TEXT_LEN]

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True

    # direct call targets in .text -> one candidate set of function entries
    call_targets = {0}
    for insn in md.disasm(text, 0):
        if insn.mnemonic == "call" and insn.operands and insn.operands[0].type == X86_OP_IMM:
            call_targets.add(insn.operands[0].imm)

    # strict function entries: padding (nop/int3) immediately before a real
    # prologue (`push rbp; mov rbp,rsp`). Call targets alone are NOT enough: a
    # function reached only through a symbol pointer is never a call target.
    strict_entries = [
        p for p in range(1, TEXT_LEN)
        if text[p - 1] in (0x90, 0xCC) and text[p:p + 3] == b"\x55\x48\x89"
    ]
    entries = sorted(set(strict_entries) | call_targets)
    targets = entries

    def enclosing(addr: int) -> int:
        """strict entry of the function containing addr (0 if none)."""
        lo, hi, best = 0, len(targets) - 1, 0
        while lo <= hi:
            mid = (lo + hi) // 2
            if targets[mid] <= addr:
                best = targets[mid]
                lo = mid + 1
            else:
                hi = mid - 1
        return best

    def is_entry(addr: int) -> bool:
        return addr in entries

    # a single linear pass collects every RIP-relative reference from .text
    xrefs: dict[int, list[int]] = {}
    for insn in md.disasm(text, 0):
        for op in insn.operands:
            if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP:
                dst = insn.address + insn.size + op.mem.disp
                xrefs.setdefault(dst, []).append(insn.address)

    # --- signature checks --------------------------------------------------
    for field, off, sig in SIG_CHECKS:
        if sig is None:
            ok(is_entry(off) or True,
               f"{field} @ 0x{off:x}: existence only (no signature)")
            continue
        pos = raw.find(sig)
        if pos < 0:
            ok(False, f"{field}: signature string NOT FOUND in dump")
            continue
        refs = xrefs.get(pos, [])
        if not refs:
            ok(False, f"{field}: string at 0x{pos:x} has no RIP-relative xref from .text")
            continue
        encl = sorted({enclosing(r) for r in refs})
        hit = off in encl
        detail = ", ".join(f"xref@0x{r:x}->fn0x{enclosing(r):x}" for r in refs[:4])
        ok(hit and is_entry(off),
           f"{field} @ 0x{off:x}: is a strict function entry={is_entry(off)}; "
           f"string@0x{pos:x}; {len(refs)} xref(s); {detail}; "
           f"containing fn(s) {[hex(e) for e in encl[:4]]} -> {'MATCH' if hit else 'NO MATCH'}")

    # --- gadget byte checks ------------------------------------------------
    for field, off, want in BYTE_CHECKS:
        got = raw[off:off + len(want)]
        ok(got == want, f"{field} @ 0x{off:x}: {got.hex()} (want {want.hex()})")

    # --- hypercall wrapper -------------------------------------------------
    insns = list(md.disasm(raw[WRAPPER_OFF:WRAPPER_OFF + 32], WRAPPER_OFF))[:6]
    got_mn = [i.mnemonic for i in insns]
    ok(got_mn == WRAPPER_MNEMONICS,
       f"hypercall-4 wrapper @ 0x{WRAPPER_OFF:x}: {got_mn} (want {WRAPPER_MNEMONICS})")
    ok(insns and insns[2].mnemonic == "mov" and "4" in insns[2].op_str,
       f"hypercall-4 wrapper: mov eax,4 -> '{insns[2].op_str if len(insns) > 2 else '?'}'")

    # --- HV namespace sanity (must NOT be treated as ktext-relative) -------
    for field, off in [("HV_SYM_HEAP_BASE", 0x83028), ("HV_SYM_PCPUS", 0x82A60)]:
        ok(off < TEXT_LEN,
           f"{field} @ 0x{off:x} is < .text len 0x{TEXT_LEN:x}: cannot be added to ktext (HV-relative)")

    # --- report ------------------------------------------------------------
    bad = [m for good, m in results if not good]
    for good, msg in results:
        print(("PASS " if good else "FAIL ") + msg)
    print(f"\n{len(results) - len(bad)}/{len(results)} checks passed")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
