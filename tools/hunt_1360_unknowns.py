#!/usr/bin/env python3
"""Offline hunt for the 9 UNKNOWN 13.60 offsets, using the community capture only.

Method (same as verify_off_1360_dump.py, which is the proven machinery here):
  * a string is located in the image, then every RIP-relative xref from .text is
    collected, then the enclosing function of each xref is computed from a set of
    strict function entries (padding + `push rbp; mov rbp,rsp`) plus direct call
    targets. File offset == ktext-relative offset inside .text (0x0..0xCC0000).
  * FUN_SMP_NO_RENDEVOUS_BARRIER has no signature: it is found from the *call
    sites* of smp_rendezvous (known 0xB04440) by reading what the caller loads
    into rdi/rsi/rdx, then checking whether the pointer is a no-op body (`ret`).

Output is CANDIDATES with their evidence, never a value written into the tables.
Exit 0 = hunt ran; 1 = a candidate was confirmed strongly enough to be reported
as such in the summary. Nothing here is applied automatically.
"""
from __future__ import annotations

import hashlib
import os
import sys
from pathlib import Path

DUMP = Path(os.environ.get("PL5_1360_DUMP",
                           str(Path.home() / "src/ps5-dumps" / "k1360.bin")))
EXPECT_SHA = "c3f745e25dc25ee7afef89eb418b295b6334bbefe8aa17e6886483c35d78cddd"
EXPECT_SIZE = 0x62C0000
TEXT_LEN = 0xCC0000
SMP_RENDEZVOUS = 0xB04440

# field -> candidate strings (the string is evidence only when a xref exists)
TARGETS: dict[str, list[bytes]] = {
    "KERNEL_UART_OVERRIDE": [
        b"Force UART polling", b"Titania UART", b"Customized DBG UART Log Begin",
        b"Non-standard ns8250 class UART with FIFOs", b"hw.uart.lpc",
    ],
    "FUN_TRANSMITTER_CONTROL": [
        b"Setting transmitter tx_en", b"Enabling PMD transmitter",
        b"Disabling PMD transmitter", b"NOT disabling PMD transmitter",
    ],
    "FUN_MP3_INITIALIZE": [
        b"Audio Controller", b"Audio CoProcessor Job Man", b"audio mixer",
        b"Audio Compute Manager bui",
    ],
    "FUN_MP3_INVOKE": [
        b"Audio play operation in p", b"audio_out", b"audio output",
    ],
    "PS5_WIFI_FW_OFFSET": [b"wifi", b"Wifi", b"WiFi", b"wlan"],
    "IOMMU_SOFTC": [b"iommu", b"IOMMU"],
    "DATA_BASE_GVMSPACE": [b"vmspace", b"gvmspace"],
}


def main() -> int:
    try:
        from capstone import CS_ARCH_X86, CS_MODE_64, Cs
        from capstone.x86 import (X86_OP_IMM, X86_OP_MEM, X86_OP_REG,
                                  X86_REG_RDI, X86_REG_RDX, X86_REG_RIP,
                                  X86_REG_RSI)
    except ImportError as exc:
        print(f"ERROR: capstone required ({exc}); run under .venv-rea.", file=sys.stderr)
        return 2

    if not DUMP.is_file():
        print(f"ERROR: capture not found: {DUMP}", file=sys.stderr)
        return 2
    raw = DUMP.read_bytes()
    sha = hashlib.sha256(raw).hexdigest()
    if sha != EXPECT_SHA or len(raw) != EXPECT_SIZE:
        print(f"ERROR: capture mismatch sha={sha[:16]} size={len(raw)}", file=sys.stderr)
        return 2
    print(f"capture ok: sha256 {sha[:16]}… size {len(raw)} (0x{len(raw):x})\n")
    text = raw[:TEXT_LEN]

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True

    # one pass: call targets, rip-relative xrefs, and the call sites of smp_rendezvous
    call_targets: set[int] = {0}
    xrefs: dict[int, list[int]] = {}
    rend_sites: list[int] = []
    insn_count = 0
    for insn in md.disasm(text, 0):
        insn_count += 1
        if insn.mnemonic == "call" and insn.operands and insn.operands[0].type == X86_OP_IMM:
            tgt = insn.operands[0].imm
            call_targets.add(tgt)
            if tgt == SMP_RENDEZVOUS:
                rend_sites.append(insn.address)
        for op in insn.operands:
            if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP:
                dst = insn.address + insn.size + op.mem.disp
                xrefs.setdefault(dst, []).append(insn.address)
    print(f"disassembled {insn_count} instructions; {len(call_targets)} call targets; "
          f"{len(xrefs)} distinct rip-relative destinations; "
          f"{len(rend_sites)} call site(s) to smp_rendezvous\n")

    # strict entries
    entries: set[int] = set()
    needle = b"\x55\x48\x89"
    i = text.find(needle)
    while i != -1:
        if i >= 1 and text[i - 1] in (0x90, 0xCC):
            entries.add(i)
        i = text.find(needle, i + 1)
    entries |= call_targets
    targets = sorted(entries)

    def enclosing(addr: int) -> int:
        lo, hi, best = 0, len(targets) - 1, 0
        while lo <= hi:
            mid = (lo + hi) // 2
            if targets[mid] <= addr:
                best = targets[mid]
                lo = mid + 1
            else:
                hi = mid - 1
        return best

    def body_kind(off: int) -> str:
        b = text[off:off + 4]
        if b[:1] == b"\xc3":
            return "ret (1 byte)"
        if b[:2] == b"\xf3\xc3":
            return "rep ret"
        if b[:3] == b"\x55\x48\x89":
            return "prologue"
        return f"other ({b.hex()})"

    # ---- 1. string-driven candidates -------------------------------------
    print("=" * 78)
    print("STRING -> XREF -> ENCLOSING FUNCTION")
    print("=" * 78)
    for field, sigs in TARGETS.items():
        print(f"\n[{field}]")
        found_any = False
        for sig in sigs:
            start = 0
            while True:
                pos = raw.find(sig, start)
                if pos < 0:
                    break
                start = pos + 1
                if pos >= len(raw):
                    continue
                refs = xrefs.get(pos, [])
                if not refs:
                    continue
                found_any = True
                fns = sorted({enclosing(r) for r in refs})
                print(f"  string {sig!r} @0x{pos:x}  xrefs={len(refs)}  "
                      f"fn={[hex(f) for f in fns[:4]]}")
                for f in fns[:3]:
                    print(f"      fn 0x{f:x}: entry={f in entries} body={body_kind(f)}")
        if not found_any:
            print("  (no string in this list has a rip-relative xref)")

    # ---- 2. FUN_SMP_NO_RENDEVOUS_BARRIER from the rendezvous call sites ----
    print("\n" + "=" * 78)
    print("FUN_SMP_NO_RENDEVOUS_BARRIER - from smp_rendezvous call sites")
    print("=" * 78)
    if not rend_sites:
        print("  no call site to smp_rendezvous found: cannot derive it this way")
    for site in rend_sites[:12]:
        # walk back up to 40 instructions within a 200-byte window
        lo = max(0, site - 200)
        args: dict[int, int] = {}
        for insn in md.disasm(text[lo:site], lo):
            if not insn.operands:
                continue
            dst = insn.operands[0]
            if dst.type != X86_OP_REG or dst.reg not in (X86_REG_RDI, X86_REG_RSI, X86_REG_RDX):
                continue
            val = None
            if insn.mnemonic == "lea" and len(insn.operands) > 1:
                src = insn.operands[1]
                if src.type == X86_OP_MEM and src.mem.base == X86_REG_RIP:
                    val = insn.address + insn.size + src.mem.disp
            elif insn.mnemonic in ("mov", "movabs") and len(insn.operands) > 1:
                src = insn.operands[1]
                if src.type == X86_OP_IMM:
                    val = src.imm
            if val is not None:
                args[dst.reg] = val
        names = {X86_REG_RDI: "rdi/setup", X86_REG_RSI: "rsi/action", X86_REG_RDX: "rdx/teardown"}
        print(f"\n  call @0x{site:x} (fn 0x{enclosing(site):x}):")
        for reg, val in sorted(args.items()):
            if val < TEXT_LEN:
                extra = f"in .text, body={body_kind(val)}"
            else:
                extra = "outside .text (string/data)"
            print(f"      {names.get(reg, hex(reg))} = 0x{val:x}  {extra}")

    print("\nDone. Candidates only: nothing is written to the offset tables here.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
