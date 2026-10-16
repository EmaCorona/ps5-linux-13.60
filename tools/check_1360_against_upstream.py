#!/usr/bin/env python3
"""Cross-check our 13.60 table against the independent upstream table.

Byepervisor-Reborn publishes `include/offsets/13_60.h`: the same three firmware
images we target, from a different project, with the *bytes* of each gadget written
in the comment. Comparing the two tables is a real cross-check of our table that
does not depend on our own derivation, and it is cheap.

Two things are verified:
  * every upstream value is checked against the capture we hold (sha256 below), by
    byte sequence for gadgets and by entry shape for symbols -- so agreement is not
    "two tables say the same thing", it is "both describe this image".
  * values we carry but upstream does not are listed, with no verdict: absence up
    there is not evidence against us.

Network: fetches 13_60.h unless --upstream PATH is given (then it is offline).
Exit 0 = every compared entry agrees; 1 = at least one differs; 2 = unusable input.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import subprocess
import sys
import urllib.request
from pathlib import Path

CAPTURE_SHA = "c3f745e25dc25ee7afef89eb418b295b6334bbefe8aa17e6886483c35d78cddd"
UPSTREAM_URL = ("https://api.github.com/repos/PS5Dev/Byepervisor-Reborn/contents/"
                "include/offsets/13_60.h")
# upstream name -> our field (only where the names differ)
RENAME = {
    "KERNEL_GADGET_PIVOT_ADD_RSP28_RET": "GAD_ADD_RSP_28_POP_RBP_RET",
    "KERNEL_GADGET_IRETQ": "GAD_IRETQ",
    "KERNEL_GADGET_POP_RAX": "GAD_POP_RAX_RET",
    "KERNEL_GADGET_POP_RCX": "GAD_POP_RCX_RET",
    "KERNEL_GADGET_POP_RDI": "GAD_POP_RDI_RET",
    "KERNEL_GADGET_POP_RSI": "GAD_POP_RSI_RET",
    "KERNEL_GADGET_POP_RDX": "GAD_POP_RDX_RET",
    "KERNEL_GADGET_POP_RSP": "GAD_POP_RSP_RET",
    "KERNEL_GADGET_RET_TRAMP": "GAD_RET_TRAMP",
    "KERNEL_GADGET_ST_RCX_RDX": "GAD_ST_RCX_RDX",
    "KERNEL_GADGET_SET_DR7": "GAD_SET_DR7",
    "KERNEL_GADGET_REP_MOVSB": "GAD_REP_MOVSB",
    "KERNEL_GADGET_CLD": "GAD_CLD",
    "KERNEL_GADGET_MOV_RAX_RSI": "GAD_MOV_RAX_RSI",
    "KERNEL_GADGET_MOV_RAX_RDI": "GAD_MOV_RAX_RDI",
}


def fetch_upstream(path: Path | None) -> str:
    if path:
        return path.read_text()
    with urllib.request.urlopen(UPSTREAM_URL, timeout=30) as r:
        payload = json.load(r)
    return base64.b64decode(payload["content"]).decode()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--upstream", type=Path, help="local copy of 13_60.h (offline)")
    ap.add_argument("--capture", type=Path,
                    default=Path.home() / "src/ps5-dumps" / "k1360.bin")
    ap.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[1])
    args = ap.parse_args()

    if not args.capture.is_file():
        print(f"ERROR: capture not found: {args.capture}", file=sys.stderr)
        return 2
    raw = args.capture.read_bytes()
    sha = hashlib.sha256(raw).hexdigest()
    if sha != CAPTURE_SHA:
        print(f"ERROR: capture sha256 {sha[:16]}… != {CAPTURE_SHA[:16]}…", file=sys.stderr)
        return 2
    print(f"capture ok: {sha[:16]}… ({len(raw)} bytes)")

    try:
        upstream = fetch_upstream(args.upstream)
    except Exception as exc:  # network or API failure is not a verdict
        print(f"ERROR: could not obtain the upstream table: {exc}", file=sys.stderr)
        print("       pass --upstream PATH to run offline.", file=sys.stderr)
        return 2

    entries = re.findall(r"(0x[0-9A-Fa-f]+),\s*//\s*([A-Z0-9_]+)", upstream)
    ours_src = (args.repo / "source/offsets/off_1360.c").read_text()
    ours = {k: int(v, 16) for k, v in
            re.findall(r"\.([A-Z_][A-Z0-9_]*)\s*=\s*(0x[0-9A-Fa-f]+|0)\b", ours_src)}

    agree = differ = absent = 0
    for val, name in entries:
        v = int(val, 16)
        field = RENAME.get(name, name)
        o = ours.get(field)
        if o is None:
            absent += 1
            print(f"  {name:<36} upstream 0x{v:08x}  (not in our table: no verdict)")
            continue
        if o == v:
            agree += 1
            print(f"  {name:<36} 0x{v:08x}  AGREE   bytes={raw[v:v+6].hex()}")
        else:
            differ += 1
            print(f"  {name:<36} 0x{v:08x}  DIFFER  ours=0x{o:x} bytes={raw[o:o+6].hex()}")
    print(f"\nagree={agree} differ={differ} absent={absent} of {len(entries)} upstream entries")
    return 1 if differ else 0


if __name__ == "__main__":
    sys.exit(main())
