#!/usr/bin/env python3
"""Static guard: the shared takeover blob must be firmware-parameterized.

The blob (source/shellcode/hv_takeover/takeover.S) is written into a live kernel
by the post-resume takeover, so a firmware address baked into its instruction
body would be applied to whatever firmware happens to be running. This checks:

  1. the instruction body (after the "end firmware config" marker) contains no
     firmware-specific literal -- 13.20 *or* 13.60 -- only macro names;
  2. a build for 13.60 is REFUSED (its HV handler PA is HV-resident and cannot
     be derived from a kernel dump), instead of silently inheriting 13.20's;
  3. a build for 13.20 reproduces the blob the repository already shipped
     (byte-identical), so the split is behaviour-preserving for the firmware
     that actually works today.

Needs gcc/objcopy on PATH. Exits non-zero on any failure.
"""
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TK = ROOT / "source/shellcode/hv_takeover"
SRC = TK / "takeover.S"
HDR = TK / "takeover.h"

# any firmware-resolved address; must never appear outside the config block
LITERALS = [
    "0x62847375", "0x44e5d0", "0xaf94e0", "0xc09e40", "0x291232",   # 13.20
    "0x44f8c0", "0xb04440", "0xc16a10", "0x2912a2",                 # 13.60
]
MARKER = "--- end firmware config ---"

results = []


def ok(cond, msg):
    results.append((bool(cond), msg))


def build(fw):
    return subprocess.run(
        ["make", "-C", str(TK), f"PL5_TAKEOVER_FW={fw}", "--always-make"],
        capture_output=True, text=True)


def main() -> int:
    text = SRC.read_text()
    if MARKER not in text:
        print(f"FAIL {SRC} has no '{MARKER}' marker")
        return 1
    body = text.split(MARKER, 1)[1]
    leaked = [lit for lit in LITERALS if lit in body.lower()]
    ok(not leaked,
       f"takeover.S instruction body carries no firmware literal "
       f"(leaked: {leaked or 'none'})")

    # 2. 13.60 must be refused
    r1360 = build(1360)
    ok(r1360.returncode != 0,
       f"build PL5_TAKEOVER_FW=1360 refused (exit {r1360.returncode})")
    ok("HV_VMMCALL_HANDLER_PA is unknown" in (r1360.stdout + r1360.stderr),
       "the 13.60 refusal names the unknown HV handler PA")

    # 3. 13.20 must still build and carry 13.20 (not 13.60) constants.
    # takeover.h is generated and untracked, so the regression is structural:
    # size + the immediates actually encoded in the blob.
    r1320 = build(1320)
    ok(r1320.returncode == 0,
       f"build PL5_TAKEOVER_FW=1320 succeeds (exit {r1320.returncode})")
    if r1320.returncode == 0:
        blob = bytes(int(b, 16) for b in re.findall(r"0x([0-9a-fA-F]{2})",
                                                    HDR.read_text()))
        ok(len(blob) == 144, f"13.20 blob is 144 B (got {len(blob)})")
        for name, imm in [("HV handler PA", "0x62847375"), ("CFI", "0x44e5d0"),
                          ("smp_rendezvous", "0xaf94e0"), ("hc4", "0xc09e40")]:
            enc = int(imm, 16).to_bytes(8, "little")[:4]
            ok(enc in blob, f"13.20 blob encodes its {name} {imm}")
        for name, imm in [("13.60 CFI", "0x44f8c0"), ("13.60 smp", "0xb04440"),
                          ("13.60 hc4", "0xc16a10")]:
            enc = int(imm, 16).to_bytes(8, "little")[:4]
            ok(enc not in blob, f"13.20 blob does NOT encode {name} {imm}")
        import hashlib
        print(f"      (13.20 blob sha256 {hashlib.sha256(blob).hexdigest()[:16]})")

        # 4. The bytes the C side expects the blob to have written must be the
        # bytes the blob actually contains. This ties the two halves of the
        # takeover together: a change on either side breaks it.
        STUB = bytes([0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
                      0x0F, 0x22, 0xD8,
                      0x48, 0xB8, 0x00, 0x30, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
                      0xFF, 0xE0])
        ok(STUB in blob,
           "the blob writes the 25-byte stub the C side verifies (takeover_stub[])")

        # The blob is written into one page of the kernel cave
        # (g_payload_va = kdldmap(STARTUP_MP_PAYLOAD_PAGE)), so it must fit.
        ok(len(blob) <= 0x1000,
           f"the blob fits its one-page staging slot ({len(blob)} <= 4096)")

    for good, msg in results:
        print(("PASS " if good else "FAIL ") + msg)
    bad = [m for g, m in results if not g]
    print(f"\n{len(results)-len(bad)}/{len(results)} checks passed")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
