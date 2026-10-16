#!/usr/bin/env python3
"""Validate the typed offset registry against the C table and its namespaces.

The registry (`tools/offset_registry.json`) states, per field, which namespace the
value lives in — `KTEXT_REL`, `KDATA_REL`, `HV_REL`, `PHYSICAL`, `STRUCT_OFF` —
plus its evidence class and provenance. This tool enforces that:

  * the registry and `source/offsets/off_1360.c` describe the same fields with the
    same values (no drift in either direction);
  * every value obeys the range its namespace implies (a ktext-relative value
    inside the kernel text image, a data value beyond it, a page-aligned physical
    address, a small struct offset);
  * no field with an `UNKNOWN`/`NOT_REQUIRED_FOR_1360_PATH` class carries a
    non-zero value, and no `KNOWN_*` field carries zero — a value is never "valid
    because it is not zero";
  * the same numeric value is not described with two different namespaces.

`DISPUTED` entries are reported as warnings, not failures: the registry's job is
to make the contradiction visible, and the dispute itself is the finding.

Exit codes:
    0   every check ran and passed (warnings may have been printed)
    1   at least one check failed
    2   unusable input
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

NAMESPACES = {"KTEXT_REL", "KDATA_REL", "HV_REL", "PHYSICAL", "STRUCT_OFF", "NONE"}
CLASSES = {"KNOWN_STATIC", "KNOWN_HARDWARE_VALIDATED", "UNKNOWN",
           "NOT_REQUIRED_FOR_1360_PATH", "DISPUTED"}
ZERO_CLASSES = {"UNKNOWN", "NOT_REQUIRED_FOR_1360_PATH"}
KNOWN_CLASSES = {"KNOWN_STATIC", "KNOWN_HARDWARE_VALIDATED"}

fails = 0
warns = 0


def ok(good: bool, msg: str) -> None:
    global fails
    if not good:
        fails += 1
    print(f"{'PASS' if good else 'FAIL'} {msg}")


def warn(msg: str) -> None:
    global warns
    warns += 1
    print(f"WARN {msg}")


def parse_c_table(path: Path) -> dict[str, int]:
    """field -> value, from the designated initialisers of off_1360."""
    out: dict[str, int] = {}
    for m in re.finditer(r"\.(\w+)\s*=\s*(0[xX][0-9a-fA-F]+|\d+)\s*[,}]", path.read_text()):
        out[m.group(1)] = int(m.group(2), 0)
    return out


def check_shape(entry: dict, i: int) -> bool:
    missing = [k for k in ("field", "namespace", "class", "value", "used_by",
                           "provenance", "verified_by") if k not in entry]
    if missing:
        ok(False, f"entry[{i}]: missing keys {missing}")
        return False
    if entry["namespace"] not in NAMESPACES:
        ok(False, f"{entry['field']}: unknown namespace {entry['namespace']!r}")
        return False
    if entry["class"] not in CLASSES:
        ok(False, f"{entry['field']}: unknown class {entry['class']!r}")
        return False
    if not isinstance(entry["value"], str):
        ok(False, f"{entry['field']}: value must be a hex string")
        return False
    return True


def check_namespace(entry: dict, value: int, text_len: int) -> None:
    ns, cls, name = entry["namespace"], entry["class"], entry["field"]
    if ns == "KTEXT_REL" and value:
        ok(0 < value < text_len,
           f"{name}: KTEXT_REL 0x{value:x} is inside the kernel text image (< 0x{text_len:x})")
    if ns == "KDATA_REL" and value:
        ok(value >= text_len,
           f"{name}: KDATA_REL 0x{value:x} is beyond the text image (>= 0x{text_len:x})")
    if ns == "PHYSICAL" and value:
        ok(value % 0x1000 == 0, f"{name}: PHYSICAL 0x{value:x} is page-aligned")
    if ns == "STRUCT_OFF" and value:
        ok(value < 0x1000, f"{name}: STRUCT_OFF 0x{value:x} is a small struct offset")
    if cls in ZERO_CLASSES:
        ok(value == 0, f"{name}: {cls} carries no value (0x{value:x})")
    if cls in KNOWN_CLASSES:
        ok(value != 0, f"{name}: {cls} has a value (no zero treated as known)")
    if cls == "DISPUTED":
        warn(f"{name}: DISPUTED value 0x{value:x} - {entry['provenance']}")


def main() -> int:
    reg_path = ROOT / "tools/offset_registry.json"
    c_path = ROOT / "source/offsets/off_1360.c"
    for p in (reg_path, c_path):
        if not p.is_file():
            print(f"REFUSE {p}: not found", file=sys.stderr)
            return 2

    reg = json.loads(reg_path.read_text())
    text_len = int(reg["artifact"]["text_length"], 0)
    entries = reg["entries"]
    print(f"registry: {len(entries)} entries; artifact {reg['artifact']['name']} "
          f"sha256 {reg['artifact']['sha256'][:8]}...")

    dup = [e["field"] for e in entries if [x["field"] for x in entries].count(e["field"]) > 1]
    ok(not dup, f"registry: field names are unique{'' if not dup else ' -> ' + str(sorted(set(dup)))}")

    valid = [e for i, e in enumerate(entries) if check_shape(e, i)]
    ok(len(valid) == len(entries), "registry: every entry has the required keys and vocabulary")

    cvals = parse_c_table(c_path)
    reg_fields = {e["field"] for e in valid}
    c_fields = set(cvals)
    ok(reg_fields == c_fields,
       "registry and off_1360.c describe the same fields"
       + ('' if reg_fields == c_fields else
          f" (only-registry={sorted(reg_fields - c_fields)}, only-c={sorted(c_fields - reg_fields)})"))

    mismatched = [e["field"] for e in valid
                  if e["field"] in cvals and cvals[e["field"]] != int(e["value"], 0)]
    ok(not mismatched, f"registry values equal the C table{'' if not mismatched else ' -> ' + str(mismatched)}")

    for e in valid:
        check_namespace(e, int(e["value"], 0), text_len)

    # One value, one namespace: a number must not be both a ktext offset and an
    # HV-relative offset, which is exactly the confusion that powered the console
    # off (HV_SYM_HEAP_BASE / HV_SYM_PCPUS are < .text length).
    by_value: dict[int, set[str]] = {}
    for e in valid:
        v = int(e["value"], 0)
        if v and e["namespace"] != "NONE":
            by_value.setdefault(v, set()).add(e["namespace"])
    clashy = {v: ns for v, ns in by_value.items() if len(ns) > 1}
    ok(not clashy, f"no value is claimed in two namespaces{'' if not clashy else ' -> ' + str(clashy)}")

    # The one thing phase B depends on and does not have.
    hv = [r for r in reg.get("takeover_requirements", [])
          if r.get("firmware") == "13.60" and r["namespace"] == "PHYSICAL"]
    unknown = [r["name"] for r in hv if not r.get("value")]
    mk = (ROOT / "Makefile").read_text()
    default_off = re.search(r"^PL5_1360_TAKEOVER\s*\?=\s*0\s*$", mk, re.M) is not None
    ok(bool(unknown) and default_off,
       f"phase B stays off while its HV reference is unknown "
       f"({', '.join(unknown) or 'none listed'}; PL5_1360_TAKEOVER default 0: {default_off})")

    print(f"\n{fails} check(s) failed, {warns} warning(s)")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
