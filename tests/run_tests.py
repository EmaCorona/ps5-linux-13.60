#!/usr/bin/env python3
"""Host test suite for the 13.60 offline verifiers.

Runs without the PS5 SDK and without a console. Two lanes:

  * SYNTHETIC  -- always run. Small fixtures under a temp dir exercise the
    verifiers' logic: valid input, altered value, missing/extra symbol, missing
    field, wrong namespace class, absent input, wrong hash, wrong size.
  * REAL       -- opt-in (PL5_TEST_REAL_DUMP=1). Runs the dump verifier against
    the real community capture and against a one-byte-mutated copy. It is not
    distributed with the repo, so it cannot be a CI default.

The report states, per test, which lane it belongs to, so a PASS on a synthetic
fixture is never presented as verification of the real capture.

Usage:
    python3 tests/run_tests.py            # synthetic lane only
    PL5_TEST_REAL_DUMP=1 python3 tests/run_tests.py
"""
from __future__ import annotations

import ast
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TOOLS = ROOT / "tools"
DUMP = Path(os.environ.get("PL5_1360_DUMP",
                           "/home/emacorona/src/ps5-dumps/k1360.bin"))

results: list[tuple[str, str, bool, str]] = []   # (lane, name, passed, note)


def record(lane: str, name: str, passed: bool, note: str = "") -> None:
    results.append((lane, name, passed, note))
    print(f"[{'PASS' if passed else 'FAIL'}] ({lane}) {name}" + (f" -- {note}" if note else ""))


def run(argv: list[str], cwd: Path | None = None) -> tuple[int, str]:
    p = subprocess.run(argv, cwd=str(cwd) if cwd else None,
                       capture_output=True, text=True)
    return p.returncode, p.stdout + p.stderr


def have(cmd: str) -> bool:
    return shutil.which(cmd) is not None


def python_with_capstone() -> str | None:
    for cand in (sys.executable, str(ROOT / ".venv-rea/bin/python")):
        if Path(cand).exists() or cand == sys.executable:
            rc, _ = run([cand, "-c", "import capstone"])
            if rc == 0:
                return cand
    return None


# --------------------------------------------------------------------------
# SYNTHETIC lane: the off_1360 table verifier
# --------------------------------------------------------------------------

def off_1360_map() -> dict[str, list[str]]:
    """The verifier's symbol -> field map, read from its own source (AST)."""
    tree = ast.parse((TOOLS / "verify_off_1360.py").read_text())
    for node in tree.body:
        if isinstance(node, ast.Assign) and \
           any(isinstance(t, ast.Name) and t.id == "MAP" for t in node.targets):
            return ast.literal_eval(node.value)
    raise RuntimeError("MAP not found in verify_off_1360.py")


def parse_off_fields(src: str) -> dict[str, int]:
    return {m.group(1): int(m.group(2), 16)
            for m in re.finditer(r"\.(\w+)\s*=\s*(0x[0-9A-Fa-f]+|\d+)\s*,", src)}


def build_fixture(tmp: Path, sym_to_field: dict[str, list[str]]) -> tuple[Path, str]:
    """Copy the verifier and the files it reads into a temp repo skeleton.

    Returns (tmp_root, header_text) for the *valid* case.
    """
    for rel in ["tools/verify_off_1360.py", "source/offsets/off_1360.c",
                "source/offsets/off_1320.c", "include/offsets/offsets.h",
                "source/core/utils.c", "source/main.c"]:
        dst = tmp / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / rel, dst)
    off_vals = parse_off_fields((tmp / "source/offsets/off_1360.c").read_text())
    lines = []
    for sym, fields in sym_to_field.items():
        val = off_vals[fields[0]]
        lines.append(f"0x{val:X}, // {sym}")
    return tmp, "\n".join(lines) + "\n"


def run_off_verifier(tmp: Path, header: Path) -> tuple[int, str]:
    return run([sys.executable, str(tmp / "tools/verify_off_1360.py"), str(header)], cwd=tmp)


def synthetic_off_1360_tests(tmp: Path) -> None:
    sym_to_field = off_1360_map()
    fixture, valid_header = build_fixture(tmp / "base", sym_to_field)
    header = tmp / "13_60.h"
    header.write_text(valid_header)

    rc, _ = run_off_verifier(fixture, header)
    record("synth", "off_1360: valid table+header -> pass", rc == 0, f"exit {rc}")

    # altered value
    bad = re.sub(r"0x[0-9A-Fa-f]+, // KERNEL_SYM_PMAP_STORE",
                 "0x1, // KERNEL_SYM_PMAP_STORE", valid_header)
    h2 = tmp / "h_alt.h"; h2.write_text(bad)
    rc, out = run_off_verifier(fixture, h2)
    record("synth", "off_1360: altered value -> fail", rc == 1 and "mismatch" in out,
           f"exit {rc}")

    # missing symbol in header
    h3 = tmp / "h_missing.h"
    h3.write_text("\n".join(l for l in valid_header.splitlines()
                            if "KERNEL_SYM_PMAP_STORE" not in l) + "\n")
    rc, out = run_off_verifier(fixture, h3)
    record("synth", "off_1360: header missing a symbol -> fail",
           rc == 1 and "missing expected symbol" in out, f"exit {rc}")

    # extra (unmapped) symbol in header
    h4 = tmp / "h_extra.h"; h4.write_text(valid_header + "0x1, // NOT_A_REAL_SYM\n")
    rc, out = run_off_verifier(fixture, h4)
    record("synth", "off_1360: header has an unmapped symbol -> fail",
           rc == 1 and "not mapped" in out, f"exit {rc}")

    # absent header
    rc, out = run_off_verifier(fixture, tmp / "does_not_exist.h")
    record("synth", "off_1360: absent header -> exit 2",
           rc == 2 and "not found" in out, f"exit {rc}")

    # KERNEL_CODE_CAVE aliased to a data address
    cave = tmp / "cave"
    shutil.copytree(fixture, cave, dirs_exist_ok=True)
    p = cave / "source/offsets/off_1360.c"
    p.write_text(re.sub(r"(\.KERNEL_CODE_CAVE\s*=\s*)0[xX]?[0-9A-Fa-f]*",
                        r"\g<1>0x2D39000", p.read_text()))
    rc, out = run_off_verifier(cave, header)
    record("synth", "off_1360: KERNEL_CODE_CAVE != 0 -> fail",
           rc == 1 and "KERNEL_CODE_CAVE must be 0" in out, f"exit {rc}")

    # required field zeroed
    zero = tmp / "zero"
    shutil.copytree(fixture, zero, dirs_exist_ok=True)
    p = zero / "source/offsets/off_1360.c"
    p.write_text(re.sub(r"(\.FUN_SMP_RENDEZVOUS\s*=\s*)0[xX]?[0-9A-Fa-f]*",
                        r"\g<1>0", p.read_text()))
    rc, out = run_off_verifier(zero, header)
    record("synth", "off_1360: required field reset to 0 -> fail",
           rc == 1 and "required (non-placeholder)" in out, f"exit {rc}")

    # field set diverges from off_1320
    drift = tmp / "drift"
    shutil.copytree(fixture, drift, dirs_exist_ok=True)
    p = drift / "source/offsets/off_1360.c"
    p.write_text(re.sub(r"^\s*\.GAD_IRETQ\s*=.*\n", "", p.read_text(), flags=re.M))
    rc, out = run_off_verifier(drift, header)
    record("synth", "off_1360: field set != off_1320 -> fail",
           rc == 1 and "differs from off_1320.c" in out, f"exit {rc}")


# --------------------------------------------------------------------------
# SYNTHETIC lane: the dump verifier's input handling (no real capture)
# --------------------------------------------------------------------------

def synthetic_dump_input_tests(tmp: Path, py: str | None) -> None:
    script = TOOLS / "verify_off_1360_dump.py"

    rc, out = run([sys.executable, str(script), str(tmp / "absent.bin")])
    record("synth", "dump: absent input -> exit 2",
           rc == 2 and "not found" in out, f"exit {rc}")

    if py is None:
        record("synth", "dump: wrong hash -> exit 2", False, "SKIP: capstone unavailable")
        record("synth", "dump: wrong size -> exit 2", False, "SKIP: capstone unavailable")
        return

    small = tmp / "small.bin"
    small.write_bytes(b"\x00" * 4096)
    rc, out = run([py, str(script), str(small)])
    record("synth", "dump: wrong hash -> exit 2",
           rc == 2 and "sha256 mismatch" in out, f"exit {rc}")

    import hashlib
    good = hashlib.sha256(small.read_bytes()).hexdigest()
    rc, out = run([py, str(script), str(small), "--sha256", good])
    record("synth", "dump: hash ok but wrong size -> exit 2",
           rc == 2 and "unexpected dump size" in out, f"exit {rc}")


# --------------------------------------------------------------------------
# SYNTHETIC lane: the takeover blob parameter guard
# --------------------------------------------------------------------------

def synthetic_takeover_tests() -> None:
    if not all(have(c) for c in ("gcc", "make", "objcopy")):
        record("synth", "takeover: parameter guard", False, "SKIP: gcc/make/objcopy missing")
        return
    rc, out = run([sys.executable, str(TOOLS / "verify_takeover_param.py")], cwd=ROOT)
    record("synth", "takeover: parameter guard (blob + 1360 refusal)", rc == 0,
           f"exit {rc}")

    # the guard must not be removable by a 1360 build alone
    rc, out = run(["make", "-B", "-C", str(ROOT / "source/shellcode/hv_takeover"),
                   "PL5_TAKEOVER_FW=1360"], cwd=ROOT)
    record("synth", "takeover: 1360 build refused (make -B)", rc != 0 and
           "HV_VMMCALL_HANDLER_PA is unknown" in out, f"exit {rc}")


# --------------------------------------------------------------------------
# REAL lane (opt-in): the actual capture
# --------------------------------------------------------------------------

def real_capture_tests(tmp: Path, py: str | None) -> None:
    if os.environ.get("PL5_TEST_REAL_DUMP") != "1":
        record("real", "dump: full verification on the real capture", False,
               "SKIP: set PL5_TEST_REAL_DUMP=1 (capture is not vendored)")
        record("real", "dump: one mutated byte is caught", False,
               "SKIP: set PL5_TEST_REAL_DUMP=1")
        return
    if py is None:
        record("real", "dump: full verification on the real capture", False,
               "SKIP: capstone unavailable")
        return
    if not DUMP.is_file():
        record("real", "dump: full verification on the real capture", False,
               f"SKIP: {DUMP} not found")
        return

    script = TOOLS / "verify_off_1360_dump.py"
    rc, out = run([py, str(script), str(DUMP)])
    record("real", "dump: full verification on the real capture", rc == 0, f"exit {rc}")

    import hashlib
    mutated = tmp / "mutated.bin"
    data = bytearray(DUMP.read_bytes())
    data[0x255034] ^= 0xFF            # corrupt the first byte of GAD_WRMSR_RET
    mutated.write_bytes(data)
    sha = hashlib.sha256(bytes(data)).hexdigest()
    rc, out = run([py, str(script), str(mutated), "--sha256", sha])
    record("real", "dump: one mutated byte is caught",
           rc == 1 and "GAD_WRMSR_RET" in out and "FAIL" in out, f"exit {rc}")


def synthetic_make_flag_tests() -> None:
    """A changed build flag must regenerate the blob with no explicit clean.

    Uses the `shellcode/hv` sub-make: it is host-gcc only, so the check needs no
    PS5 SDK. Before the configuration stamp existed, `make PL5_HV_STOP=1` after a
    `PL5_HV_STOP=0` build silently reused the objects and produced the same blob.
    """
    import hashlib

    name = "make: flag switch rebuilds the blob (no clean)"
    d = ROOT / "source" / "shellcode" / "hv"
    hdr = d / "shellcode_hv.h"
    if not (d / "Makefile").is_file():
        record("synth", name, False, "SKIP: shellcode/hv not present")
        return
    if not (have("make") and have("gcc") and have("ld") and have("objcopy")):
        record("synth", name, False, "SKIP: make/gcc/ld/objcopy unavailable")
        return

    def sha() -> str:
        return hashlib.sha256(hdr.read_bytes()).hexdigest()[:16] if hdr.is_file() else ""

    def make(stop: str) -> int:
        return run(["make", "-C", str(d), f"PL5_HV_STOP={stop}"])[0]

    run(["make", "-C", str(d), "clean"])
    (d / ".pl5-config.stamp").unlink(missing_ok=True)

    rc0 = make("0")
    h0 = sha()
    rc1 = make("1")            # deliberately no clean in between
    h1 = sha()
    rc2 = make("0")            # and back
    h2 = sha()
    run(["make", "-C", str(d), "clean"])

    ok = rc0 == rc1 == rc2 == 0 and h0 and h0 != h1 and h2 == h0
    record("synth", name, ok, f"0:{h0 or 'none'} 1:{h1 or 'none'} back:{h2 or 'none'}")

    # clean-objs must be phony: a stray file of that name would disable it.
    mk = (ROOT / "Makefile").read_text()
    phony = next((l for l in mk.splitlines() if l.startswith(".PHONY:")), "")
    record("synth", "make: clean-objs is declared .PHONY",
           "clean-objs" in phony.split(), phony.strip())

    # The top-level Makefile must key the objects on the configuration stamp.
    # (There is more than one `$(OBJS):` rule — the static pattern rule comes
    # first — so look for any of them carrying the stamp.)
    record("synth", "make: top-level objects follow the config stamp",
           "PL5_CONFIG_STAMP" in mk and any(
               l.startswith("$(OBJS):") and "PL5_CONFIG_STAMP" in l
               for l in mk.splitlines()),
           "stamp wired into an OBJS rule")


def package_lane_tests(tmp: Path) -> None:
    """Checks on a *built* payload ELF: opt-in (PL5_TEST_ELF=1).

    The default suite must not depend on a payload build (it needs the PS5 SDK),
    so this lane is separate; the CI build job runs the checker for real.
    """
    name = "payload: built ELF passes the static checks"
    if os.environ.get("PL5_TEST_ELF") != "1":
        for n in (name,
                  "payload: truncated file is refused (exit 2)",
                  "payload: missing version string is caught (exit 1)",
                  "payload: unknown takeover firmware is refused (exit 2)"):
            record("package", n, False, "SKIP: set PL5_TEST_ELF=1 (needs a built payload)")
        return

    tool = TOOLS / "check_payload_static.py"
    elf = ROOT / "bin/pLinux5-NG.elf"
    if not elf.is_file():
        record("package", name, False, f"SKIP: {elf} not built")
        return

    rc, out = run([sys.executable, str(tool)])
    record("package", name, rc == 0, f"exit {rc}")

    truncated = tmp / "truncated.elf"
    truncated.write_bytes(elf.read_bytes()[:32])
    rc, _ = run([sys.executable, str(tool), "--elf", str(truncated)])
    record("package", "payload: truncated file is refused (exit 2)", rc == 2, f"exit {rc}")

    # Blank the version string: the ELF is still an ELF, but it is not the
    # artifact this tree claims to build.
    data = elf.read_bytes().replace(b"0.1.0\x00", b"9.9.9\x00")
    mutated = tmp / "wrong-version.elf"
    mutated.write_bytes(data)
    rc, out = run([sys.executable, str(tool), "--elf", str(mutated)])
    record("package", "payload: missing version string is caught (exit 1)",
           rc == 1 and "version" in out, f"exit {rc}")

    rc, _ = run([sys.executable, str(tool), "--takeover-fw", "1360", "--takeover", "1"])
    record("package", "payload: unknown takeover firmware is refused (exit 2)",
           rc == 2, f"exit {rc}")


def synthetic_registry_tests(tmp: Path) -> None:
    """The offset registry must fail when it drifts from the C table or a value
    breaks its namespace. Each case runs the checker in a throwaway tree that
    mirrors tools/ + source/offsets/ so ROOT resolves there."""
    import json
    import shutil

    def tree(name: str) -> Path:
        t = tmp / name
        (t / "tools").mkdir(parents=True)
        (t / "source" / "offsets").mkdir(parents=True)
        shutil.copy(ROOT / "tools/check_offset_registry.py", t / "tools/")
        shutil.copy(ROOT / "tools/offset_registry.json", t / "tools/")
        shutil.copy(ROOT / "source/offsets/off_1360.c", t / "source/offsets/")
        shutil.copy(ROOT / "Makefile", t / "Makefile")
        return t

    def run_in(t: Path) -> tuple[int, str]:
        return run([sys.executable, str(t / "tools/check_offset_registry.py")])

    def edit(t: Path, mutate) -> None:
        p = t / "tools/offset_registry.json"
        reg = json.loads(p.read_text())
        mutate(reg)
        p.write_text(json.dumps(reg, indent=2))

    base = tree("reg-base")
    rc, out = run_in(base)
    record("synth", "registry: unmodified tree passes", rc == 0, f"exit {rc}")

    t = tree("reg-drift")
    edit(t, lambda r: r["entries"][4].__setitem__("value", "0x1"))
    rc, out = run_in(t)
    record("synth", "registry: value drift vs the C table is caught",
           rc == 1 and "equal the C table" in out, f"exit {rc}")

    t = tree("reg-unknown")

    def non_zero_unknown(r):
        for e in r["entries"]:
            if e["class"] == "UNKNOWN":
                e["value"] = "0x1000"
                break
    edit(t, non_zero_unknown)
    rc, out = run_in(t)
    record("synth", "registry: an UNKNOWN field with a value is caught",
           rc == 1 and "carries no value" in out, f"exit {rc}")

    t = tree("reg-namespace")

    def hv_as_ktext(r):
        for e in r["entries"]:
            if e["field"] == "KERNEL_CFM_CHECK":  # never matches
                pass
            if e["field"] == "FUN_SMP_RENDEZVOUS":
                e["value"] = "0xCE0000"     # one past the text image
    edit(t, hv_as_ktext)
    rc, out = run_in(t)
    record("synth", "registry: a value outside its namespace is caught",
           rc == 1 and "inside the kernel text image" in out, f"exit {rc}")

    t = tree("reg-missing")
    edit(t, lambda r: r["entries"].pop())
    rc, out = run_in(t)
    record("synth", "registry: a field missing from the registry is caught",
           rc == 1 and "same fields" in out, f"exit {rc}")


def main() -> int:
    print(f"py={sys.executable}  capstone_py={python_with_capstone()}  repo={ROOT}\n")
    with tempfile.TemporaryDirectory(prefix="pl5-tests-") as td:
        tmp = Path(td)
        synthetic_off_1360_tests(tmp)
        synthetic_dump_input_tests(tmp, python_with_capstone())
        synthetic_takeover_tests()
        # Package lane before the make lane: the make lane deliberately rebuilds
        # and then cleans source/shellcode/hv, which would leave the tree without
        # the blob the payload check expects.
        package_lane_tests(tmp)
        synthetic_make_flag_tests()
        synthetic_registry_tests(tmp)
        real_capture_tests(tmp, python_with_capstone())

    synth = [r for r in results if r[0] == "synth"]
    real = [r for r in results if r[0] == "real"]
    pack = [r for r in results if r[0] == "package"]
    failed = [r for r in results if not r[2] and "SKIP" not in r[3]]
    skipped = [r for r in results if not r[2] and "SKIP" in r[3]]
    print(f"\nsummary: synthetic {sum(1 for r in synth if r[2])}/{len(synth)} passed; "
          f"real {sum(1 for r in real if r[2])}/{len(real)} passed; "
          f"package {sum(1 for r in pack if r[2])}/{len(pack)} passed; "
          f"{len(skipped)} skipped")
    for lane, name, _, note in results:
        if not results_ok(lane, name):
            print(f"  FAIL ({lane}) {name} -- {note}")
    print("\nNOTE: synthetic fixtures validate the verifiers' logic only; they do "
          "not verify the community capture. The REAL lane must be run by hand.")
    return 1 if failed else 0


def results_ok(lane: str, name: str) -> bool:
    for l, n, p, note in results:
        if l == lane and n == name:
            return p or "SKIP" in note
    return True


if __name__ == "__main__":
    sys.exit(main())
