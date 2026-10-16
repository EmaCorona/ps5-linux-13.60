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
    # Bring the tree to a consistent default build first: the make lane below
    # deliberately cleans source/shellcode/hv, so a leftover tree would make the
    # payload check fail for the wrong reason.
    rc, out = run(["make", "-j4"], cwd=ROOT)
    if rc != 0:
        record("package", name, False, f"SKIP: default build failed (exit {rc})")
        return
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

    # Phase B must be impossible to enable while its HV reference is a
    # placeholder, in every configuration we can name.
    if not os.environ.get("PS5_PAYLOAD_SDK", ""):
        record("package", "phase B: PL5_1360_TAKEOVER=1 refused",
               False, "SKIP: PS5_PAYLOAD_SDK not set")
        record("package", "phase B: foreign blob on a 1360 build refused",
               False, "SKIP: PS5_PAYLOAD_SDK not set")
        return
    for name, extra in (("phase B: PL5_1360_TAKEOVER=1 refused",
                         ["PL5_1360_TAKEOVER=1"]),
                        ("phase B: foreign blob on a 1360 build refused",
                         ["PL5_1360_TAKEOVER=1", "PL5_TAKEOVER_FW=1360"])):
        rc, out = run(["make", "-B", *extra], cwd=ROOT)
        refused = rc != 0 and ("#error" in out or "error:" in out)
        record("package", name, refused,
               f"exit {rc}" if refused else "build did NOT fail")


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


def synthetic_policy_tests(tmp: Path) -> None:
    """The live-read policy must refuse before any read, and the payload must use
    it. Compiled and executed on the host: no console involved."""
    header = ROOT / "include/tools/pl5_dump_policy.h"
    if not header.is_file():
        record("synth", "policy: header present", False, "SKIP: missing")
        return

    prog = tmp / "policy_probe.c"
    prog.write_text(
        '#include "tools/pl5_dump_policy.h"\n'
        '#include <stdio.h>\n'
        'int main(void) {\n'
        '  struct { const char *n; int got; int want; } c[] = {\n'
        '    {"1360 .text committed", pl5_decide(0x1360, 0x1360, PL5_REG_TEXT, 1), PL5_REFUSE_FW_TEXT},\n'
        '    {"1360 .data committed", pl5_decide(0x1360, 0x1360, PL5_REG_DATA, 1), PL5_ALLOW},\n'
        '    {"1360 .text via 1320 tables", pl5_decide(0x1360, 0x1320, PL5_REG_TEXT, 1), PL5_REFUSE_FW_MISMATCH},\n'
        '    {"1320 .text uncommitted", pl5_decide(0x1320, 0x1320, PL5_REG_TEXT, 0), PL5_REFUSE_NOT_COMMITTED},\n'
        '    {"1320 .text committed", pl5_decide(0x1320, 0x1320, PL5_REG_TEXT, 1), PL5_ALLOW},\n'
        '    {"1320 hv committed", pl5_decide(0x1320, 0x1320, PL5_REG_HV, 1), PL5_ALLOW},\n'
        '  };\n'
        '  int rc = 0;\n'
        '  for (unsigned i = 0; i < sizeof c / sizeof c[0]; i++) {\n'
        '    printf("%s: %s\\n", c[i].n, c[i].got == c[i].want ? "ok" : "BAD");\n'
        '    if (c[i].got != c[i].want) rc = 1;\n'
        '  }\n'
        '  printf("is_fatal(1360)=%d is_fatal(1320)=%d\\n",\n'
        '         pl5_text_read_is_fatal(0x1360), pl5_text_read_is_fatal(0x1320));\n'
        '  if (!pl5_text_read_is_fatal(0x1360) || pl5_text_read_is_fatal(0x1320)) rc = 1;\n'
        '  return rc;\n'
        '}\n')
    if not have("gcc"):
        record("synth", "policy: refusals before any read", False, "SKIP: gcc unavailable")
        return
    exe = tmp / "policy_probe"
    rc, out = run(["gcc", "-std=c11", "-I", str(ROOT / "include"),
                   str(prog), "-o", str(exe)])
    if rc != 0:
        record("synth", "policy: refusals before any read", False, f"compile failed: {out.strip()[:80]}")
        return
    rc, out = run([str(exe)])
    bad = [l for l in out.splitlines() if l.endswith("BAD")]
    record("synth", "policy: refusals before any read", rc == 0 and not bad,
           "; ".join(bad) if bad else "6 decisions + fatal-firmware check")

    # The policy must be wired into the payload, not just exist.
    src = (ROOT / "tools/pl5-offsets.c").read_text()
    record("synth", "policy: pl5-offsets.c applies it before reading",
           "pl5_decide(" in src and "PL5_COMMIT_MARKER" in src
           and src.index("pl5_decide(") < src.index("pl5_dump_offsets") + 4000,
           "gate is at the top of pl5_dump_offsets()")


def synthetic_hook_state_tests(tmp: Path) -> None:
    """The hook's state machine and its adoption rule, compiled and run on the
    host. No console, no SDK: khook_state.h is freestanding."""
    if not have("gcc"):
        record("synth", "hook state: transitions and adoption", False, "SKIP: gcc unavailable")
        return
    prog = tmp / "kh_state_probe.c"
    prog.write_text(
        '#include "byepervisor/khook_state.h"\n'
        '#include <stdio.h>\n'
        'static int bad = 0;\n'
        '#define EXPECT(cond, label) do { if (!(cond)) { printf("BAD %s\\n", label); bad++; } } while (0)\n'
        'int main(void) {\n'
        '  enum kh_state n;\n'
        '  enum kh_state s = KH_ST_UNINITIALIZED;\n'
        '  EXPECT(!kh_state_is_live(s), "uninitialized not live");\n'
        '  EXPECT(kh_state_next(s, KH_EV_INIT, &n) && n == KH_ST_STAGED, "init->staged");\n'
        '  s = n;\n'
        '  EXPECT(kh_state_next(s, KH_EV_ARM, &n) && n == KH_ST_ARMED, "staged->armed");\n'
        '  s = n;\n'
        '  EXPECT(kh_state_is_live(s), "armed is live");\n'
        '  EXPECT(kh_state_next(s, KH_EV_TRAP_OURS, &n) && n == KH_ST_TRIGGERED, "armed->triggered");\n'
        '  s = n;\n'
        '  EXPECT(kh_state_next(s, KH_EV_DISARM, &n) && n == KH_ST_RESTORED, "triggered->restored");\n'
        '  s = n;\n'
        '  EXPECT(!kh_state_is_live(s), "restored not live");\n'
        '  EXPECT(kh_state_next(s, KH_EV_ARM, &n) && n == KH_ST_ARMED, "restored->armed");\n'
        '  /* refusals */\n'
        '  EXPECT(!kh_state_next(KH_ST_UNINITIALIZED, KH_EV_ARM, &n), "cannot arm from uninitialized");\n'
        '  EXPECT(!kh_state_next(KH_ST_STAGED, KH_EV_TRAP_OURS, &n), "no our-trap while staged");\n'
        '  EXPECT(!kh_state_next(KH_ST_ARMED, KH_EV_TRAP_FOREIGN, &n), "foreign trap is not a state");\n'
        '  EXPECT(!kh_state_next(KH_ST_UNINITIALIZED, KH_EV_ERROR, &n), "no error before init");\n'
        '  /* failure is recoverable, and clean-up is still owed */\n'
        '  EXPECT(kh_state_next(KH_ST_ARMED, KH_EV_ERROR, &n) && n == KH_ST_FAILED, "armed->failed");\n'
        '  EXPECT(kh_state_next(KH_ST_FAILED, KH_EV_RESTORE, &n) && n == KH_ST_RESTORED, "failed->restored");\n'
        '  EXPECT(kh_state_next(KH_ST_FAILED, KH_EV_INIT, &n) && n == KH_ST_STAGED, "failed->staged");\n'
        '  /* adoption needs all four conditions */\n'
        '  EXPECT(kh_marker_adopt(KH_MARKER_MAGIC, 0, 1, 0) == KH_ADOPT_DISABLED, "disabled by default");\n'
        '  EXPECT(kh_marker_adopt(0, 1, 1, 1) == KH_ADOPT_NO_MARKER, "marker must match");\n'
        '  EXPECT(kh_marker_adopt(KH_MARKER_MAGIC, 0, 1, 1) == KH_ADOPT_EPOCH_MISMATCH, "epoch required");\n'
        '  EXPECT(kh_marker_adopt(KH_MARKER_MAGIC, 1, 0, 1) == KH_ADOPT_NO_EVIDENCE, "live evidence required");\n'
        '  EXPECT(kh_marker_adopt(KH_MARKER_MAGIC, 1, 1, 1) == KH_ADOPT_OK, "all four -> adopt");\n'
        '  printf(bad ? "BAD %d checks\\n" : "ok\\n", bad);\n'
        '  return bad != 0;\n'
        '}\n')
    exe = tmp / "kh_state_probe"
    rc, out = run(["gcc", "-std=c11", "-I", str(ROOT / "include"), str(prog), "-o", str(exe)])
    if rc != 0:
        record("synth", "hook state: transitions and adoption", False, f"compile failed: {out.strip()[:80]}")
        return
    rc, out = run([str(exe)])
    bad = [l for l in out.splitlines() if l.startswith("BAD")]
    record("synth", "hook state: transitions and adoption", rc == 0 and not bad,
           "; ".join(bad) if bad else "21 assertions")

    src = (ROOT / "source/hv/defeat/hv_defeat_1360.c").read_text()
    record("synth", "hook state: adoption is opt-in and the marker alone is not enough",
           "kh_marker_adopt(" in src and "PL5_1360_ADOPT_ARMED 0" in src,
           "default disabled; epoch not published")


def synthetic_boot_data_tests(tmp: Path) -> None:
    """The Linux hand-off arithmetic and its refusal cases, compiled and run on the
    host. include/boot/boot_data.h is freestanding, so this needs no SDK."""
    if not have("gcc"):
        record("synth", "boot data: hand-off checks", False, "SKIP: gcc unavailable")
        return
    prog = tmp / "boot_data_probe.c"
    prog.write_text(
        '#include "boot/boot_data.h"\n'
        '#include <stdio.h>\n'
        'static int bad;\n'
        '#define EXP(cond, label) do { if (!(cond)) { printf("BAD %s\\n", label); bad++; } } while (0)\n'
        'static struct pl5_boot_facts base(void) {\n'
        '  struct pl5_boot_facts f = {0};\n'
        '  f.bzimage_size = 0x3000; f.initrd_size = 0x2000; f.cmdline_len = 120;\n'
        '  f.hdr_magic = PL5_SETUP_HDR_MAGIC; f.hdr_version = 0x020f;\n'
        '  f.boot_flag = PL5_BOOT_FLAG;\n'
        '  f.cave_start = 0x1000; f.cave_end = 0x1000 + 64u * 1024 * 1024;\n'
        '  f.initrd_offset = 0x3000; f.page_size = 4096;\n'
        '  return f; }\n'
        'int main(void) {\n'
        '  struct pl5_boot_facts f;\n'
        '  f = base(); EXP(pl5_boot_check_data(&f) == PL5_BOOT_OK, "valid layout");\n'
        '  f = base(); f.bzimage_size = 0; EXP(pl5_boot_check_data(&f) == PL5_BOOT_MISSING, "missing bzImage");\n'
        '  f = base(); f.bzimage_size = 512; EXP(pl5_boot_check_data(&f) == PL5_BOOT_TOO_SMALL, "tiny bzImage");\n'
        '  f = base(); f.hdr_magic = 0; EXP(pl5_boot_check_data(&f) == PL5_BOOT_BAD_MAGIC, "not a bzImage");\n'
        '  f = base(); f.boot_flag = 0; EXP(pl5_boot_check_data(&f) == PL5_BOOT_BAD_MAGIC, "bad boot flag");\n'
        '  f = base(); f.hdr_version = 0x0100; EXP(pl5_boot_check_data(&f) == PL5_BOOT_BAD_PROTOCOL, "old protocol");\n'
        '  f = base(); f.cmdline_len = 2048; EXP(pl5_boot_check_data(&f) == PL5_BOOT_CMDLINE_TOO_LONG, "cmdline too long");\n'
        '  f = base(); f.initrd_offset = 0x2000; EXP(pl5_boot_check_data(&f) == PL5_BOOT_INITRD_OVERLAP, "overlapping images");\n'
        '  f = base(); f.initrd_size = 0x2001; EXP(pl5_boot_check_data(&f) == PL5_BOOT_UNALIGNED, "unaligned initrd");\n'
        '  f = base(); f.cave_end = f.cave_start + 0x1000; EXP(pl5_boot_check_data(&f) == PL5_BOOT_NO_ROOM, "images do not fit");\n'
        '  f = base(); f.initrd_size = 0;\n'
        '    EXP(pl5_boot_check_data(&f) == PL5_BOOT_OK, "no initrd is allowed");\n'
        '  f = base(); f.page_size = 0; EXP(pl5_boot_check_data(&f) == PL5_BOOT_MISSING, "bad page size");\n'
        '  printf(bad ? "BAD %d\\n" : "ok\\n", bad);\n'
        '  return bad != 0; }\n')
    exe = tmp / "boot_data_probe"
    rc, out = run(["gcc", "-std=c11", "-I", str(ROOT / "include"), str(prog), "-o", str(exe)])
    if rc != 0:
        record("synth", "boot data: hand-off checks", False, f"compile failed: {out.strip()[:80]}")
        return
    rc, out = run([str(exe)])
    bad = [l for l in out.splitlines() if l.startswith("BAD")]
    record("synth", "boot data: hand-off checks", rc == 0 and not bad,
           "; ".join(bad) if bad else "12 cases")

    src = (ROOT / "source/boot/loader.c").read_text()
    record("synth", "boot data: loader refuses bad input before staging",
           "pl5_boot_check_data(" in src and "long bzimage_size_l" in src
           and "long initrd_size_l" in src,
           "size checks use long, validation runs before staging")


def synthetic_frame_contract_tests(tmp: Path) -> None:
    """The #DB frame layout and the pivot contract, run on the host.

    Guards the discrepancy found in review: the pivot field is named
    GAD_ADD_RSP_28_POP_RBP_RET but the verified bytes are 'add rsp,0x28; rep ret'.
    """
    if not have("gcc"):
        record("synth", "frame: #DB layout and pivot contract", False, "SKIP: gcc unavailable")
        return
    prog = tmp / "frame_probe.c"
    prog.write_text(
        '#include "byepervisor/khook_frame.h"\n'
        '#include <stdio.h>\n'
        'static int bad;\n'
        '#define EXP(c, l) do { if (!(c)) { printf("BAD %s\\n", l); bad++; } } while (0)\n'
        'int main(void) {\n'
        '  unsigned char fr[0x28];\n'
        '  for (int i = 0; i < 0x28; i++) fr[i] = 0;\n'
        '  uint64_t vals[5] = {0xAABBCCDDEEFF0011ULL, 0x33ULL, 0x202ULL, 0x7FF000ULL, 0x2BULL};\n'
        '  for (int i = 0; i < 5; i++)\n'
        '    for (int b = 0; b < 8; b++) fr[i*8+b] = (unsigned char)(vals[i] >> (8*b));\n'
        '  struct kh_frame f;\n'
        '  kh_frame_parse(fr, &f);\n'
        '  EXP(f.rip == vals[0], "RIP at +0");\n'
        '  EXP(f.cs == vals[1], "CS at +8");\n'
        '  EXP(f.rflags == vals[2], "RFLAGS at +0x10");\n'
        '  EXP(f.rsp == vals[3], "RSP at +0x18");\n'
        '  EXP(f.ss == vals[4], "SS at +0x20");\n'
        '  EXP(kh_frame_contract_ok() == 1, "constants agree");\n'
        '  EXP(kh_frame_base_for_ist(0x1000) == 0x1000 - 0x28, "frame base = IST - 0x28");\n'
        '  EXP(kh_forward_rsp_direct(0x1000) == 0x1000, "direct forward leaves RSP");\n'
        '  EXP(kh_forward_rsp_after_pivot(0x1028) == 0x1028 - 0x30, "post-pivot rewind is 0x30");\n'
        '  EXP((KH_RFLAG_TF | KH_RFLAG_RF) == 0x00010100ULL, "TF/RF bits");\n'
        '  EXP(kh_pivot_is_pure_skip(KH_PIVOT_BYTES, 6) == 1, "pivot bytes accepted");\n'
        '  unsigned char mut[6];\n'
        '  for (int i = 0; i < 6; i++) mut[i] = KH_PIVOT_BYTES[i];\n'
        '  mut[3] = 0x30;\n'
        '  EXP(kh_pivot_is_pure_skip(mut, 6) == 0, "mutated pivot rejected");\n'
        '  EXP(kh_pivot_is_pure_skip(KH_PIVOT_BYTES, 5) == 0, "wrong length rejected");\n'
        '  printf(bad ? "BAD %d\\n" : "ok\\n", bad);\n'
        '  return bad != 0; }\n')
    exe = tmp / "frame_probe"
    rc, out = run(["gcc", "-std=c11", "-I", str(ROOT / "include"), str(prog), "-o", str(exe)])
    if rc != 0:
        record("synth", "frame: #DB layout and pivot contract", False,
               f"compile failed: {out.strip()[:80]}")
        return
    rc, out = run([str(exe)])
    bad = [l for l in out.splitlines() if l.startswith("BAD")]
    record("synth", "frame: #DB layout and pivot contract", rc == 0 and not bad,
           "; ".join(bad) if bad else "13 assertions")

    # The header's pivot bytes, the table's comment and the dump verifier's
    # expectation must be the same statement, in the same order.
    hdr = (ROOT / "include/byepervisor/khook_frame.h").read_text()
    table = (ROOT / "source/offsets/off_1360.c").read_text()
    import re as _re
    m = _re.search(r"GAD_ADD_RSP_28_POP_RBP_RET\s*=\s*0x[0-9A-Fa-f]+,\s*/\*[^*]*?"
                   r"([0-9a-f]{2}(?:\s[0-9a-f]{2})+)\s*\*/", table)
    comment_bytes = [int(b, 16) for b in m.group(1).split()] if m else []
    m2 = _re.search(r"KH_PIVOT_BYTES\[6\]\s*=\s*\{([^}]+)\}", hdr)
    hdr_bytes = [int(b.strip(), 16) for b in m2.group(1).split(",")] if m2 else []
    record("synth", "frame: pivot bytes agree between header and offset table",
           comment_bytes == hdr_bytes and comment_bytes == [0x48, 0x83, 0xc4, 0x28, 0xF3, 0xC3],
           f"header={[hex(b) for b in hdr_bytes]} table={[hex(b) for b in comment_bytes]}")


def synthetic_ownership_tests(tmp: Path) -> None:
    """The trap-ownership decision, run on the host against synthetic contexts.

    Every case except the fully-identified one must come out FOREIGN: the chain is
    only reachable when the trap is provably ours.
    """
    if not have("gcc"):
        record("synth", "ownership: ours vs foreign traps", False, "SKIP: gcc unavailable")
        return
    prog = tmp / "ownership_probe.c"
    prog.write_text(
        '#include "byepervisor/khook_ownership.h"\n'
        '#include <stdio.h>\n'
        'static int bad;\n'
        '#define EXP(c, l) do { if (!(c)) { printf("BAD %s\\n", l); bad++; } } while (0)\n'
        'static struct kh_trap_context ours(void) {\n'
        '  struct kh_trap_context c = {0};\n'
        '  c.frame_rip = 0x4000; c.frame_cs = 0x2b; c.frame_rflags = KH_RFLAG_TF;\n'
        '  c.dr6_bs = 1; c.armed = 1; c.gate_is_ours = 1;\n'
        '  c.core_id = 0; c.cookie_core = 0; c.cookie_magic = KH_TRAP_COOKIE_MAGIC;\n'
        '  c.cookie_seq = 7; c.expect_core = 0; c.expect_seq = 7;\n'
        '  c.expect_rip = 0x4000; c.expect_cs = 0x2b;\n'
        '  return c; }\n'
        'static int ours_ok(struct kh_trap_context c) {\n'
        '  return kh_trap_decide(&c).decision == KH_TRAP_OURS; }\n'
        'static int reason_is(struct kh_trap_context c, enum kh_trap_reason r) {\n'
        '  struct kh_trap_verdict v = kh_trap_decide(&c);\n'
        '  return v.decision == KH_TRAP_FOREIGN && v.reason == r; }\n'
        'int main(void) {\n'
        '  struct kh_trap_context c;\n'
        '  EXP(ours_ok(ours()), "fully identified -> OURS");\n'
        '  c = ours(); c.gate_is_ours = 0; EXP(reason_is(c, KH_TRAP_R_GATE_CHANGED), "gate changed");\n'
        '  c = ours(); c.armed = 0; EXP(reason_is(c, KH_TRAP_R_NOT_ARMED), "already disarmed");\n'
        '  c = ours(); c.dr6_bs = 0; EXP(reason_is(c, KH_TRAP_R_NO_BS), "not a breakpoint");\n'
        '  c = ours(); c.cookie_magic = 0; EXP(reason_is(c, KH_TRAP_R_BAD_COOKIE), "stale/foreign cookie");\n'
        '  c = ours(); c.core_id = 3; EXP(reason_is(c, KH_TRAP_R_WRONG_CORE), "wrong core");\n'
        '  c = ours(); c.cookie_core = 3; EXP(reason_is(c, KH_TRAP_R_WRONG_CORE), "cookie from another core");\n'
        '  c = ours(); c.cookie_seq = 6; EXP(reason_is(c, KH_TRAP_R_STALE_SEQ), "previous arming");\n'
        '  c = ours(); c.frame_rip = 0x9000; EXP(reason_is(c, KH_TRAP_R_RIP_MISMATCH), "foreign RIP");\n'
        '  c = ours(); c.frame_cs = 0x33; EXP(reason_is(c, KH_TRAP_R_CS_MISMATCH), "foreign CS");\n'
        '  c = ours(); c.frame_rflags = 0; EXP(reason_is(c, KH_TRAP_R_NO_TF), "TF not set");\n'
        '  EXP(kh_trap_decide(0).decision == KH_TRAP_FOREIGN, "null context is foreign");\n'
        '  struct kh_foreign_action a = kh_foreign_action_for(KH_TRAP_OURS);\n'
        '  EXP(!a.forward_to_original && !a.restore_after && !a.disarm, "ours: no forwarding");\n'
        '  a = kh_foreign_action_for(KH_TRAP_FOREIGN);\n'
        '  EXP(a.forward_to_original && a.restore_after && a.disarm, "foreign: forward + restore + disarm");\n'
        '  printf(bad ? "BAD %d\\n" : "ok\\n", bad);\n'
        '  return bad != 0; }\n')
    exe = tmp / "ownership_probe"
    rc, out = run(["gcc", "-std=c11", "-I", str(ROOT / "include"), str(prog), "-o", str(exe)])
    if rc != 0:
        record("synth", "ownership: ours vs foreign traps", False,
               f"compile failed: {out.strip()[:80]}")
        return
    rc, out = run([str(exe)])
    bad = [l for l in out.splitlines() if l.startswith("BAD")]
    record("synth", "ownership: ours vs foreign traps", rc == 0 and not bad,
           "; ".join(bad) if bad else "14 assertions (11 refusal reasons)")


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
        synthetic_policy_tests(tmp)
        synthetic_hook_state_tests(tmp)
        synthetic_boot_data_tests(tmp)
        synthetic_frame_contract_tests(tmp)
        synthetic_ownership_tests(tmp)
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
