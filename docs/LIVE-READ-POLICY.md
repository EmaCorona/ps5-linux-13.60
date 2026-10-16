# Live reads: what a payload may read, and where that is decided

Two activities are easy to confuse and must stay separate:

| activity | artifact | touches a console? |
| --- | --- | --- |
| **offline analysis of a capture** | `tools/verify_off_1360_dump.py`, `tools/verify_off_1360.py` | no — a file on disk |
| **live read** | `tools/pl5-offsets.*`, `tools/pl5-verify-1360.*` | yes |

The offline path is the normal one for deriving values. The live path exists for consoles whose
firmware has no capture yet, and it is the one that can damage hardware.

## The rule

**Reading kernel `.text` on firmware 13.60 powers the console off.** This is recorded as an
observation, not a theory: the `.text` read attempt and the console shutdown are in
[`1360-port-status.md`](1360-port-status.md), and the wider hazard is analysed in
[`1360-khook-death.md`](1360-khook-death.md). A live `.text` dump is therefore **not** a proposed
next step for 13.60 anywhere in this repository.

The rule is enforced in code, not in prose: `include/tools/pl5_dump_policy.h` holds the single
decision function, `pl5_decide()`, and `tools/pl5-offsets.c` calls it at the top of
`pl5_dump_offsets()` — before the paging setup, before the region dump, before anything is read.

## What the policy decides

| firmware | region | commit marker | decision |
| --- | --- | --- | --- |
| 13.60 | `.text` | present | **refuse** — `REFUSED: reading kernel .text on 13.60 powers this console off` |
| 13.60 | data / HV | present | allow |
| any | any | absent | refuse — dry run, nothing is read |
| any | any | present | refuse when the firmware does not match the payload's offset tables |

Two properties are deliberate:

- **dry run is the default.** Sending the payload does nothing by itself; the operator must place
  `/data/pl5-offsets-commit` on the console. There is no flag, environment variable or marker that
  skips the firmware/`.text` rule — the refusal is unconditional for 13.60 `.text`.
- **a firmware mismatch is refused, not warned.** `tools/pl5-offsets.c` used to print a warning and
  continue with another firmware's offsets; it now refuses, because wrong offsets are as harmful as
  a wrong read.

`tools/pl5-verify-1360.c` applies the same idea to single-offset checks: `NS:OFFSET` is mandatory,
`.text`-relative offsets (`< 0xCC0000`) are refused with the reason, and `--commit` is required to
read a single 8-byte word.

## How it is tested without a console

`tests/run_tests.py` compiles `pl5_dump_policy.h` with the host compiler and asserts all six
decision cases plus the fatal-firmware predicate, then checks that `pl5-offsets.c` actually calls
`pl5_decide()` before `pl5_dump_offsets()` does any work. The policy is a header with `static inline`
functions precisely so that the payload and the host test run the same code.
