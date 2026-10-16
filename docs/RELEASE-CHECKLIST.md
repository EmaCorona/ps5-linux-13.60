# Release checklist — what may be claimed today

The port may be called **complete for 13.60** only when every applicable line below is satisfied. This
file is the honest answer to "can we ship it?" and each line names the evidence, not an intention.

Legend: **DONE** (implemented and evidenced) · **PARTIAL** (code exists, evidence incomplete) ·
**BLOCKED** (external prerequisite missing) · **NOT STARTED**.

## Criteria

| # | criterion | status | evidence |
| --- | --- | --- | --- |
| 1 | reproducible build with automatic checks on PR | **DONE** | toolchain pinned (`docs/TOOLCHAIN.md`): SDK v0.44 checksummed, pLabs5-SDK pinned to a commit, Docker/CI aligned on Clang 21; two clean local builds byte-identical (`63a81be8…`); `verify.yml` runs the structure, registry and host-suite gates on every push/PR |
| 2 | offsets carry namespace, provenance and verification | **DONE** | `tools/offset_registry.json` + `tools/check_offset_registry.py` (bijection with `off_1360.c`, namespace ranges, no value in two namespaces, no zero treated as known); `verify_off_1360_dump.py` re-derives the values from the capture (22/22) |
| 3 | diagnostic tools protected against forbidden live reads | **DONE** | `include/tools/pl5_dump_policy.h` + wiring in `pl5-offsets.c`: `.text` on 13.60 refused unconditionally, firmware mismatch refused, dry run by default; host tests cover six decisions |
| 4 | hook does not capture foreign traps or kill the loader services | **NOT STARTED** | design approved on paper only (`docs/1360-khook-design.md`); the current implementation is unchanged and still fails the measurement in `1360-khook-death.md` |
| 5 | standby/resume with a component demonstrably able to continue | **NOT STARTED** | contract written (`docs/1360-post-resume-contract.md`); nothing implemented; the userland assumption it removes is still in `main.c` |
| 6 | no essential HV reference is a placeholder or borrowed from another firmware | **BLOCKED** | the one required value (`PL5_1360_HV_VMMCALL_HANDLER_PA`) has no verified source (`docs/1360-hv-source-search.md`); build refuses (`#error`), phase B off |
| 7 | phase B enabled only for a correctly verified 13.60 configuration | **DONE (as *disabled*)** | `PL5_1360_TAKEOVER=0` default, in the build-configuration stamp; both refusal paths asserted by tests and by a CI step |
| 8 | kernel hand-off demonstrated with recorded evidence | **NOT STARTED** | requires 4, 5 and 6 |
| 9 | display/audio/network/SMP documented for the claimed goal | **DONE for G1 scope** | `docs/SUBSYSTEM-MATRIX-1360.md`; G1 (kernel entry) vs G2 (usable Linux) separated, and G2 explicitly not attempted |
| 10 | 13.20 regression and 13.60 repeatability tests completed | **PARTIAL** | 13.20 blob regression pinned (`verify_takeover_param.py`: structure, encoded constants, 144 bytes); the full 13.20 boot regression and 13.60 repeatability need hardware |
| 11 | README, status docs, artifact hashes and residual limits consistent with the evidence | **DONE** | README + `docs/README.md` index + `BASELINE_1360.md`; the payload check publishes `static-report.txt` with the ELF and blob hashes next to the artifact |

## What a release today may say

- 13.20: **supported** to the same extent the upstream project supports it. Nothing in this work
  changed that path except two error checks that now report a missing file correctly
  (`docs/BOOT-LOADER-REVIEW.md`).
- 13.60: **experimental, does not boot Linux.** Build, escape-stage work, offline offset derivation
  and static verification are real; the boot is not.
- The published binary must always be accompanied by `bin/static-report.txt` and a SHA-256, and the
  report must show phase B **out**.

## Stop conditions

If item 6 stays `BLOCKED`, the release keeps phase B disabled and 13.60 remains "experimental" — that
is a permitted, complete outcome. Items 4 and 5 are offline-first: they can be finished without a
console, and they are the only path to changing 8.
