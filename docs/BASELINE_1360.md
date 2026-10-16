# BASELINE_1360 — frozen initial state of the 13.60 port

**Purpose:** let another agent reconstruct the exact starting state of the
`feature/13.60-support` branch without guessing which revision was analysed, what
the toolchain was, or what the verifiers said before any change. This file is the
Task 1 deliverable of the 13.60 completion plan and is a *record*, not an
instruction.

**Recorded:** 2026-10-16, by the plan-execution session, before any code change.

---

## 1. Revision

| item | value |
| --- | --- |
| repository | `EmaCorona/ps5-linux-13.60` (fork of `pLabs5/pLinux5-NG`) |
| branch | `feature/13.60-support` |
| local HEAD | `2e6768914ad71cb672984d7cf7bd9d9cd2e8631c` (`docs: 13.60 HV PA verdict — PUP container facts and evidence ids`, 2026-10-16T02:32:35+02:00) |
| remote `origin/feature/13.60-support` | `05d89cb36e1aba3d093b5aff90ca9fdf0b9e0421` |
| local vs origin | **ahead by 1 commit** (the HV PA verdict doc + its amend are local-only) |
| `master` (untouched) | tracked; not modified by this work |
| manifest version | `0.1.0` (`source/manifest/manifest.c`) |
| remote `upstream` | `https://github.com/pLabs5/pLinux5-NG.git` |

### 1.1 Working tree at baseline time

The tree was **not clean** when this baseline was taken. It carried an unverified
in-progress experiment and a deletion:

```
 M source/hv/defeat/hv_defeat_1360.c   (PL5_DIAG==19 arm-late guards added)
 M source/main.c                       (PL5_DIAG==19 legacy enter_rest_mode() path)
 D docs/1360-hv-pas-offline-verdict.md (tracked file deleted in the working tree)
```

**Disposition (preserve, do not lose):**

- the two `PL5_DIAG==19` source edits were committed verbatim to a separate branch
  **`wip/1360-diag19`** (`e5f3e90`), so the feature branch stays clean and the
  experiment is not lost. It was neither built nor run;
- `docs/1360-hv-pas-offline-verdict.md` was **restored** (`git checkout --`),
  because the completion plan cites it as a live source of truth. Its deletion was
  not documented anywhere, so restoring is the reversible choice.

The `diag19` experiment is relevant to Task 15 (post-resume contract): it selects
the *legacy* `enter_rest_mode()` path instead of `sceSystemStateMgrEnterStandby()`
to isolate which path the payload process survives. It is a hypothesis, not a result.

---

## 2. File inventory (summary)

Tracked source, docs and tooling at the baseline commit. Generated artefacts
(`*.o`, `*.bin`, `*.elf`, `*.h` under `source/shellcode/**`) and `bin/*.elf` are
present in the working tree but are build output, not sources.

| area | files | notes |
| --- | --- | --- |
| build | `Makefile`, `Dockerfile`, `docker-bake.hcl`, `CONTRIBUTING.md`, `LICENSE` | see §4 |
| CI | `.github/workflows/build-pLinux5-NG.yml`, `.github/workflows/build-tools.yml` | see §5 |
| docs | `README.md`, `docs/README.md`, `docs/1360-port-status.md` (35 KB), `docs/1360-offsets-from-dump.md` (17 KB), `docs/1360-khook-death.md` (15 KB), `docs/analyst-recap-1360.md` (30 KB), `docs/1360-hv-pas-offline-verdict.md`, `docs/upstream-ps5-linux-loader-README.md` | see §6 |
| core | `source/main.c`, `source/core/utils.c`, `include/core/*.h` | firmware routing |
| offsets | `source/offsets/off_*.c` (30 tables), `source/offsets/off_1360.c`, `include/offsets/offsets.h` | see §7 |
| HV defeat | `source/hv/defeat/hv_defeat_{0304,0506,0607,1320,1360}.c`, `include/hv/defeat/*.h` | 13.60 impl 40 KB |
| byepervisor | `source/byepervisor/{kdlsym,khook,paging}.c`, `include/byepervisor/*.h` | khook = the `#DB` gate hook |
| boot | `source/boot/{loader,prepare_resume}.c`, `include/boot/*.h`, `include/core/linux.h` | Linux payload prep |
| hw | `source/hw/{firmware,gpu,iommu,tmr}.c`, `include/hw/*.h` | display/GPU/IOMMU |
| shellcode | `source/shellcode/{0607,break_hv,hv,hv_boot,hv_takeover,kernel}/` | freestanding blobs + `takeover.S` |
| tools | `tools/pl5-offsets.c`, `tools/pl5-verify-1360.c`, `tools/pl5-encsrv-probe.c`, `tools/pl5-escape-probe.c`, `tools/pl5-gpu-probe.c`, `tools/pl5-gpu-read.c`, `tools/gen_sigtable.py`, `tools/pupdec/`, `tools/Makefile`, `tools/sigtable_1320.h` | see §3 |
| scripts | `scripts/bin2c.py`, `scripts/send.sh`, `scripts/send.ps1` | `send.sh` ships the ELF to the console |

There is **no `tests/` directory** at the root: the only automated checks are the
three `tools/verify_*.py` scripts run by hand.

---

## 3. Verifier state at baseline (measured, not asserted)

Run on this host against the real community capture
`~/src/ps5-dumps/k1360.bin` (sha256 `c3f745e2…cddd`, size `0x62C0000`).

| verifier | command | result | caveat |
| --- | --- | --- | --- |
| `tools/verify_off_1360.py` | `python3 tools/verify_off_1360.py /tmp/13_60.h` | **PASS** — 35/35 header symbols mapped, 57/57 fields match `off_1320.c`, 57 values checked | needs a local `13_60.h`; exits 0 |
| `tools/verify_off_1360_dump.py` | `.venv-rea/bin/python tools/verify_off_1360_dump.py` | **22/22 "passed"** | **`FUN_PRINTF` check is `ok(is_entry(off) or True, …)` — always true. The PASS is not evidence.** Also the dump path and sha256 are hard-coded to this host. |
| `tools/verify_takeover_param.py` | `python3 tools/verify_takeover_param.py` | **12/12 PASS** — body carries no firmware literal, `PL5_TAKEOVER_FW=1360` build refused naming the unknown HV PA, `1320` blob is 144 B and encodes only 13.20 constants | needs `gcc`/`objcopy`/`make` (present) |

The `or True` defect is **Task 4** of the plan. Recorded here as an observed fact:
`22/22` on that script does **not** mean the dump evidence for `FUN_PRINTF` exists
— that field has no signature check at all.

---

## 4. Toolchain at baseline

| component | where declared | version |
| --- | --- | --- |
| compiler (Docker) | `Dockerfile` | `silkeh/clang:22-trixie` (**Clang 22**) |
| compiler (CI) | both workflows | LLVM/Clang **21** via `apt.llvm.org/llvm.sh` |
| PS5 payload SDK | `Dockerfile` + workflows | v0.44, sha256 `4d06eab777bb135705b5a6816688c9132efb246093fe606ac488ab6cf65ca5b0` (both pinned) |
| pLabs5 SDK | `Dockerfile` + workflows | **`pLabs5-SDK` branch `main`, unpinned** (zip / `actions/checkout`) |
| local host (this machine) | — | `gcc 16.2.1`, `make 4.4.1`, `clang 18.1.8`, `python 3.14.7`; **no `/opt/ps5-payload-sdk`, no `LLVM_CONFIG`** |

`PS5_PAYLOAD_SDK` and `LLVM_CONFIG` are the two documented env inputs
(`Makefile`, `Dockerfile`, workflows). The **Clang 22 vs 21** and the **unpinned
pLabs5-SDK** are the reproducibility gaps tracked by **Task 7**.

A local full payload build is **not possible as-is** on this host (no PS5 SDK).
Shellcode/takeover builds work locally without it (Task 5/16 rely on this).

---

## 5. CI at baseline

| workflow | triggers | coverage gap |
| --- | --- | --- |
| `build-pLinux5-NG.yml` | `push`/`pull_request` on **`master`** only, tags `v*`, `workflow_dispatch` | the feature branch is **not** covered on push/PR |
| `build-tools.yml` | `master` push, `master` PR touching `tools/**`, tags, dispatch; matrix `fw: ["1320"]` | `tools/**` only, **1320 only**; no 13.60 entry |

Neither workflow runs `tools/verify_*.py`. **Task 6** adds the verifier gate.

---

## 6. Documentation at baseline

Detailed but chronological, with stale notes that read as current instructions.
Known items (confirmed by the plan analysis):

- `README.md` says 13.20 supported, 13.60 escape confirmed but post-resume
  takeover blocked → Linux does not boot on 13.60;
- `docs/1360-port-status.md` is the long-form chronology (including superseded
  hypotheses, e.g. the "payload does not survive S3" note that commit `e6f848d`
  later supersedes);
- `docs/1360-offsets-from-dump.md` is the derivation of the kernel-relative
  values;
- `docs/1360-khook-death.md` documents the khook hazard (Task 13's input);
- `docs/1360-hv-pas-offline-verdict.md` records the negative result for the HV PAs
  (Task 23's input);
- `docs/analyst-recap-1360.md` is the cold-start handoff.

**Task 2** reconciles these into one current statement + a chronological annex.

---

## 7. What the baseline proves, and what it does not

Kept deliberately separate, per the plan's evidence rules:

| class | content |
| --- | --- |
| **hardware observation** (from the branch's own logs, not reproduced here) | escape reaches 13.60; the armed khook kills the console; arm-late reaches standby and wakes; the payload process is not observed after resume |
| **static analysis** (reproduced on this host) | the three verifier results in §3; `off_1360.c` matches `13_60.h`; the takeover blob refuses 13.60 |
| **inference** | the three blockers (global hook, post-resume owner, unknown HV PA) are architecture, not missing offsets |
| **hypothesis** | the `diag19` legacy-rest-mode branch in `wip/1360-diag19`; any claim that a longer timeout fixes post-resume |

Nothing in §3 proves a **boot**. Build success, escape success and a green
verifier are all weaker than "Linux reached its entry point".

---

## 8. Reproduce this baseline

```bash
cd <repo> && git fetch origin
git rev-parse HEAD origin/feature/13.60-support        # §1
git log -1 --format='%H %cI %s'
git status --porcelain -b                              # §1.1 (expected clean here)
python3 tools/verify_off_1360.py /tmp/13_60.h          # §3 row 1
.venv-rea/bin/python tools/verify_off_1360_dump.py     # §3 row 2 (needs capstone + dump)
python3 tools/verify_takeover_param.py                 # §3 row 3
```
