# 13.60 port — status, evidence and blockers

Branch: `feature/13.60-support` (fork `EmaCorona/ps5-linux-13.60`).
Target console: PS5 Slim, fw **13.60**, regular (non-pro) SoC.

This document is written for a reviewer who has only this repository: it states
what is implemented, what was observed on real hardware, and what is still
missing.

---

## 1. What is implemented

| File | What it does |
|---|---|
| `source/offsets/off_1360.c` | 13.60 kernel/HV symbol + gadget table, values taken from Byepervisor-Reborn `include/offsets/13_60.h`; same field layout as `off_1320.c`. Fields not published by Byepervisor are left `0` with explicit `TODO(13.60)` comments. |
| `include/hv/defeat/hv_defeat_1360.h` | Public API: `hv_defeat_1360()` (arm), `hv_defeat_1360_post_resume()`. |
| `source/hv/defeat/hv_defeat_1360.c` | 13.60 sibling of `hv_defeat_1320.c`: Byepervisor khook escape (kernel `.text` RW + XOTEXT clear, khook on `HV_MP_STARTUP_CALL` → `break_hv`). Phase B (post-resume takeover) is compiled out unless `PL5_1360_TAKEOVER=1` because its addresses are still unknown (see §5). |
| `source/core/utils.c` | `case 0x1360: env_offset = off_1360;` |
| `source/main.c` | dispatches 13.20/13.60 inside the `0x0800..0x1400` range and calls the matching post-resume hook. |
| `tools/verify_off_1360.py` | static check: every symbol/gadget in `13_60.h` is mapped with the same value; `off_1360.c` initialises the same `offset_list` field set as `off_1320.c`; routing present. Currently **PASS** (35/35 symbols, 57/57 fields). |
| `README.md`, `CONTRIBUTING.md` | 13.60 state + the four values still missing. |

Deliberate design choice: 13.20 and 13.60 share the same algorithm, so
`hv_defeat_1360.c` is a sibling of `hv_defeat_1320.c` (project style is one file
per firmware family) rather than a refactor of the shared high-FW path. The
generated shellcode blobs are declared `extern` in the 1360 file to avoid
duplicate definitions at link time (the generated headers define non-static
globals).

## 2. Build

No LLVM build is required: `ps5-payload-dev/sdk` publishes a prebuilt release.

```
PS5_PAYLOAD_SDK=<sdk dir>  LLVM_CONFIG=<pLabs5-SDK>/tools/nixos/llvm-config  make -j4 all
PS5_PAYLOAD_SDK=<sdk dir>  LLVM_CONFIG=<pLabs5-SDK>/tools/nixos/llvm-config  make offsets
```

Host used: `ps5-payload-sdk` release **v0.44** (`ps5-payload-sdk.zip`, sha256
`4d06eab777bb135705b5a6816688c9132efb246093fe606ac488ab6cf65ca5b0` — the same
digest pinned in the project `Dockerfile`) plus `pLabs5-SDK` from `main`
(needed only for `LLVM_CONFIG`).

Result: **zero errors, zero warnings**. Artefacts: `bin/pLinux5-NG.elf`,
`bin/pLinux5-NG-offsets.elf` (`-DPL5_OFFSETS_MODE`), `tools/pl5-offsets.elf`
(standalone dumper, no escape).

## 3. Hardware observations

Sent to the console's elfldr (`192.168.1.168:9021`). Payload notifications are
mirrored to `/data/plinux5.log` on the console (read back through the ps5upload
engine HTTP API on the host, `127.0.0.1:19113`).

**The escape (phase A) works on 13.60.** From the log:

```
13.60 selftest: core=15 oracle=0xcafe133741414141 -> KHOOK OK
13.60: [A] payload staged @ cave+0x1000, hv_base=0x62800000 cr3=0x22e84000 redirect=1
13.60: [C] kh_init rc=0
13.60: [B] chain built (384 bytes)
13.60: [D] kh_install rc=0
13.60: [E] core=15 ktext=0xffffffffdf030000 scratch=0xffffffffe1d69000 tgt=0xffffffffdfc46ee0 idt=0xffffffffe2be4300 tss=0xffffffffe2be6fe0
13.60: [F] triggered
13.60: hypervisor escape armed (diag=4). Rest mode -> payload.
```

Offset sanity (independent of Byepervisor's own tables):

* `tgt − ktext = 0xC16EE0` = `KERNEL_SYM_HV_MP_STARTUP_CALL` (13.60)
* `idt − ktext = 0x3BB4300` = `KERNEL_SYM_IDT_ARRAY` (13.60)
* `tss − ktext = 0x3BB6FE0` = `KERNEL_SYM_COMMON_TSS` (13.60)
* the khook self-test fires a `#DB` breakpoint on `sys_getuid` (a real
  instruction address) and its chain writes the oracle cookie — so the table
  resolves to real addresses, not near-misses.

**The S3 path is the blocker.**

| round | payload | result |
|---|---|---|
| 1 | ours, `PL5_DIAG=4` | escape armed; console **powered off by itself**; no `[W0]`, no dump |
| 2 | ours, `PL5_DIAG=1` (hook installed, **no** RSI redirect → `break_hv` never runs) | same → the failure is not `break_hv`/redirect |
| — | root cause 1: the console had **HDMI Device Link = ON** and *Supply Power to USB Ports* not set to *Always* (the "CRITICAL" checklist in README/Byepervisor). With Device Link on, CEC powers the console off around rest mode. Operator fixed both. | |
| 3 | ours, `PL5_DIAG=4` (settings fixed) | escape armed; console entered rest mode and **resumed ~5 min later**; the ps5upload helper survived; **but `plinux5.log` never advanced past "Going to rest mode"** — no `[W0]`, no `[W]`, no `[X]`, no dump |
| 4 | **Byepervisor-Reborn reference**, built from source with the same SDK | console entered rest mode; operator reports it powered off again afterwards |

`logmsg()` is not `DEBUG`-gated (it does `printf` + `fflush` + file write), so
`[W0]` — printed as the first statement of `hv_defeat_1360_post_resume()` —
*would* appear on a genuine post-resume continue. Its absence in round 3 is the
central observation.

## 4. Working hypothesis

**The payload process does not continue after S3 on this setup.** Everything
that runs *before* the sleep works; nothing after it does. Byepervisor's README
explicitly says the payload "expects to continue running on resume from rest
mode, and it relies on elfldr for this" — i.e. the loader must keep the payload
resident across suspend. The loader in use here is the one shipped by
ps5upload (TCP 9021), not necessarily the canonical `ps5-payload-dev/elfldr`
the reference flow assumes.

Consequence: any design shaped as *escape → rest mode → post-resume dump/boot*
cannot complete in this environment, no matter how correct the offsets are.

## 5. Still missing for phase B (Linux boot)

Four firmware-specific addresses, **not** in Byepervisor's `13_60.h`; 13.20
values shown for reference:

| value | 13.20 | lives in |
|---|---|---|
| HV VMMCALL handler PA (dmap) | `0x62847375` | `hv_defeat_1360.c` |
| `KERNEL_CFI_CHECK` | `0x44E5D0` | `off_1360.c` (0 today) |
| `FUN_SMP_RENDEZVOUS` | `0xAF94E0` | `off_1360.c` (0 today) |
| hypercall-4 wrapper (`mov eax,4; vmmcall; ret`) | `0xC09E40` | `hv_defeat_1360.c` |

The shared takeover blob (`source/shellcode/hv_takeover/`) is also
13.20-hard-coded and needs the same treatment.

Also unknown for 13.60 (not needed by the escape, needed for a Linux boot):
display bring-up symbols (`G_VBIOS`, `FUN_TRANSMITTER_CONTROL`,
`FUN_MP3_*`), the WiFi firmware blob, `GAD_WRMSR_RET`.

## 6. Proposed next steps

1. **Standalone dumper after a successful escape + resume** —
   `tools/pl5-offsets.elf` (built with `-DPL5_OFFSETS_MODE`-less `main()`, so it
   calls `pl5_dump_offsets()` directly and does **not** require rest mode).
   Once any escape has cleared XOTEXT and a rest-mode cycle has flushed the
   stale TLB, it can read kernel `.text` and the HV image. Expected to yield at
   least 3 of the 4 missing values. This removes the dependency on the payload
   surviving resume.
2. **Establish whether payloads survive S3 here at all** — repeat with the
   canonical `ps5-payload-dev/elfldr` + kstuff flow rather than the ps5upload
   loader, and compare. If payloads do survive, round 3's missing `[W0]` means
   something else kills/interrupts the process and the escape+rest design is
   still viable.
3. **`PL5_DIAG=0`** (no escape, no hook: pure rest-mode round trip with our
   payload) to separate "suspend mechanism" from "escape state".
4. Re-run `PL5_DIAG=4` once (2) is resolved; phase A is already proven, so a
   `[W]` line should be followed immediately by the dump.

## 7. Local build host layout (for reproduction)

```
$HOME/src/ps5-linux-13.60                          # this fork, branch feature/13.60-support
$HOME/src/ps5-sdk-dl/sdk/ps5-payload-sdk            # v0.44 prebuilt (sha256 in the Dockerfile)
$HOME/src/ps5-sdk-dl/plabs5/pLabs5-SDK-main         # for LLVM_CONFIG
```

---

## Update — 23:09 — the escape and the standby are fine; the armed khook is not

Progression of hardware results, each one isolating a single variable:

| stage | what is armed across suspend | result |
|---|---|---|
| `PL5_DIAG=0` | nothing | standby + resume: the console comes back; **but `[W0]` never appears**, i.e. with the legacy event-flag rest path the payload does not continue (no TLB flush either) |
| `PL5_DIAG=1` | escape + armed khook | the console powers off ~5 s after arming, **before the standby is even requested** (`sceSystemStateMgrEnterStandby()` line absent from the log) |
| `PL5_DIAG=5` | escape only, no khook | **standby + resume work and the payload continues**: `[W0] pre-suspend` is present and the run exits cleanly |
| `PL5_DIAG=5` + dump | escape only, then the offsets dump | standby + resume ok, then the console powers off **during the dump**, i.e. while reading `.text` |

Supporting measurements:

* the escape is verifiably complete — `[X] ktext pte@…=0x19190103 xotext=0 rw=1`,
  3264 PDEs and 3264 PTEs touched;
* the direct-map alias of the kernel image is **deliberately unmapped**
  (`dmap pde = 0x725b007`, `dmap pte = 0x0`), so a dmap read returns nothing —
  cleanly, no crash;
* writing that alias ourselves (`pte = pa | present|RW`, on a VA that was never
  accessed, so no stale TLB entry) and reading it **powers the console off**;
* reading `.text` through its kernel VA — after a real suspend — **powers the
  console off**.

### Conclusion so far

Escape: works. Standby (official API): works. Payload resume: works. Extractor:
runs and writes. The single remaining blocker is **reading the bytes of kernel
`.text`**: every way we have tried (kernel VA, dmap alias, self-mapped alias)
ends in a power-off. The XOTEXT bit in the page table is clearly not the whole
mechanism — the protection appears to be enforced below the page-table
permissions on this console/firmware, so the *act* of reading the kernel image
is what trips it.

The armed khook is separately fatal here: the console dies seconds after the
gate is installed. Byepervisor-Reborn arms exactly the same gate, which is
consistent with it also dying on this console.

### Candidates for the next round (for review)

a) **Find out why the armed khook is fatal.** This console has many payloads
   loaded (`ps5upload` helper, kstuff, elfldr, nanodns, garlic, shadowmount,
   blackbox-v2, pldmgr, elf-arsenal); some may own the debug registers, the IDT
   or the TSS that the khook needs. Test with a **minimal chain** (exploit +
   elfldr only). If the khook then survives, the whole 13.20-style vector —
   including `break_hv` and the NPT-off approach to the HV — becomes available
   again.
b) **Read `.text` from kernel context** through a khook chain, where a fault
   may be recoverable rather than fatal. Blocked by (a).
c) **Do it offline instead**: obtain a 13.60 firmware image (kernel + HV) and
   derive the four values with the tooling already available on the build host
   (REA/Ghidra). No console risk, and it also yields the HV VMMCALL handler
   without needing `break_hv`.
d) Note for whoever picks this up: the payload log on the console is preserved
   across the power-off. It must be read **before** any new payload run, because
   `notify()` truncates it per run.

---

## Update — 23:40 — GPU-DMA path: reconnaissance on the console

The GPU translates its accesses through its own per-VMID GPUVM, so it does not go
through the CPU-side NPT/nda protection that makes any CPU read of `.text` fatal.
This repo already carries most of the primitive in `source/hw/gpu.c`
(`gpu_init`, `gpu_read_phys`, `gpu_transfer_physical`, the PM4 `DMA_DATA` builder
and the `/dev/gc` submit ioctl); what is missing is the 13.60 model.

`tools/pl5-gpu-probe.c` (read-only: it never retargets a leaf and never submits a
DMA packet) was run on the console. Measured:

```
fw=1360 ktext=0xffffffffd00b0000 kdata=0xffffffffd0d70000 dmap=0xfffffc6f00000000
vmid(+0x1FC) = 0xff00000000000002        -> u32 = 2   (offset 0x1FC confirmed;
                                                         the u64 carries a Sony sentinel)
victim va=0x200200000 off=0x2027a00000
staging va=0x200400000 off=0x2027c00000
cmd     va=0x200600000 off=0x2027e00000
/dev/gc fd=20                            (opens fine)
gvmspace[0] @ kdata+0x2EEA570  page_dir_va=0xffffff8093aa0000 start=0 size=0xfc00000000
gvmspace[2] (= our vmid)       page_dir_va=0xffffff8093aa8000 start=0 size=0x1000000000000
gvmspace[3..6] start=0 size=0x1000000000000 ; gvmspace[7..15] all zero
```

So for 13.60: `VMSPACE_VM_VMID = 0x1FC` (read as u32) and
`DATA_BASE_GVMSPACE = 0x2EEA570` are both confirmed on hardware, and
`page_dir_va` is a **kernel VA** (reading it as a physical address yields zeros).

Walking the trees for GPU VA `0xc80000000` reached entries in vmids 0..6, but the
result does not yet match the documented layout:

```
vmid=2  ptb[0] @0x…16232000 = 0x900000016232805 tf=1 frag=1
        leaf8k[0] @0x…16232000 = 0x900000016232805   (same address re-read)
vmid=4  ptb[0] @0x…1623d000 = 0x90000001623d805 tf=1 frag=1
        leaf8k[0] @0x…1623c000 = 0x200000001623d005   phys=0x1623c000
vmid=6  ptb[0] @0x…1626f000 = 0x90000001626f805 tf=1 frag=1
        leaf8k[0] @0x…1626e000 = 0x473690277          phys=0x473690000  (>16 GiB: VRAM)
```

Open questions that must be settled before any retarget is attempted (a wrong
retarget panics the console):

1. the exact level/index tuple and the mask used at each level: `GPU_DMA_PHYS_FIX`
   documents PDB2→PDB1(39)→PDB0(30)→PTB(21)→TF sub-table(16)→8 KB leaf(13), but our
   walk from pml4[0]→pdpt[50]→pd[0] already lands on entries carrying bits 56/59,
   i.e. there is at least one extra indirection versus that description;
2. whether the garlic buffers really sit at `0xc80000000 + 2 MiB * n`: only the
   first allocation appears under `0xc80000000`, and `staging`/`cmd` are mapped
   nowhere in any tree (all vmids return -1 for `0xc80200000` / `0xc80400000`);
3. which vmid the `/dev/gc` ioctl actually submits under (trees exist for 0..6;
   the analyst's notes say the dev vmid is dynamic, 5 or 6 on different boots).

The probe, the source tree and the ability to rerun it over elfldr's HTTP
interface (which returns the payload's stdout) are all in place, so answering the
three points above is one console session away.

---

## Update — 23:45 — GPUVM walk fixed and validated

The pipeline is now correct. The 13.60 GPU chain is:

```
PDB2 (PML4, kernel VA)  -> idx (gva>>39)&0x1FF
  PDB1 (PDPT, physical) -> idx (gva>>30)&0x1FF
    PDB0 (PD,  physical) -> idx (gva>>21)&0x1FF
      PTB (64 KB, frag=4) -> idx (gva>>16)&0x1F
        TF sub-table (bit56) -> idx (gva>>13)&0x7  -> 8 KB leaf PTE
```

Two traps that cost several runs and are worth recording:

* the **TF-flagged entry is a table pointer**, so its address is in bits 6..47
  (`0x0000FFFFFFFFFFC0`). Using the *leaf* mask (bits 13..47) there strips bits
  6..12 and lands back on the same page -- which is exactly what the earlier
  "same address re-read" symptom was;
* `page_dir_va` is indexed as the **PML4**; indexing the PDPT with it (as one
  intermediate scan did) reads an empty entry and hides the whole tree.

Validated output (a single boot):

```
vmid=2 (our process) : 40 leaves, gva 0xc80000000 + 8 KB*n  ->  phys 0x35200000 + 8 KB*n
vmid=3               : 40 leaves, same GPU VA range        ->  phys 0x3f600000 + 8 KB*n
vmid=4               : 40 leaves                           ->  phys 0x44c00000 + 8 KB*n
vmid=5               : 40 leaves                           ->  phys 0x43b600000 + 8 KB*n
vmid=6               : 40 leaves                           ->  phys 0x43b5a8000 + 8 KB*n
```

* leaf value shape, e.g. `0x4000035200177` -> address bits 13..47 = `0x35200000`,
  low bits `0x177`, **bit 50 already set** (these are direct-memory allocations,
  i.e. system RAM, so the "system coherent" flag is already there);
* **population is lazy**: 40 x 8 KB = 320 KB mapped per vmid, not the full 2 MB;
* the mapped physicals are **not readable through the CPU dmap** (reading
  `dmap + phys` returns zeros), so there is no CPU-side shortcut and the garlic
  space is separate, exactly as the reference documents state;
* the CPU pattern written into the victim (`0xDEADBEEF...`) is **not** found at
  any of those physicals, and `staging`/`cmd` are **not** at
  `gva 0xc80200000` / `0xc80400000` (those PD entries are invalid).

### Remaining questions before a retarget is allowed

1. Which vmid does the `/dev/gc` ioctl submit under, and does the victim's leaf
   appear in *that* vmid's tree only after a GPU submission touches it? (every
   populated vmid shows the same 40-leaf window at the same GPU VAs, with its own
   physical, so the window is not by itself evidence of ownership);
2. how to obtain the GPU VAs of `staging` and `cmd`: scanning by physical failed
   (+2 MB / +4 MB leaves do not exist), which suggests they are simply not
   populated yet.

### Planned next step (one console session)

Allocate the three buffers, submit one trivial GPU operation that touches them
through the raw PM4 path already documented, then re-scan and **diff the leaf
set**: the leaves that appear are ours, which yields their GPU VAs and leaf
addresses. Only after that is the retarget (`new = (old & ~0x0000FFFFFFFFE000) |
(target_pa & 0x0000FFFFFFFFE000) | (1<<50)`) attempted, with a self-test read of
the victim before any `.text` chunk.
