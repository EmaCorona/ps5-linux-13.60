# 13.60 port — status, evidence and blockers

> **This file is the chronology, not the current statement.** It is kept as it was written, day by
> day, and the sections further down describe the state at the moment they were appended. For the
> current status read the root [`README.md`](../README.md) (support table + *Known limitations*),
> with [`BASELINE_1360.md`](BASELINE_1360.md) for the frozen starting point. Where this file and the
> root README disagree, the README is current and this is history.
>
> Current one-line outcome: the escape works on 13.60, the kernel-relative offsets were derived from
> a verified kernel capture ([`1360-offsets-from-dump.md`](1360-offsets-from-dump.md)), and the boot
> is blocked by three separate things — the armed global `#DB` hook, the unproven post-resume
> payload continuity ([`1360-khook-death.md`](1360-khook-death.md)), and the still-unknown
> hypervisor physical addresses ([`1360-hv-pas-offline-verdict.md`](1360-hv-pas-offline-verdict.md)).

Branch: `feature/13.60-support` (fork `EmaCorona/ps5-linux-13.60`).
Target console: PS5 Slim, fw **13.60**, regular (non-pro) SoC.

This document is written for a reviewer who has only this repository: it states
what is implemented, what was observed on real hardware, and what is still
missing.

---

## 1. What is implemented

| File | What it does |
|---|---|
| `source/offsets/off_1360.c` | 13.60 kernel/HV symbol + gadget table, values taken from Byepervisor-Reborn `include/offsets/13_60.h`; same field layout as `off_1320.c`. Every field now carries an evidence class (`KNOWN_STATIC`, `KNOWN_HARDWARE_VALIDATED`, `UNKNOWN`, `NOT_REQUIRED_FOR_1360_PATH`); a field with no evidenced value stays `0` and is labelled `[UNKNOWN]`. *Historical note: earlier revisions left those fields `0` with bare `TODO(13.60)` comments.* |
| `include/hv/defeat/hv_defeat_1360.h` | Public API: `hv_defeat_1360()` (arm), `hv_defeat_1360_post_resume()`. |
| `source/hv/defeat/hv_defeat_1360.c` | 13.60 sibling of `hv_defeat_1320.c`: Byepervisor khook escape (kernel `.text` RW + XOTEXT clear, khook on `HV_MP_STARTUP_CALL` → `break_hv`). Phase B (post-resume takeover) is compiled out unless `PL5_1360_TAKEOVER=1` because its addresses are still unknown (see §5). |
| `source/core/utils.c` | `case 0x1360: env_offset = off_1360;` |
| `source/main.c` | dispatches 13.20/13.60 inside the `0x0800..0x1400` range and calls the matching post-resume hook. |
| `tools/verify_off_1360.py` | static check: every symbol/gadget in `13_60.h` is mapped with the same value; `off_1360.c` initialises the same `offset_list` field set as `off_1320.c`; routing present. Currently **PASS** (35/35 symbols, 57/57 fields). |
| `README.md`, `CONTRIBUTING.md` | 13.60 state. *Historical note: this row used to say "the four values still missing"; two of those (kernel-relative `KERNEL_CFI_CHECK`, `FUN_SMP_RENDEZVOUS`) were later derived from the capture, while the hypervisor-side addresses remain unknown.* |

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

**Superseded (2026-10-16, round 5).** This section used to claim that "the
payload process does not continue after S3 on this setup" and blamed the loader
(the ps5upload one on 9021 rather than the canonical `ps5-payload-dev/elfldr`).
Two independent checks refute that, and it contradicted the diag table further
down this same document:

* the diag table already records **`PL5_DIAG=5` (escape only, no khook):
  standby + resume work and the payload continues** -- payload continuity across
  S3 works here;
* the loader on 9021 **is** the canonical elfldr. It answers
  `[elfldr.elf] Error reading HTTP payload`, byte-for-byte the string at
  `0x145ef4` of the official `elfldr-ps5.elf` (sha256 `ed6d587a057c09d6...`),
  and its bootstrap resolves `SceRedisServer` and ptrace-attaches into it
  (REA `ev_fe55c7fb...`, strings `ev_25861daf...`/`ev_a908710c...`).

What actually fails is narrower and already measured: the **armed khook is
fatal**. `PL5_DIAG=1` (escape + armed khook, no redirect) powers the console off
~5 s after arming, *before* standby is even requested; `PL5_DIAG=0` (legacy
event-flag rest path) returns but the payload does not continue; only the
official `sceSystemStateMgrEnterStandby()` path gives payload continuity.

So the design *escape -> rest mode -> post-resume work* is **not** excluded by
this environment, and the offsets are not the blocker either. The blocker is the
hook's live state across the suspend/resume cycle -- exactly what the P4 /
diag17-19 arm-late work targets.

## 5. Still missing for phase B (Linux boot)

> *Historical section, written before the offline offset work.* Two of the four values below are
> now derived from the verified capture (`KERNEL_CFI_CHECK`, `FUN_SMP_RENDEZVOUS`); the ones that
> remain genuinely missing are the **hypervisor-side** addresses, which a kernel capture cannot
> reach — see [`1360-hv-pas-offline-verdict.md`](1360-hv-pas-offline-verdict.md) and §7. The table
> is kept as written, with the 13.20 column shown only for reference.

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

> **Superseded for 13.60.** Step 1 below proposes reading kernel `.text` live through the
> standalone dumper. Reading `.text` on 13.60 powers the console off, so that is **not** a next
> step on this firmware — see [`LIVE-READ-POLICY.md`](LIVE-READ-POLICY.md) and the enforced
> refusal in `include/tools/pl5_dump_policy.h`. The section is kept as the record of what was
> proposed at the time; the kernel-relative values it was after were later derived offline from a
> capture instead ([`1360-offsets-from-dump.md`](1360-offsets-from-dump.md)).

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

---

## Update — 23:45 — the GPU-DMA read primitive WORKS on this console

The self-test passed on hardware:

```
gpuprobe: submitting DMA 0x200200000 -> 0x200400000 len=0x2000 ioctl=0xc0108102
gpuprobe: ioctl rc=0 (errno=0)
gpuprobe: victim  [0]=0xdeadbeef00000000 [8]=0xdeadbeef00000001
gpuprobe: staging [0]=0xdeadbeef00000000 [8]=0xdeadbeef00000001   DMA_WORKS=1
```

A CPU-written pattern in the victim buffer was copied by the GPU into the staging
buffer and read back from the CPU. That validates the whole path: the
`/dev/gc` submit ioctl, the PM4 `PACKET3_DMA_DATA` packet, and the GVA
identification.

### Anatomy solved on 13.60

* **the dev vmid is 6** -- the garlic buffers are mapped in *vmid 6's* tree, not
  in the process's own vmid (2). That answers the first open question;
* the buffers are mapped **at their own CPU VA** (not at a separate GPU window),
  as **2 MB leaves** (`IS_PTE`, bit 54):

```
vmid=6 victim  gva=0x200200000 leaf@dmap+0x16271008 val=0x4000047bc004f7 phys=0x47bc00000
vmid=6 staging gva=0x200400000 leaf@dmap+0x16271010 val=0x4000047be004f7 phys=0x47be00000
vmid=6 cmd     gva=0x200600000 leaf@dmap+0x16271018 val=0x4000047c0004f7 phys=0x47c000000
```

* leaf physical = bits 21..47 (`0x0000FFFFFFE00000`), **bit 50 = 0** in
  garlic format, so the retarget must add it to reach system RAM;
* the earlier "0xc80000000 window" (40 x 8 KB leaves per vmid) is **not** our
  buffer: a DMA through it returned `rc=0` but moved nothing observable.

### The `.text` read attempt

```
gpuprobe: ktext=0xffffffffd00b0000 -> pa=0x100b0000 ok=1
gpuprobe: RETARGET old=0x4000047bc004f7 -> new=0x440000100004f7 (text2m=0x10000000 off=0xb0000)
gpuprobe: TEXT DMA rc=0
gpuprobe: TEXT[00] 00 00 ...  (all zero, nonzero_bytes_of_256=0)
gpuprobe: victim leaf restored
```

The retarget and the DMA both executed (`rc=0`) and **the console survived**, but
the staging buffer stayed zero. Most likely cause, straight from the reference
docs: **the GPU TLB caches `gva -> phys`, and a retarget of the same leaf is
ignored** -- the docs' recipe explicitly requires a *fresh victim* for every
chunk. Our victim had already been used by the self-test DMA, so its translation
was cached.

### Next steps

1. allocate a **fresh victim buffer per chunk** and retarget only its leaf (never
   reused), then DMA `victim -> staging` and read the staging buffer;
2. validate that order on a *known* target first: retarget a fresh victim leaf to
   the **staging** physical (whose content we control) and check that the DMA
   reproduces it -- this proves the retarget itself, independently of `.text`;
3. then retarget to `.text` in 2 MB-aligned steps, dumping each chunk, and run
   the signature scanner over the result;
4. keep restoring the leaf after every chunk (and remember the GPU TLB caveat:
   a restored-then-reused leaf may also be stale).

---

## Update — 23:50 — GPU reads: .data works, .text is refused

Two results from the same run, with the same recipe and fresh victims:

```
VALIDATE retarget victim2 -> staging physical | bit50
         dma rc=0 cmd[0]=0xc0ffee0000000000 -> RETARGET-OK        (retarget proven)

DATA     kva=0xffffffffd0d71000 pa=0x10d71000 cpu[0]=0xffffffff81530282
         dma rc=0 gpu[0]=0xffffffff81530282 -> SYSRAM-READ-OK     (system RAM read OK)

TEXT     kva=0xffffffffd00b0000 pa=0x100b0000 (2 MB base 0x10000000, off 0xb0000)
         dma rc=0, 4096 bytes, all 0xFF                           (refused)
```

So the GPU path is fully functional and is **not** generically blocked from system
RAM: a kernel `.data` physical is read back byte-identical to what the CPU sees
for the same address. But the physical that the CPU page tables give for `.text`
returns **all-ones**.

Interpretation: the `.text` pages are protected **below** the page-table
permissions -- the XOTEXT/nda bit is not the whole mechanism. Both access paths
now agree:

* CPU, through the kernel VA: faults/panics (even after the escape and a real
  suspend);
* CPU, through a self-made mapping of the physical: panics;
* GPU, through a retargeted GPU PTE with the system-coherent flag: returns 0xFF.

A faulting/refused read is not a wrong address: the same recipe reads a
`.data` physical of the same kernel image correctly.

### Where that leaves the four values

Reading kernel `.text` on this console/firmware looks closed for live extraction.
The practical routes that remain:

1. **offline**: obtain a 13.60 firmware image (kernel + HV) and derive
   `KERNEL_CFI_CHECK`, `FUN_SMP_RENDEZVOUS`, the hypercall-4 wrapper and the HV
   VMMCALL handler with the tooling already on the build host (REA/Ghidra). No
   console risk, and it does not need `break_hv`;
2. **HV carveout through the GPU**: the GPU read path works for system RAM, and
   the HV reservation is a physical range -- worth one probe (the reference
   documents report it as readable even though it can be encrypted at rest);
3. note that even with the four values, the phase-B takeover still needs an
   **armed khook across suspend**, which is separately fatal on this console
   (the diag=1 result); that blocker is independent of the offsets and deserves
   its own investigation (minimal chain, other payloads owning DR7/IDT/TSS).

---

## Update — 23:52 — the HV carveout is refused too; both protected regions read 0xFF

One run, same recipe, fresh victims:

```
VALIDATE retarget -> staging physical           -> RETARGET-OK
DATA     kva=0xffffffffd0d71000 -> cpu[0]=0xffffffff81530282
         dma rc=0 gpu[0]=0xffffffff81530282     -> SYSRAM-READ-OK
TEXT     kva=0xffffffffd00b0000 (pa 0x100b0000) -> 4096 bytes of 0xFF
HV       HV_BASE=0x062800000, retarget -> 0x440000628004f7
         first page 4096 bytes                   -> all 0xFF
         anchor page at +0x1ba10 ("hvcGF")       -> all 0xFF, no anchor
```

So the GPU read path distinguishes three kinds of memory:

| region | CPU read | GPU read (retarget + bit50) |
|---|---|---|
| ordinary kernel `.data` (`kva=0xffffffffd0d71000`) | works | **works, bytes identical** |
| kernel `.text` | faults / panics | **all-ones** |
| HV reservation (`0x062800000`) | not mapped in the dmap | **all-ones** |

Both protected regions are therefore protected **below** the page-table
permissions, and the protection is applied to *any* reader, not just the CPU.
That closes live extraction on this console: neither the kernel `.text` offsets
nor the HV VMMCALL handler can be read out of a running system by either path.

### Consequences

* the four values cannot be obtained from this console by reading memory;
* the reference recipe that reads the HV "through the GPU" does not transfer to
  this console/firmware (our result: 0xFF), so that document's claim should not be
  relied on here;
* an offline route needs a 13.60 kernel/HV image, and dumping it locally is
  blocked by the same protection (the carveout reads 0xFF) -- it would have to
  come from an external firmware source;
* the second, independent blocker remains: an **armed khook across suspend is
  fatal** on this console, so even with the offsets the phase-B takeover cannot
  work as designed today.

The GPU-DMA tooling (`tools/pl5-gpu-read.c`) is nevertheless a fully working
primitive on this console: retarget plus `PACKET3_DMA_DATA` copies any
non-protected physical to a CPU-readable buffer, verified against both a known
pattern and a `.data` page. It is the right tool to re-run if a future firmware
protects less, or to read `.data`-resident values.

## Update — 2026-10-16 (round 3) — integration defects fixed; offsets re-verified offline

Two integration defects that the notes had flagged as suspicions are now
**confirmed by test** and fixed, and every kernel value is re-derived by a
committed, reproducible tool.

### Fixed

1. **`make PL5_1360_TAKEOVER=1` was a silent no-op.** The Makefile never
   forwarded the flag to the compiler, so the in-source `#define
   PL5_1360_TAKEOVER 0` won and the build shipped phase-A-only while the
   operator believed phase B was enabled. The Makefile now has
   `PL5_1360_TAKEOVER ?= 0` and passes `-DPL5_1360_TAKEOVER=$(PL5_1360_TAKEOVER)`.
2. **A phase-B build now refuses zero placeholders** instead of arming a
   takeover that would jump through address 0: two `#error` guards in
   `source/hv/defeat/hv_defeat_1360.c` fire on the still-empty
   `PL5_1360_HV_VMMCALL_HANDLER_PA` / `PL5_1360_FUN_VMMCALL_HC4`.

### Verified by build

```
$ make                          -> EXIT 0, bin/pLinux5-NG.elf (256824 B)
$ make PL5_1360_TAKEOVER=1      -> EXIT 2, both #error guards fire (expected)
$ python3 tools/verify_off_1360.py <13_60.h>      -> PASS (57 values)
$ python3 tools/verify_off_1360_dump.py           -> 22/22 checks passed
```

### Offsets

`FUN_HV_IOMMU_SET_BUFFERS` corrected `0x4FB13D` -> **`0x4FABD0`** (the old value
is mid-function). `KERNEL_CODE_CAVE` set to **0**: the value it carried
(`0x2D39000`) is Byepervisor's `KERNEL_SYM_DATA_CAVE`, a *data* address, not a
code cave. `KERNEL_SYM_PMAP_STORE = 0x3B48FF8` confirmed (the `0x3B24FF8` hint
is unsupported — that offset reads all-zero in the dump). Details and the full
evidence table: `docs/1360-offsets-from-dump.md`, section *Round 3*.

### Not moved

Phase B and S3 resume are **unchanged**: they need the hypervisor PAs, which a
kernel capture cannot contain, and console time. The `.text` power-off
explanation in `docs/1360-offsets-from-dump.md` was itself wrong and is
corrected there rather than left standing.

## Update — 2026-10-16 (round 4) — the shared takeover blob is firmware-parameterized

The blob written into the live kernel by the post-resume takeover
(`source/shellcode/hv_takeover/takeover.S`) had 13.20 addresses baked into its
instruction body: the HV handler PA, the CFI handler, the smp_rendezvous
wrapper, the hypercall-4 wrapper and the `ret` gadget. Anything that built the
blob for 13.60 would have silently written a *13.20* patch into a 13.60 kernel.

Every firmware-specific constant now lives in one guarded block selected by
`PL5_TAKEOVER_FW`; the instruction body references only macro names.

```
$ python3 tools/verify_takeover_param.py        -> 12/12
$ make                                          -> EXIT 0
$ make PL5_TAKEOVER_FW=1360                     -> refused (HV handler PA unknown)
$ make PL5_1360_TAKEOVER=1                      -> refused (3 errors)
```

**Behaviour-preserving for the firmware that works today:** the rebuilt 13.20
blob is **byte-identical** to the one shipped before the split (144 B,
sha256 `c6cfbaa3dffc5638…`), verified by building the pre-change source with the
same toolchain and comparing bytes.

### What this does NOT do

It does not make phase B work on 13.60. It removes a whole class of silent
error: a 13.60 takeover can no longer inherit 13.20 addresses. The 13.60 blob
still cannot be built, because `HV_VMMCALL_HANDLER_PA` is HV-resident and a
kernel dump cannot contain it — the build says so instead of guessing.

`hv_defeat_1360.c` now also refuses to arm 13.60 with a blob built for another
firmware (`PL5_TAKEOVER_FW != 1360`), so the two sides cannot disagree.

**Still 13.20-hardcoded (not part of this change):** `hv_defeat_1320.c`
duplicates `0x62847375` in five places (lines ~149/633/636/646/652) instead of
naming it once. Same class of contamination, different file; left alone because
13.20 is the working platform and the change is untestable here.
`solution/shellcode/hv_takeover/takeover.c` was reported here as dead code still
carrying the 13.20 defines. It is **not present in this branch and was never
tracked here** (`git ls-files solution/` is empty), so the ambiguity is gone: the
canonical blob is `source/shellcode/hv_takeover/takeover.S`. See
[`SOURCE-MAP.md`](SOURCE-MAP.md) for the live/generated/historical map.

## Update — 2026-10-16 (round 6) — armed-gate anatomy on 13.60; the 13.20 differential is blocked

Offline analysis of `k1360.bin` (sha256 `c3f745e2…cddd`), no console involved.

### The 13.60 IDT/TSS decode cleanly

`IDT = 0x3BB4300` (Byepervisor-verbatim) is a valid 32-vector table: every gate
present, type `0xE`, selector `0x20`, handlers are 16-byte `jmp <handler>; int3`
thunks in a table at `ktext+0x26A000`. IST assignment is the standard kernel map:

| vector | thunk | IST |
| --- | --- | --- |
| #DF (8) | ktext+0x26A330 | IST1 |
| NMI (2) | ktext+0x26A308 | IST2 |
| #MC (18) | ktext+0x26A378 | IST3 |
| **#DB (1)** | ktext+0x26A070 | **IST4** |
| #VC (29) | — | IST5 |
| **IST6 / IST7** | — | **0 (free)** |

`COMMON_TSS = 0x3BB6FE0` also decodes: `RSP0 = 0xffffff8097807a40` is a canonical
kernel stack, i.e. it passes the khook's own sanity check
(`(RSP0 >> 47) == 0x1FFFF`).

### What arming actually does

From `khook.c` (identical to upstream `Byepervisor-Reborn/khook.c` apart from the
P4 bisection masks on `kh_diag_skip_mask`):

* the #DB **gate** is rewritten to the ROP pivot
  (`kgadget(KERNEL_GADGET_PIVOT_ADD_RSP28_RET)`) with `IST = kh->ist_index` (6);
* the hijack **chain pointer** is written into the TSS **IST6 slot**.

So IST6 is overloaded: it is simultaneously the stack pointer the CPU loads for
#DB *and* the redirect surface. Any #DB taken while armed therefore diverts into
the chain with something that is not a real stack. That is fatal by construction
if a #DB arrives that the design did not intend to catch.

### Not a port artifact

`HOOK_IST` (6), `TSS_STRIDE` (0x68) and `HOOK_CORE` (0) are **identical** in
`hv_defeat_1320.c` and `hv_defeat_1360.c`, and the vendored khook differs from
upstream only by the P4 masks. `IDT`/`COMMON_TSS` differ between the two
firmwares by a constant `+0x24000` (same delta as `PMAP_STORE`) and both values
are Byepervisor-published. So the code does not arm 13.60 any differently from
13.20: whatever differs is environmental.

### Blocked: the 13.20 differential

The planned comparison (IDT/IST/TSS contents and the #DB handler between 13.20
and 13.60) **cannot be done today**: no 13.20 (or 13.00) kernel dump is
available. A repository/code search found only
`terrafirma2021/ps5-13.60-kernel-dump`. Without a second image there is nothing
to diff, so "why is the armed gate fatal on 13.60 and not on 13.20" is not
answerable offline. It needs either a 13.20 image or a live observation.


## Update — 2026-10-16 (round 7) — PUP analysis and HV-address status

The 13.60.00 Recovery PUP was inspected offline (SHA-256
`e210451f789ebe46f55b13ae049894663b796163f7b094ab993218f1cb20aa97`).
The container inspection found two nested PUPs, at `0x400` and
`0x4A5AE600`. Their headers are visible, but the examined payload remains
encrypted and no visible segment-name entry identifies a standalone
hypervisor image. The available public PUP-decryption path depends on the
console's EncryptService; the tested console endpoint returned `EPERM`.
Therefore the current PUP/tooling path has not yielded an HV image. This is a
bounded result for the examined artifact and tools, not a claim that every
possible offline decryption technique is impossible.

The verified community kernel image was analyzed as an ELF at VA
`0xffffffff9e3f0000` with Ghidra headless and REA. The scan recorded 37
`vmmcall` sites and zero `vmrun`, `vmload`, or `vmsave` sites. This
supports the distinction between guest-side hypercall wrappers and the
hypervisor implementation; it does not recover an HV handler address.

The guest hypercall-4 wrapper at `0xC16A10` is confirmed by instruction
decoding and a raw-byte scan. REA uses Ghidra 12.1.4 as its native provider
in this analysis, so agreement between REA and Ghidra is not an independent
engine cross-check; the raw-byte scan provides the separate check. The
IOMMU buffers function entry is `0x4FABD0`, as already recorded in the
offsets document.

Current disposition:

* `HV_VMMCALL_HANDLER_PA`: **unknown**. The guest wrapper is not the
  hypervisor handler; no verified 13.60 HV image was available.
* `HV_CODE_CAVE_PA` and `HV_HANDLE_VMEXIT_PA`: remain unset unless the
  selected implementation requires them and an adequate source proves their
  values. Do not reuse legacy addresses from older firmware.
* The takeover guard remains necessary. These findings do not establish a
  working takeover or a successful Linux boot on 13.60.

See [1360-offsets-from-dump.md](1360-offsets-from-dump.md) for the evidence and
artifact details.
