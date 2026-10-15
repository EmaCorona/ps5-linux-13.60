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
/home/emacorona/src/ps5-linux-13.60          # this fork, branch feature/13.60-support
/home/emacorona/src/ps5-sdk-dl/sdk/ps5-payload-sdk        # v0.44 prebuilt
/home/emacorona/src/ps5-sdk-dl/plabs5/pLabs5-SDK-main     # for LLVM_CONFIG
```
