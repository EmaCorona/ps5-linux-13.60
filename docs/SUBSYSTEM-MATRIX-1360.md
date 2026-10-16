# Subsystem support matrix — 13.60

Two goals, kept apart:

| goal | definition | status |
| --- | --- | --- |
| **G1 — kernel entry** | the console leaves the guest and the Linux kernel begins initialising (headless) | **not achieved** |
| **G2 — usable Linux** | G1 plus display, network and audio working | **not attempted** |

Everything below is about **G1**. A subsystem is "on the path" only if the code executed before
`startup_64` touches it; being listed in `off_1360.c` is not the same thing (see
[`BOOT-REQUIREMENTS-1360.md`](BOOT-REQUIREMENTS-1360.md)).

## Matrix

| subsystem | on the path to the kernel entry? | where | what proves it / what it needs | test |
| --- | --- | --- | --- | --- |
| **memory map / e820** | **yes** | `source/shellcode/hv/boot_linux.c` (`append_e820_table`, VRAM as RAM + reserved) | the arithmetic and ordering are host-testable (Task 20 lane); the *values* need hardware | hardware session (Task 30) |
| **SMP (multi-core)** | **yes, as designed** | `boot_linux.c`: `atomic_add_32(&exited_cpus, 1)` and the `MAXCPU` barrier, with `HV_HEADLESS_SINGLE_CORE=0` | the barrier only completes if the takeover blob drove the kernel's `smp_rendezvous`; that in turn needs `FUN_SMP_RENDEZVOUS` and the 13.60 HV reference (Task 23) | hardware, after phase B |
| **IOMMU** | **yes** | `boot_linux.c`: `AMDIOMMU_CTRL &= ~1` before the hand-off | code-only today; the MMIO address used is a constant in the shellcode, not in `off_1360.c` | hardware |
| **GPU / VRAM** | **partially** | `boot_linux.c`: `configure_vram(FB_BASE, VRAM_BASE, vram_size)` runs before `boot_linux()`; `vram_size` comes from `vram.txt` with a static fallback | the *configuration* is on the path; the display **bring-up** symbols (`G_VBIOS`, `FUN_TRANSMITTER_CONTROL`) are read only by the legacy `prepare_sck_args()` path and are not reachable on 13.60 | configure: hardware; bring-up: G2 |
| **audio** | **no** | `FUN_MP3_INITIALIZE`/`FUN_MP3_INVOKE` only in `prepare_resume.c` | not reached on 13.60 | G2 |
| **Wi-Fi** | **no** | `hw/firmware.c:97` ← `dump_device_firmwares()` ← `loader.c` | runs for 13.60 but **fails gracefully** when the offset is 0 (`PS5 WiFi firmware offset missing`, and `loader.c` logs `Continuing`) | G2 |
| **serial / debug** | **no** | `KERNEL_UART_OVERRIDE` only in `prepare_resume.c` | not reached on 13.60; the shellcode prints through its own channel | — |

## What this means for the plan

- **Do not** treat a missing audio/Wi-Fi/display symbol as a blocker for G1. The 13.60 path never
  reads those fields; the registry records them as `blocks: none` for this path.
- **Do** treat SMP as a G1 dependency *of the current design*, and say so: with
  `HV_HEADLESS_SINGLE_CORE=0` the shellcode waits for every core, and the rendezvous is driven by the
  part of the takeover that still needs the unknown hypervisor reference. A single-core variant would
  remove that dependency and is the obvious fallback if Task 23 stays blocked — it is a design change,
  not a flag flip, and is recorded here rather than done.
- **Do not** claim G2 from a G1 result. The bring-up symbols for display/audio/reachability are
  unresolved (`[UNKNOWN]` in the registry) and their absence is not a licensing or evidence problem,
  it is simply not implemented.

## Hardware acceptance, per subsystem (for Task 25's sheet)

| to observe | how it is distinguished |
| --- | --- |
| kernel entry reached | console leaves the guest; the shellcode's own print; `PL5_HV_STOP` checkpoint output where supported |
| SMP barrier passed | the boot progresses past the checkpoint that follows it (stop=3) |
| IOMMU disabled | no separate signal; inferred from reaching `configure_vram` (stop=2) |
| display | only meaningful for G2 — a black screen is *expected* for G1 |

A screen that stays black is therefore **not** evidence of failure for G1, and a screen that lights up
is not evidence of success: the checkpoints and the console's own behaviour are the evidence.
