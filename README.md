# pLinux5-NG

> Experimental Linux boot project for PS5 high firmware (8.xx–13.60). Linux boot is confirmed on 13.20; 13.60 remains blocked.

`pLinux5-NG` ports the [ps5-linux-loader](https://github.com/ps5-linux/ps5-linux-loader)
boot path to the high-firmware escape implemented by
[Byepervisor-Reborn](https://github.com/PS5Dev/Byepervisor-Reborn).

The reused Linux path covers bzImage/initrd placement, `boot_params`/e820 setup, hardware
initialization, SVM/IOMMU teardown and the jump to `startup_64`. The firmware-dependent part is
the escape and its offset table: the upstream loader uses flatz' ACPI-wakeup ROP path on firmware
3.00–7.61, while this project uses the Byepervisor-derived khook path on high firmware.

> [!IMPORTANT]
> This project is **experimental and work in progress**. Linux boot is supported on **13.20**.
> On **13.60**, phase A has been exercised on hardware, but the post-resume takeover is blocked;
> Linux does **not** boot on 13.60 yet. See [13.60 port](#1360-port).

The payload is intended to run from RAM and does not intentionally install permanent software.
However, the current 13.60 hook path is known to disrupt services and has caused shutdowns during
testing; do not treat experimental runs as risk-free.

## What it solves

A retail PS5 normally runs its own system software under the hypervisor. Booting Linux requires
a working escape, a reliable handoff across all required cores, and a boot path that prepares the
kernel and hardware correctly. The steps below show the **intended end-to-end flow**; the final
takeover is not yet working on firmware 13.60.

```text
Retail PS5, high firmware (8.xx … 13.60)
    guest kernel + hypervisor, no root of the machine

        ↓

jailbreak (kernel R/W)  →  elfldr on :9021
    we can read and write the guest kernel

        ↓

pLinux5-NG escape (khook on the S3-resume path)
    kernel .text made writable, XOTEXT cleared
    hook installed on HV_MP_STARTUP_CALL → break_hv
    rest mode → resume with NPT disabled

        ↓

post-resume takeover (phase B — blocked on 13.60)
    stage Linux images and boot structures
    complete the handoff, then boot

        ↓

Linux on the PS5
    bzImage + initrd at the addresses boot_params expects
```

The payload is designed to be transient and does not intentionally flash firmware or install a
permanent system component. Failure behavior depends on the stage reached; the current 13.60 hook
has caused service loss and shutdowns during testing.

You do not need to know what a khook, an NPT or an SVM VMCB is to use it: those details live in
[`docs/`](docs/).

## Highlights

### One escape, many firmwares

High-firmware variants share an escape design, but each supported firmware needs the correct
offset table and compatibility checks. `source/offsets/off_<fw>.c` holds firmware-specific symbols
and gadgets; `source/main.c` selects the corresponding path. A shared code path does not imply that
every firmware is supported or validated.

### Offsets that can be checked, not guessed

The documented 13.60 kernel offsets are derived from a verified community kernel capture using
instruction decoding and references, with additional live corroboration only where explicitly
recorded. This does **not** mean every value has been validated live, and a kernel capture cannot
establish addresses that belong to a separate hypervisor image. Methods, hashes and known limits are
recorded in [`docs/1360-offsets-from-dump.md`](docs/1360-offsets-from-dump.md).

### A destructive probe stays destructive only once

Live reads of kernel `.text` are prohibited by the validation tooling because prior attempts have
caused fatal failures on this console. A separate read at `0x2D39000` also powered the console off,
even though the verified dump places that offset in the data region; the cause of that incident is
still unknown. The tools reject `.text` probes and mixed address namespaces; see the port notes for
the exact evidence and remaining uncertainty.

### Boot path reused, not rewritten

The Linux boot path is derived from ps5-linux-loader: bzImage/initrd placement, `boot_params`/e820,
hardware initialization, SVM/IOMMU teardown and the jump to `startup_64`. The main porting risks are
the firmware-specific escape, required references and reliable post-resume handoff.

### Freestanding shellcode, embedded

The shellcode blobs (`hv`, `kernel`, `break_hv`, `hv_boot`, `hv_takeover`) are compiled freestanding
with the host gcc and embedded as C headers, so the payload is a single ELF to send.

### Fail-closed by default

`PL5_1360_TAKEOVER=0` (the default) compiles phase B out. This prevents an incomplete takeover
from being executed; it does **not** make the experimental hook intrinsically safe. On 13.60, treat
the default build as diagnostic only: it does not boot Linux, and the armed-hook path has known
stability problems.

## Quick start

1. Set the two PS5 settings in [CRITICAL](#critical) — they are not optional.
2. Run the [jailbreak](#running-the-jailbreak) so `elfldr` is listening on port `9021`.
3. Get `pLinux5-NG.elf` from releases, or [build it](#building).
4. [Send it](#sending) to the console.

## Requirements

### Platform

- a PS5 whose firmware is in the supported range (see [firmware support](#firmware-support)),
- a jailbroken console with `elfldr` reachable on the LAN,
- rest mode configured as in [CRITICAL](#critical).

### Toolchain

- the [PS5 payload SDK](https://github.com/ps5-payload-dev/sdk),
- the [pLabs5-SDK](https://github.com/pLabs5/pLabs5-SDK) (for `LLVM_CONFIG`),
- a C compiler on the host (the shellcode builds with the host gcc).

## CRITICAL

PS5 configuration. Both settings matter, and one of them will look like a crash if you skip it:

- enable rest-mode features:
  `settings` → `system` → `power saving` → `features available in rest mode`,
  set **`Supply Power to USB Ports`** to **`Always`**;
- disable HDMI device link:
  `settings` → `system` → **`HDMI`**, set **`Enable HDMI Device Link`** to **`off`**.

With HDMI Device Link left on, the TV's CEC can power the console off around rest mode — which
looks exactly like a failed escape and will send you hunting a bug that is not there.

## Running the jailbreak

- point the console's DNS at `45.56.67.85`:
  `settings` → `network` → `settings` → `set up internet connection`, press the options button on
  the controller, `advanced settings`, set **`primary DNS`** to `45.56.67.85`, confirm. An
  `internet connection failed` popup is expected and fine;
- open the user's guide:
  `settings` → `Guide & Tips, Health and Safety, and Other Information` → `User's Guide`;
  when the page asks whether to continue despite the certificate, accept;
- on the page that says **RELAPSE**, press `Jailbreak` and wait — it is done when `elfldr` starts.

Then build or download `pLinux5-NG.elf` and go to [sending](#sending).

## Sending

On Linux/unix:

```bash
# from the repository root, with the payload in bin/
cd scripts/
chmod +x send.sh
./send.sh PS5_IP=<Playstation 5's IP> PS5_PORT=9021
```

On Windows, in PowerShell:

```powershell
.\scripts\send.ps1 -PS5IP <Playstation 5's IP> -Port 9021
```

or from CMD:

```cmd
powershell -ExecutionPolicy Bypass -File .\scripts\send.ps1 -PS5IP <Playstation 5's IP> -Port 9021
```

## Building

### Locally

```bash
export PS5_PAYLOAD_SDK=/path/to/ps5-payload-sdk
export LLVM_CONFIG=/path/to/pLabs5-SDK/tools/nixos/llvm-config
make -j
```

The output is `bin/pLinux5-NG.elf`.

Shellcode blobs are compiled freestanding with the host `gcc` (`-ffreestanding -nostdlib`) and
embedded as C headers; `scripts/bin2c.py` replaces `xxd -i`, which is not present everywhere.

### Docker

```shell
docker buildx bake
```

The output lands at `bin/pLinux5-NG.elf`.

## How it works

1. **Jailbreak, then payload.** The console has kernel read/write and `elfldr` loads
   `pLinux5-NG.elf`. The payload identifies the firmware and selects its offset table.
2. **Escape.** The high-firmware path prepares the required kernel state and uses the S3-resume
   `HV_MP_STARTUP_CALL` path. Phase A has been exercised on 13.60 hardware, but the armed hook is
   not yet stable and must not be treated as a completed end-to-end escape path.
3. **Takeover (phase B).** The intended handoff stages Linux images, boot structures and required
   shellcode before transferring control to the Linux boot path. Phase B is blocked on 13.60 while
   required hypervisor references and the post-resume execution path remain unresolved.
4. **Linux.** The intended result is to boot bzImage and initrd using the prepared `boot_params`.

Linux boots on 13.20. On 13.60, phase A has been exercised but phase B and the Linux boot have not
been demonstrated; see [13.60 port](#1360-port).

## Firmware support

| firmware | escape | Linux boot |
| --- | --- | --- |
| 3.00 … 7.61 | flatz ACPI-wakeup ROP (upstream ps5-linux-loader) | upstream |
| 8.xx … 13.00 | Byepervisor khook design | not validated across this range; firmware-specific offsets/support remain incomplete |
| 13.20 | Byepervisor khook | **supported** |
| 13.60 | Byepervisor khook, confirmed on hardware | **blocked** — see below |

## 13.60 port

13.60 follows the same overall escape and boot architecture, but its offsets and high-firmware
references must be validated independently. Shared code does not establish firmware compatibility.

In place today:

- `source/offsets/off_1360.c` — kernel/HV symbols and gadgets (from Byepervisor-Reborn's
  [`13_60.h`](https://github.com/EchoStretch/Byepervisor-Reborn/blob/main/include/offsets/13_60.h)),
  extended with values derived and validated in this project;
- `include/hv/defeat/hv_defeat_1360.h` and `source/hv/defeat/hv_defeat_1360.c`;
- routing in `source/main.c` / `source/core/utils.c` (`case 0x1360`).

The phase-A path has been exercised on 13.60 hardware. This is not proof of a stable armed hook,
a working post-resume takeover or a Linux boot.

**Kernel offsets with recorded static evidence** (the method, input hashes and individual validation
status are documented in [`docs/1360-offsets-from-dump.md`](docs/1360-offsets-from-dump.md); not every
value has been confirmed by a live read):

| value | 13.60 |
| --- | --- |
| `KERNEL_CFI_CHECK` | `0x44F8C0` |
| `FUN_SMP_RENDEZVOUS` | `0xB04440` |
| `FUN_HV_IOMMU_SET_BUFFERS` | `0x4FABD0` |
| `FUN_HV_IOMM_WAIT_COMPLETION` | `0x4F9030` |
| `GAD_WRMSR_RET` | `0x255034` |
| hypercall-4 wrapper | `0xC16A10` |
| `G_VBIOS` | `0x3DDB9F0` |

**Still blocking a Linux boot on 13.60:**

- `HV_VMMCALL_HANDLER_PA` remains **unknown**: the guest-side wrapper at `0xC16A10` is not the
  hypervisor handler, and the examined PUP/kernel artifacts have not yielded a verified 13.60 HV
  image. Do not substitute a legacy `0x628xxxxx` value. `HV_CODE_CAVE_PA` and
  `HV_HANDLE_VMEXIT_PA` must remain unset unless the active design requires them and credible
  13.60-specific evidence establishes their values;
- several data/audio/display references remain unresolved or require reconciliation, including
  `IOMMU_SOFTC`, `DATA_BASE_GVMSPACE`, `FUN_MP3_*`, `FUN_TRANSMITTER_CONTROL` and the Wi-Fi firmware
  pair. Determine which are genuinely required for the first boot rather than treating every
  placeholder as equally blocking;
- **the armed khook is not stable**: the global `#DB` gate can route unrelated debug exceptions into
  a chain that assumes its own trap context. Tests recorded service loss and shutdown when armed;
  restoring the gate immediately after a diagnostic trigger avoided that specific failure but does
  not solve the required resume path. Full evidence is in
  [`docs/1360-khook-death.md`](docs/1360-khook-death.md).

`PL5_1360_TAKEOVER=0` (default) compiles phase B out and retains the fail-closed guard. This only
prevents execution of the incomplete takeover; it does not make an armed 13.60 run risk-free.

## Project structure

```text
source/
  main.c            entry point and firmware routing
  core/             kernel primitives, logging, process and memory helpers
  offsets/          per-firmware offset tables (off_<fw>.c)
  hv/defeat/        the hypervisor escape, per firmware family
  byepervisor/      vendored khook + kdlsym (see license)
  boot/             resume preparation and the Linux boot handoff
  hw/               firmware, GPU and device helpers
  shellcode/        freestanding blobs, embedded as C headers
  manifest/         payload identity (name, version)
include/            mirrors source/
tools/              host-side generators and the on-console tools
docs/               documentation (see below)
scripts/            build and send helpers
bin/                build output (not in git)
```

## Documentation

```text
docs/README.md                 index of the documentation below
docs/1360-port-status.md       chronological record: what was tried, what the console did
docs/1360-offsets-from-dump.md evidence, derivations and limits of the 13.60 offsets
docs/1360-khook-death.md       why the armed khook kills this console, with the bisection
docs/analyst-recap-1360.md     handoff summary with raw evidence, questions and next steps
docs/upstream-ps5-linux-loader-README.md  the upstream project's README, for reference
```

`docs/` is written as evidence: commands, raw output and readings, so a claim can be re-checked
rather than taken on trust.

## Limitations

- Only **13.20** boots Linux today; 13.60 escapes but cannot take over yet.
- The escape requires **rest mode** and a physical wake-up: the console must actually suspend and
  resume for the hook to run.
- Live reads of kernel `.text` are prohibited by the validation tooling because prior attempts
  have failed fatally on this console. A separate read at `0x2D39000` (classified as data by the
  dump) also powered the console off for an unresolved reason; do not present that incident as proof
  that the address lies in `.text`. See [offset evidence](docs/1360-offsets-from-dump.md).
- The armed khook currently captures `#DB` from every process, not only ours (see
  [13.60 port](#1360-port)); until it is scoped, an armed run is expected to disturb other payloads.
- The console's firmware version must be in the supported range; an unsupported one stops with
  `something went wrong during initialization` and changes nothing.

## License

This project is licensed under the **AGPL-3.0** licence.
The boot path and shellcode are derived from **ps5-linux-loader**, which is **GPL-3.0**; those files
retain their original authorship and are used here in accordance with the GPL/AGPL compatibility
provisions. The high-firmware escape is adapted from **Byepervisor-Reborn**, whose `khook.c`,
`kdlsym.c` and `paging.c` are vendored under `source/byepervisor/` and keep their notices.

## Legal

I, niko86c/pLabs5, as well as its contributors, are not affiliated with, associated with, sponsored
by, endorsed by or otherwise established with Sony Interactive Entertainment, PlayStation, or any of
their other companies or works unless explicitly stated otherwise.
***Just because an explicit mention above isn't present does **NOT** mean otherwise.***

All software is provided "as is", without warranty of **ANY** kind, express or implied. Use all
software at your own risk.

You are solely responsible for complying with the terms of service of all programs, as well as any
applicable law.
