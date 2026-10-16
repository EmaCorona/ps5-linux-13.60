# pLinux5-NG

> Boot Linux on PS5 consoles running high firmware (8.xx through 13.60).

`pLinux5-NG` is a port of [ps5-linux-loader](https://github.com/ps5-linux/ps5-linux-loader)
— which works on 3.00 through 7.61 — to the newer
[Byepervisor-Reborn](https://github.com/PS5Dev/Byepervisor-Reborn) hypervisor escape.

The *Linux boot path* is brought over from ps5-linux-loader: bzImage/initrd relocation,
`boot_params`/e820 setup, hardware bring-up, SVM/IOMMU teardown and the jump to `startup_64`.
What changed is the **escape** — how code ends up running in hypervisor root mode on every core.
On 3.00 through 7.61 that is flatz' ACPI-wakeup ROP chain; on high firmware it is a khook on the
S3-resume `HV_MP_STARTUP_CALL` path, as implemented in Byepervisor-Reborn.

> [!IMPORTANT]
> This project is **very work-in-progress**. **13.20** is fully supported.
> **13.60** has its offset table and the escape wired up, and the escape is now
> confirmed on hardware — but the post-resume takeover is still blocked, so Linux
> does not boot on 13.60 yet. See [13.60 port](#1360-port).

**No permanent modification: the payload runs from RAM, and the console boots
normally the moment you don't send it.**

## What it solves

A retail PS5 does not let you run your own kernel: the hypervisor keeps the guest kernel's
`.text` read-only and non-executable-from-outside, and it owns the page tables the kernel runs on.
Getting Linux running means getting control of the machine underneath that guest — once, on every
core — and then handing the hardware over to a Linux kernel instead of to the PS5 system software.

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

post-resume takeover (phase B)
    stage the Linux images, the identity table and the hypervisor shellcode
    become root of the machine, then boot

        ↓

Linux on the PS5
    bzImage + initrd at the addresses boot_params expects
```

The payload is **per-run**: it changes nothing on disk, and if the escape or the takeover fails the
console is expected to boot its own system again. Nothing is flashed, no permanent tile is added.

You do not need to know what a khook, an NPT or an SVM VMCB is to use it: those details live in
[`docs/`](docs/).

## Highlights

### One escape, many firmwares

The high-firmware escape is the same code for every 13.xx version; only the offset table changes.
`source/offsets/off_<fw>.c` holds that firmware's kernel and hypervisor symbols and gadgets and
`source/main.c` routes to it by firmware version.

### Offsets that can be checked, not guessed

Every 13.60 value carried here is backed by evidence and, where possible, by a measurement on the
live console: the flashable ones are derived from a verified kernel capture and then read back
through the kernel to confirm the address still holds what the capture says. The method and the raw
readings are in [`docs/1360-offsets-from-dump.md`](docs/1360-offsets-from-dump.md).

### A destructive probe stays destructive only once

Reading kernel `.text` on this console powers it off. That lesson is encoded in the tooling: the
validation probe refuses any offset that would fall inside `.text`, refuses to mix namespaces, and
will not read anything until it has printed exactly what it is about to read.

### Boot path reused, not rewritten

bzImage/initrd relocation, `boot_params`/e820, hardware bring-up, SVM/IOMMU teardown and the jump to
`startup_64` all come from the existing ps5-linux-loader. The port surface is the escape, not the
Linux boot.

### Freestanding shellcode, embedded

The shellcode blobs (`hv`, `kernel`, `break_hv`, `hv_boot`, `hv_takeover`) are compiled freestanding
with the host gcc and embedded as C headers, so the payload is a single ELF to send.

### Fail-closed by default

`PL5_1360_TAKEOVER=0` (the default) compiles phase B out entirely. A 13.60 build is then safe to
run: it confirms the escape and stops, instead of jumping into a takeover whose addresses are not
known yet.

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
LLVM_CONFIG=/path/to/pLabs5-SDK/tools/nixos/llvm-config
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
   `pLinux5-NG.elf`. The payload identifies the firmware and selects the matching offset table.
2. **Escape.** The guest kernel's `.text` is made writable and its `XOTEXT` bit cleared, then a
   khook is installed on the S3-resume `HV_MP_STARTUP_CALL` path. The console is asked to enter
   rest mode; on resume the hook runs `break_hv` in hypervisor root mode with NPT disabled.
3. **Takeover (phase B).** From the resumed console the payload stages the Linux images, the
   identity-page-table table and the hypervisor shellcode, then transfers control so Linux can be
   booted as the root guest instead of the PS5 system.
4. **Linux.** The kernel is booted with bzImage and initrd where `boot_params` expects them.

Steps 1 and 2 are implemented and exercised on hardware for 13.20 and 13.60. Step 3 is what is
still missing on 13.60 — see [13.60 port](#1360-port).

## Firmware support

| firmware | escape | Linux boot |
| --- | --- | --- |
| 3.00 … 7.61 | flatz ACPI-wakeup ROP (upstream ps5-linux-loader) | upstream |
| 8.xx … 13.00 | Byepervisor khook | boot path present, that firmware's offsets still missing |
| 13.20 | Byepervisor khook | **supported** |
| 13.60 | Byepervisor khook, confirmed on hardware | **blocked** — see below |

## 13.60 port

13.60 reuses the 13.20 escape and boot path verbatim; only the offset values change.

In place today:

- `source/offsets/off_1360.c` — kernel/HV symbols and gadgets (from Byepervisor-Reborn's
  [`13_60.h`](https://github.com/EchoStretch/Byepervisor-Reborn/blob/main/include/offsets/13_60.h)),
  extended with values derived and validated in this project;
- `include/hv/defeat/hv_defeat_1360.h` and `source/hv/defeat/hv_defeat_1360.c`;
- routing in `source/main.c` / `source/core/utils.c` (`case 0x1360`).

With these, the escape runs on 13.60 and the console resumes with NPT disabled.

**Values filled in and validated on a live 13.60 console** (method and readings in
[`docs/1360-offsets-from-dump.md`](docs/1360-offsets-from-dump.md)):

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

- the **hypervisor** addresses (`HV_VMMCALL_HANDLER_PA`, `HV_CODE_CAVE_PA`,
  `HV_HANDLE_VMEXIT_PA`). On 8.00+ the hypervisor moved off the `0x628xxxxx` carve-out, so a kernel
  capture cannot contain them; they need a dump taken through the NPT alias;
- a few data/audio/display symbols that were already unknown on 13.20 (`IOMMU_SOFTC`,
  `DATA_BASE_GVMSPACE`, `FUN_MP3_*`, `FUN_TRANSMITTER_CONTROL`, the WiFi firmware pair). They gate
  the Linux boot, not the escape;
- **a design problem in the armed khook**, which is the one that actually costs the most today: once
  armed, the `#DB` hijack is global, so a debug exception belonging to *any other* process is
  delivered into our chain and resumed against a foreign context. Measured on hardware: with the
  `#DB` gate left untouched the console survives; with the gate installed but never exercised, the
  loader and the helper processes die; with the gate installed and exercised, the console performs
  an orderly power-off about a second later. Full evidence in
  [`docs/1360-khook-death.md`](docs/1360-khook-death.md).

Until that is settled, `PL5_1360_TAKEOVER=0` (default) keeps phase B compiled out, so a 13.60 build
is safe to run and stops after confirming the escape.

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
docs/1360-offsets-from-dump.md how the 13.60 values were derived and validated
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
- Reading kernel `.text` **powers the console off** on this hardware, so offsets cannot be recovered
  from a live console by reading text; that is why the tables come from captures and are validated
  on data addresses only.
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
