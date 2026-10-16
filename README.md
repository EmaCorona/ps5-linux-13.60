# pLinux5-NG

> Experimental Linux boot project for PlayStation 5. **Linux boot is confirmed on firmware 13.20; firmware 13.60 is not yet bootable.**

pLinux5-NG adapts the Linux boot path from [ps5-linux-loader](https://github.com/ps5-linux/ps5-linux-loader) to the high-firmware escape architecture derived from [Byepervisor-Reborn](https://github.com/PS5Dev/Byepervisor-Reborn).

The project is a work in progress. Firmware support is version-specific; a shared code path or populated offset table does not, by itself, establish compatibility.

> [!WARNING]
> The 13.60 path is experimental. Tests have caused service loss and console shutdowns while the hook is armed. The post-resume takeover is incomplete and Linux does not boot on 13.60. Do not treat a successful build or escape-stage test as proof of a working boot.

## Support status

| Firmware | Status |
| --- | --- |
| 3.00–7.61 | Uses the upstream ps5-linux-loader path; refer to that project's support information. |
| 8.00–13.00 | Not validated across this range; firmware-specific support remains incomplete. |
| 13.20 | **Supported** — Linux boot confirmed. |
| 13.60 | **Experimental / blocked** — phase A has been exercised on hardware; the hook and post-resume takeover remain unresolved. |

## Overview

The existing Linux boot path prepares the kernel and initrd, sets up <code>boot_params</code> and e820 memory information, initializes required hardware, and transfers execution to the Linux entry point.

For high firmware, the main porting work is the firmware-dependent escape, offset table, and reliable handoff after resume. On 13.60, the current global <code>#DB</code> hook can interfere with unrelated processes, and the post-resume takeover is not complete.

## Requirements

### Target console

- A PS5 running a firmware supported by the table above.
- A compatible jailbreak environment with <code>elfldr</code> reachable over the local network (default port <code>9021</code>).
- Rest-mode configuration appropriate for the selected firmware path.

For the currently tested escape path, keep **Supply Power to USB Ports** set to **Always** and disable **HDMI Device Link**. HDMI-CEC behavior can otherwise be confused with an exploit failure.

### Build environment

- [PS5 payload SDK](https://github.com/ps5-payload-dev/sdk).
- [pLabs5-SDK](https://github.com/pLabs5/pLabs5-SDK), used to provide <code>LLVM_CONFIG</code>.
- GNU Make, a host C compiler, and the host GCC used to build freestanding shellcode.
- Alternatively, Docker Buildx.

## Build

Set the paths for the installed SDKs, then build from the repository root:

    export PS5_PAYLOAD_SDK=/path/to/ps5-payload-sdk
    export LLVM_CONFIG=/path/to/pLabs5-SDK/tools/nixos/llvm-config
    make -j"$(nproc)" all

The main payload is written to <code>bin/pLinux5-NG.elf</code>.

To build using Docker Buildx:

    docker buildx bake

The Bake target writes the release artifacts to <code>bin/</code>, including <code>pLinux5-NG.elf</code> and its SHA-256 file.

Shellcode is compiled as freestanding code and embedded into the final payload as generated C headers. The build uses <code>scripts/bin2c.py</code> rather than depending on <code>xxd -i</code>.

### 13.60 takeover guard

The default <code>PL5_1360_TAKEOVER=0</code> build excludes phase B, whose required references are not yet available. This is a fail-closed build setting, **not a guarantee that the experimental 13.60 hook is safe to run**. Firmware 13.60 does not currently boot Linux.

## Run the payload

Ensure that <code>elfldr</code> is already running on the console and reachable from the host. From the repository root, send the default build:

**Linux**

    PS5_IP=<console-ip> ./scripts/send.sh

To send a specific ELF instead:

    PS5_IP=<console-ip> ./scripts/send.sh /path/to/payload.elf

**Windows PowerShell**

    .\scripts\send.ps1 -PS5IP <console-ip>

The send scripts default to port <code>9021</code>; override it with <code>PS5_PORT</code> on Linux or <code>-Port</code> on Windows.

**Important:** use only a firmware known to work for the result you expect. On 13.20, Linux boot is supported. On 13.60, the current payload is still experimental and does not provide a working Linux boot.

## Architecture

| Path | Purpose |
| --- | --- |
| <code>source/main.c</code> | Entry point and firmware dispatch. |
| <code>source/core/</code> | Core primitives, logging, process and memory helpers. |
| <code>source/offsets/</code> | Firmware-specific kernel and hypervisor offset tables. |
| <code>source/hv/defeat/</code> | Firmware-specific escape implementation. |
| <code>source/byepervisor/</code> | Vendored Byepervisor-derived components. |
| <code>source/boot/</code> | Resume preparation and Linux boot handoff. |
| <code>source/hw/</code> | Firmware, GPU and device helpers. |
| <code>source/shellcode/</code> | Freestanding shellcode embedded into the payload. |
| <code>tools/</code> | Host-side generators, verifiers and payload utilities. |
| <code>scripts/</code> | Build and payload-transfer helpers. |
| <code>docs/</code> | Technical evidence, status reports and investigation notes. |

## Known limitations

- **13.60 does not boot Linux.** The post-resume takeover remains blocked.
- The armed <code>#DB</code> hook is not stable and has disrupted services or caused shutdowns in tests.
- <code>HV_VMMCALL_HANDLER_PA</code> for 13.60 remains unknown. A guest-side kernel hypercall wrapper is not the hypervisor-side handler.
- <code>HV_CODE_CAVE_PA</code> and <code>HV_HANDLE_VMEXIT_PA</code> are not established for 13.60; do not reuse addresses from older firmware without evidence.
- Several data, audio, display and Wi-Fi references remain unresolved or need further validation.
- Live reads of kernel <code>.text</code> are prohibited by the validation tooling because previous attempts caused fatal failures. A separate fatal read at <code>0x2D39000</code> remains unexplained; the dump classifies that offset as data, not code.
- Firmware-specific offsets and behavior must be validated independently. Do not infer support for every version in a range from the support of one version.

## Documentation

Start with the [documentation index](docs/README.md).

| Document | Contents |
| --- | --- |
| [13.60 port status](docs/1360-port-status.md) | Implementation status, experiments, evidence and remaining blockers. |
| [13.60 offset analysis](docs/1360-offsets-from-dump.md) | Kernel-dump provenance, offset derivations, validation and limits. |
| [13.60 khook investigation](docs/1360-khook-death.md) | Evidence and analysis of the unstable armed hook. |
| [Analyst recap](docs/analyst-recap-1360.md) | Investigation handoff, results and open questions. |
| [Upstream loader README](docs/upstream-ps5-linux-loader-README.md) | Reference documentation from ps5-linux-loader. |

The documentation distinguishes measured observations, static derivations, hypotheses and unresolved questions. Treat historical notes as an investigation record and use the current status above for the project summary.

## License and attribution

This project is licensed under **AGPL-3.0-only**. The boot path and shellcode derive in part from [ps5-linux-loader](https://github.com/ps5-linux/ps5-linux-loader), and components under <code>source/byepervisor/</code> derive from [Byepervisor-Reborn](https://github.com/PS5Dev/Byepervisor-Reborn). Retain the original copyright and license notices for third-party code.

## Disclaimer

This project is independent and is not affiliated with, endorsed by, or sponsored by Sony Interactive Entertainment. The software is provided “as is”, without warranty. You are responsible for complying with applicable laws and the terms governing any software or services you use.
