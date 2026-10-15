# Contributing

Thanks for wanting to help out. This project is early, so the single most useful thing is getting it
booting on more firmware.

## Where support stands

| firmware | escape | Linux boot |
| --- | --- | --- |
| 3.00 … 7.61 | upstream ps5-linux-loader | upstream |
| 8.xx … 13.00 | Byepervisor khook | boot path present, that firmware's offsets still missing |
| 13.20 | Byepervisor khook | **supported** |
| 13.60 | Byepervisor khook, confirmed on hardware | **blocked** by the armed-khook problem, not by offsets |

13.60 has its offset table (`off_1360.c`) and the escape wired up (`hv_defeat_1360.*`), and the
missing values have since been derived and validated. What still blocks it is documented in
[`docs/1360-khook-death.md`](docs/1360-khook-death.md): once armed, the `#DB` hijack is global and
captures traps belonging to other processes.

Every other high firmware (8.xx through 13.00) has the boot path in place but is missing that
firmware's kernel and hypervisor offsets.

## `something went wrong during initialization`

If you get this on boot:

> Something went wrong during initialization.
> Please make sure your fw is supported.

nothing is broken and your console is fine. It just means your firmware has not been added yet.

## Adding your firmware

Support is per version, and it comes from a table of kernel/hypervisor offsets
(`source/offsets/off_<fw>.c`, generated from the shared list in `include/offsets/offsets.h`). Those
offsets have to be pulled out of a real console running that firmware — reading kernel `.text` on a
live console is not an option, since it powers the console off.

If you can run a payload, you can generate everything needed with the offsets tool.

### 1. Build the offsets tool

```bash
export PS5_PAYLOAD_SDK=/path/to/ps5-payload-sdk
LLVM_CONFIG=/path/to/pLabs5-SDK/tools/nixos/llvm-config
make -C tools
```

This produces `tools/pl5-offsets.elf`.

### 2. Send it to your console

With `elfldr` running (the same way you send `pLinux5-NG.elf`):

```bash
PS5_IP=<your.ps5.ip> ./scripts/send.sh tools/pl5-offsets.elf
```

### 3. Collect the dump

The tool reads the kernel text/data and the hypervisor, works out every offset it can for your
firmware, and packs it into one zip. It lands in two places:

- on the console: `/data/pl5-<fw>.zip`
- on a USB stick, if one is plugged in: `pl5.zip` in the root

A USB stick is optional. Without one, grab the zip off `/data` over FTP.

### 4. Send it in

Attach the zip to the pinned firmware-offsets issue, along with:

- your exact firmware version,
- whether it is a regular or a pro console,
- the `report.txt` if you want to paste it inline.

Once the dump is in, the offsets can be turned into a table and your firmware gets added.

## Building

### Locally

Needs the [PS5 payload SDK](https://github.com/ps5-payload-dev/sdk), the
[pLabs5-SDK](https://github.com/pLabs5/pLabs5-SDK) and a C compiler:

```bash
export PS5_PAYLOAD_SDK=/path/to/ps5-payload-sdk
LLVM_CONFIG=/path/to/pLabs5-SDK/tools/nixos/llvm-config
make -j
```

The output is `bin/pLinux5-NG.elf`.

### Docker

```shell
docker buildx bake
```

The output will be at `bin/pLinux5-NG.elf`.

### Diagnostic builds

The escape has a bisection switch. `PL5_DIAG` selects the stage, and stages `>= 10` install and
then heartbeat **without** entering standby, which makes a single-variable test cost seconds:

```bash
make PL5_DIAG=13 offsets   # control: escape only, kh_install skipped
make PL5_DIAG=16 offsets   # full install, kh_trigger() never called
```

The stages and what each isolates are listed in
[`docs/1360-khook-death.md`](docs/1360-khook-death.md). Clear the objects between stages
(`make clean-objs`), since the flag does not retrigger a rebuild on its own.

## Code layout

- `source/` holds the payload code, grouped by domain: `core/`, `hw/`, `boot/`, `byepervisor/`,
  `hv/`, `manifest/`, `offsets/` and the freestanding `shellcode/`. Only `main.c` sits at the root.
- `include/` mirrors `source/`.
- `tools/` holds the host-side generators and the on-console tools.
- `docs/` holds the evidence for the port; start at [`docs/README.md`](docs/README.md).

## Pull requests

- keep changes scoped to one thing where you can;
- make sure `make` still builds before opening a PR;
- if you are adding a firmware, include the `off_<fw>.c` produced from a real console dump;
- if you are changing the escape, say which `PL5_DIAG` stage you measured and what the console did.
