# Toolchain — inputs, pinning and the effective compiler

This file answers one question: **what exactly compiles the payload, and is that thing pinned?**
It was written by reading the SDK shims and by measuring two clean local builds (evidence at the
bottom); the values in it are the ones actually used by `Dockerfile` and by the workflows.

## The two documented inputs

| variable | what it is | what it actually controls |
| --- | --- | --- |
| `PS5_PAYLOAD_SDK` | an unpacked [ps5-payload-dev/sdk](https://github.com/ps5-payload-dev/sdk) release | `toolchain/prospero.mk` sets `CC := $(PS5_PAYLOAD_SDK)/bin/prospero-clang`, the SDK's header/lib/`crt1.o` root, and the `-target x86_64-sie-ps5` sysroot |
| `LLVM_CONFIG` | `…/pLabs5-SDK/tools/nixos/llvm-config` | the LLVM the build ends up invoking — see the chain below. It is **not** cosmetic |

`PS5_PAYLOAD_SDK` defaults to `/opt/ps5-payload-sdk/` in the `Makefile` if unset.

## The compiler chain (why `LLVM_CONFIG` matters)

`prospero-clang` in the SDK is a **shell shim**. Its `bin/clang` sibling resolves the real driver
through `prospero-llvm-config`, which:

1. takes `LLVM_CONFIG` from the environment if it is executable, and
2. otherwise walks a fixed candidate list (`llvm-config-23` … `llvm-config-15`, `llvm-config`).

The pLabs5 `llvm-config` is itself a shim whose `--bindir` **finds `clang` on `PATH`**.

So the chain is:

```
make → prospero-clang → bin/clang (shim) → prospero-llvm-config → $LLVM_CONFIG
     → pLabs5 tools/nixos/llvm-config → first `clang` on PATH   ← the real compiler
```

Consequences:

- The **host LLVM version is part of the build identity.** A different `clang` on `PATH` can change
  the emitted code, so the Docker image / CI LLVM version is a reproducibility input, not a detail.
- Debian/Ubuntu install the version-suffixed `clang-21` binary; the pLabs5 shim looks for the
  unversioned name, which is why the workflows prepend `/usr/lib/llvm-21/bin` to `GITHUB_PATH` and
  not just `clang-21`.

## Freestanding shellcode is a separate, GCC-based lane

`source/shellcode/*` are built by their own Makefiles with the **host GCC** (`gcc`, `ld`,
`objcopy`) as `-ffreestanding -nostdlib -m64` objects, then converted to a C header by
`scripts/bin2c.py`. They do **not** go through `prospero-clang` or through `LLVM_CONFIG`.
`PL5_TAKEOVER_FW` and `PL5_HV_STOP` are forwarded into that lane.

## Pinned values

| component | pin | where |
| --- | --- | --- |
| ps5-payload SDK | release **v0.44**, zip sha256 `4d06eab777bb135705b5a6816688c9132efb246093fe606ac488ab6cf65ca5b0` | `Dockerfile`, both workflows |
| pLabs5-SDK | commit **`eeae9d047623f71dbaecc7328dd4e32e4d7101d0`** (2026-10-13), codeload zip sha256 `48c4abb8c172ae4487f8cd485a682a7d4098304c676491caaa895b5a323d6feb` | `Dockerfile` (`ARG PLABS5_SDK_COMMIT`, checksummed zip), both workflows (`actions/checkout` `ref:`) |
| Docker base image | `silkeh/clang:21-trixie` (digest at pin time `sha256:7cb6d48fa9882b0956f09e6e722f38c9cef11fb676f60db2b9ce612f4ff9e58d`) | `Dockerfile` |
| CI LLVM | 21 (`apt.llvm.org/llvm.sh 21`, `clang-21`/`lld-21`/`llvm-21`, `PATH` += `/usr/lib/llvm-21/bin`) | both workflows |

The Clang 21 / 21 alignment replaces the previous Docker 22 vs CI 21 mismatch: the image's clang is
the effective compiler inside the container, so the two environments now name the same version.

The pLabs5-SDK pin replaces `zip/refs/heads/main` (Docker) and an unqualified `actions/checkout`
(workflows) — both of which moved silently and could change the produced ELF without any source
change in this repository. Updating the pin is a deliberate act: change `PLABS5_SDK_COMMIT`, the
checksum and the `ref:` together.

## Measured evidence

Host: `clang 18.1.8` (Homebrew, the `clang` on `PATH` here), `gcc 16.2.1`, `GNU ld 2.46.1`,
SDK v0.44 at `$HOME/src/ps5-sdk-dl/sdk/ps5-payload-sdk`, pLabs5 at
`$HOME/src/ps5-sdk-dl/plabs5/pLabs5-SDK-main`.

```bash
export PS5_PAYLOAD_SDK=$HOME/src/ps5-sdk-dl/sdk/ps5-payload-sdk
export LLVM_CONFIG=$HOME/src/ps5-sdk-dl/plabs5/pLabs5-SDK-main/tools/nixos/llvm-config
make clean && make -j6      # twice, from a clean tree
```

| run | result | sha256 of `bin/pLinux5-NG.elf` |
| --- | --- | --- |
| clean build A | exit 0, `ELF 64-bit LSB pie executable, x86-64` | `63a81be8e1564b78453c7332a734c8d09e5d0df91b6c268a223dc6dd75362162` |
| clean build B | exit 0 | `63a81be8e1564b78453c7332a734c8d09e5d0df91b6c268a223dc6dd75362162` |

Two clean builds of the same tree with the same toolchain are **byte-identical** here, so the build
is deterministic in a fixed environment and the remaining variability is toolchain identity.

What this does **not** show: that a build with a different LLVM yields the same bytes. It is
expected to differ — the compiler is an input — and the pins above exist so that "which LLVM"
always has an answer. Cross-environment binary equality is therefore not claimed.

The local build also emits three warnings from `source/hv/defeat/hv_defeat_1360.c`
(`-Wself-assign` and two unused variables around the hook state); they are recorded here as
observed, not as accepted.
