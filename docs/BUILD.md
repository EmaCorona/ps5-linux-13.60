# Build targets and flag dependencies

What each target does, and — the part that used to bite — what happens to already-built objects when
a build flag changes.

## Targets

| target | effect |
| --- | --- |
| `all` (default) | generates the six shellcode headers, compiles every `source/**/*.c`, links `bin/pLinux5-NG.elf` |
| `offsets` | same sources plus `tools/pl5-offsets.c` with `-DPL5_OFFSETS_MODE`, links `bin/pLinux5-NG-offsets.elf` (the dumper payload) |
| `version` | prints the manifest version read from `source/manifest/manifest.c` — the same field CI uses to name a release |
| `clean` | removes the ELF, the objects **and** the generated shellcode blobs/headers, via the sub-makes |
| `clean-objs` | removes only the userland `source/**/*.o` (keeps the shellcode blobs) |

`all`, `clean`, `version`, `offsets` and `clean-objs` are all declared `.PHONY`. `clean-objs` was
missing from that list, so a file named `clean-objs` in the tree would have silently disabled the
target.

Each `source/shellcode/*/Makefile` is an independent sub-make with its own `all`/`clean`; the
top-level forwards `PL5_HV_STOP` to `shellcode/hv` and `PL5_TAKEOVER_FW` to `shellcode/hv_takeover`
and nothing else.

## Flags

| flag | default | effect |
| --- | --- | --- |
| `PL5_DIAG` | `4` | 13.20 diagnostic bisection stage (see `source/hv/defeat/hv_defeat_1320.c`) |
| `PL5_TAKEOVER_STAGE` | `3` | step selector inside `shellcode/hv_takeover/takeover.S` |
| `PL5_PROBE` | `0` | pre-rest-mode `resume_rip` probe instead of the normal flow |
| `PL5_1360_TAKEOVER` | `0` | enables 13.60 phase B. Must stay `0`: the required HV reference is unknown, and the build refuses `PL5_TAKEOVER_FW=1360` while it is |
| `PL5_TAKEOVER_FW` | `1320` | firmware the shared takeover blob is built for; the blob carries that firmware's constants |
| `PL5_HV_STOP` | `0` | freeze the HV shellcode at a checkpoint instead of booting (`1` entry, `2` post-`configure_vram`, `3` post-barrier, `4`/`6`/`7`/`8` reset variants) |

## Flags invalidate objects — the configuration stamp

`PL5_DIAG`, `PL5_TAKEOVER_STAGE`, `PL5_PROBE`, `PL5_1360_TAKEOVER`, `PL5_TAKEOVER_FW` and
`PL5_HV_STOP` reach the compiler as `-D` options. A `-D` option is not a prerequisite of any rule,
so **make would reuse objects compiled with the previous values** and the flag would be a silent
no-op — the Makefile used to warn "remember to clear the objects first".

That is now enforced instead of documented. Each Makefile that carries flags writes
`.pl5-config.stamp` holding the flag values and regenerates it **only when a value changes**:

```
$(STAMP): FORCE
	@printf '%s\n' '<flag values>' | cmp -s - $@ || printf '%s\n' '<flag values>' > $@
```

The objects (and, at the top level, the generated shellcode headers) depend on that file, so:

- switching a flag rewrites the stamp → its dependents rebuild, **no `clean` needed**;
- re-running with the same flags leaves the stamp mtime untouched → the build is a no-op.

The top-level stamp covers all six flags; `shellcode/hv` stamps `PL5_HV_STOP` and
`shellcode/hv_takeover` stamps `PL5_TAKEOVER_FW`, so a flag switch propagates into the sub-make that
actually consumes it.

`.pl5-config.stamp` is build state, not source: it is in `.gitignore`.

## Measured evidence

```bash
cd source/shellcode/hv        # fast: host gcc only, no SDK needed
make clean; make PL5_HV_STOP=0   # shellcode_hv.h 970b951b…
make PL5_HV_STOP=1               # no clean: 87167ffd…   (rebuilt on the flag alone)
make PL5_HV_STOP=0               # no clean: 970b951b…   (back to the first value)
```

Full payload, `PL5_PAYLOAD_SDK` + `LLVM_CONFIG` set:

| run | `bin/pLinux5-NG.elf` sha256 (16 hex) |
| --- | --- |
| `make clean && make -j6` (defaults) | `63a81be8…` |
| `make -j6 PL5_HV_STOP=1` (no clean) | `8d93601f…` |
| `make -j6` (no clean, back to defaults) | `63a81be8…` |
| `make -j6` again | `63a81be8…`, nothing recompiled |

`tests/run_tests.py` runs the shellcode-level half of this automatically (the full build needs the
PS5 SDK, so it is not part of the default suite).
