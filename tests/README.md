# Host test suite (offline)

`run_tests.py` exercises the three 13.60 verifiers without the PS5 SDK and
without a console. Nothing here touches hardware.

```bash
python3 tests/run_tests.py                       # synthetic lane only (default)
PL5_TEST_REAL_DUMP=1 python3 tests/run_tests.py  # synthetic lane + real capture
```

## Two lanes, never mixed

| lane | input | runs | what a PASS proves |
| --- | --- | --- | --- |
| `synth` | minimal fixtures generated in a temp dir | always | the verifiers' **logic**: a valid table passes, an altered value / missing symbol / missing field / wrong namespace / absent input / wrong hash / wrong size fails with the right exit code |
| `real` | the community 13.60 kernel capture (not vendored) | opt-in, `PL5_TEST_REAL_DUMP=1` | the offsets really are located in **that** image, and a one-byte mutation of it is caught |

The report prints the lane next to every result, so a synthetic PASS can never
be read as verification of the capture. The capture is external by design: it is
not redistributed with the repository, so the `real` lane cannot be a CI
default.

Input resolution: `PL5_1360_DUMP` (default
`$HOME/src/ps5-dumps/k1360.bin`). The expected SHA-256 lives in
`tools/verify_off_1360_dump.py` and is checked before any content is read.

## What is covered

- `tools/verify_off_1360.py` — structure of `off_1360.c` against a symbol
  header: valid, altered value, missing symbol, unmapped symbol, absent input,
  `KERNEL_CODE_CAVE` non-zero, a required field reset to `0`, a field set that
  diverges from `off_1320.c`.
- `tools/verify_off_1360_dump.py` — absent input, wrong hash, right hash with
  wrong size (all exit `2`, never a false PASS), plus the full `real` check.
- `tools/verify_takeover_param.py` — the shared takeover blob carries no
  firmware literal, and a `PL5_TAKEOVER_FW=1360` build is refused while
  `HV_VMMCALL_HANDLER_PA` is unknown.

`FUN_PRINTF` is checked as a function-entry *shape* only. That check is
falsifiable (a wrong offset is not an entry) but it does not prove the identity
of the function; it is reported as such.

## CI

[`../.github/workflows/verify.yml`](../.github/workflows/verify.yml) runs the
synthetic lane plus the structure/takeover checks on push and pull request to
this branch. It never runs the `real` lane.

The build workflow additionally runs `tools/check_payload_static.py` on the
freshly built ELF and publishes `bin/static-report.txt` with the artifact. The
same checker has a `package` lane here, opt-in with `PL5_TEST_ELF=1` because it
needs a built payload. See
[`../docs/BASELINE_1360.md`](../docs/BASELINE_1360.md) for the verifier results
recorded before these tests existed.
