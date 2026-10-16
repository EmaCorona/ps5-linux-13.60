# Offset registry — one value, one namespace

An address in this project is only meaningful together with the base it is relative to. `0x83028`
added to the kernel text base is not the same thing as `0x83028` inside the hypervisor image, and
treating the second as the first is what powered the console off
(`HV_SYM_HEAP_BASE`, `HV_SYM_PCPUS` — both *below* the kernel text length).

`tools/offset_registry.json` records, for every field of `source/offsets/off_1360.c`:

| key | meaning |
| --- | --- |
| `namespace` | what the value may be added to — `KTEXT_REL`, `KDATA_REL`, `HV_REL`, `PHYSICAL`, `STRUCT_OFF`, `NONE` |
| `class` | the evidence class: `KNOWN_STATIC`, `KNOWN_HARDWARE_VALIDATED`, `UNKNOWN`, `NOT_REQUIRED_FOR_1360_PATH`, `DISPUTED` |
| `value` | the value as written in the C table |
| `used_by` | the functionality that needs it |
| `provenance` | the artifact or source the value comes from |
| `verified_by` | the check that re-derives it |

A second section, `takeover_requirements`, lists what phase B needs per firmware — including the
entry that is deliberately **not** filled: `HV_VMMCALL_HANDLER_PA` has no verified 13.60 value, and a
guest-side `VMMCALL` wrapper is a different entity.

## What is enforced

`tools/check_offset_registry.py` runs on every push and PR:

- registry and `off_1360.c` describe the same fields with the same values — either side drifting is a
  failure, in either direction;
- every value obeys the range its namespace implies: a `KTEXT_REL` value inside the kernel text image,
  a `KDATA_REL` value beyond it, a page-aligned `PHYSICAL` address, a small `STRUCT_OFF`;
- no value is claimed in two different namespaces;
- an `UNKNOWN` / `NOT_REQUIRED_FOR_1360_PATH` field must be `0`, and a `KNOWN_*` field must not be:
  **a value is never valid just because it is not zero**;
- phase B must still be disabled while its hypervisor reference is unknown (`PL5_1360_TAKEOVER`
  default `0`).

`DISPUTED` entries are printed as warnings rather than failures: the registry's purpose is to make
the contradiction visible, so `G_VBIOS` — which this table claims came from the capture while
[`1360-offsets-from-dump.md`](1360-offsets-from-dump.md) lists it as not covered — is reported on
every run until one of the two statements is withdrawn.

The payload itself is freestanding C and carries no type system; the compile-time side of the same
rule is the `#error` guard in `source/hv/defeat/hv_defeat_1360.c`, which refuses to build phase B
while the required constants are placeholders.
