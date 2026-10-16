# The 9 unresolved 13.60 offsets — offline hunt, result per field

Question: can the nine `[UNKNOWN]` fields be resolved from the community capture
(`k1360.bin`, sha256 `c3f745e2…`, 103,546,880 B) without touching a console?

Answer: **one is closed by design, one registry defect was found and fixed, and the
other seven are not derivable from a kernel image alone** — with the measurement that
shows why, not an assumption. Tools: `tools/hunt_1360_unknowns.py` (the hunt) and
`tools/check_1360_against_upstream.py` (the cross-check below).

## What the hunt produced on its own

**The whole 13.60 table agrees with an independent project.** Byepervisor-Reborn
publishes `include/offsets/13_60.h` — same three firmware, different project, with each
gadget's *bytes* in the comment. Compared entry by entry against our table and against
the capture:

```
agree=25 differ=0 absent=10 of 35 upstream entries
```

Zero disagreements. Ten upstream entries we simply do not carry (no verdict — absence
upstream is not evidence against us). This does not resolve any of the nine, but it is
the strongest statement available offline about the table those nine sit in, and it is
reproducible:

```
python3 tools/check_1360_against_upstream.py --upstream <13_60.h>   # or without --upstream to fetch
```

## Result per field

| # | field | verdict | evidence |
| --- | --- | --- | --- |
| 1 | `FUN_SMP_NO_RENDEVOUS_BARRIER` | **closed by design** | the field is optional and the takeover blob supplies its own no-op. The confirmed bare `ret` is `GAD_RET_TRAMP 0x2912A2` (upstream publishes it with the byte comment `ret`; our capture byte there is `c3`). The *kernel's own* barrier is not identified |
| 2 | `KERNEL_UART_OVERRIDE` | **not required** (diagnostics) | read only by the legacy `prepare_resume()` path, which `fw >= 0x0800` never calls (`BOOT-REQUIREMENTS-1360.md`) |
| 3 | `IOMMU_SOFTC` | **registry fixed, value open** | used as `ktext + offset` (`hw/iommu.c:9`, `prepare_resume.c:139`) but classified `STRUCT_OFF`, which made `check_offset_registry.py` **refuse the correct value** (`STRUCT_OFF` must be `< 0x1000`). Namespace corrected to `KTEXT_REL` |
| 4 | `DATA_BASE_GVMSPACE` | **contradiction recorded, not patched blind** | `hw/gpu.c:295` stores it raw without adding `ktext`, while the 3.00 table held `0x06423F80` — an offset. Either it is already an address or `gpu.c` is missing a `ktext+`. The capture cannot settle it, so the namespace is deliberately left alone |
| 5 | `FUN_TRANSMITTER_CONTROL` | **not derivable here** | display strings live outside kernel `.text` and have **no RIP-relative xref from `.text`**; the 13.20 value `0xC01ED0` is not a function entry in 13.60 (`entry=False`, body `5cfbccff`) |
| 6 | `FUN_MP3_INITIALIZE` | **not derivable here** | as #5; 13.20 `0xA0B3E0` → body `d031ff31`, not an entry |
| 7 | `FUN_MP3_INVOKE` | **not derivable here** | as #5; 13.20 `0xA0A9D0` → body `b7700100`, not an entry |
| 8 | `PS5_WIFI_FW_OFFSET` | **not derivable here** | a data-region address of a blob; candidates exist but nothing names it (7.61 used a `0x1655800`-relative address). Absence is handled at runtime (`hw/firmware.c:97`) |
| 9 | `PS5_WIFI_FW_SIZE` | **not derivable here** | a blob byte count (7.61 `497636`, 3.00 `492304`); not identified |

## Why 5–9 cannot be derived from a kernel capture (the constraint, measured)

To locate a *function* offline you need one of three things, and each was tested:

1. **a distinctive string referenced from that function.** For display/audio the
   capture's matching strings (`Enabling PMD transmitter`, `Setting transmitter tx_en`,
   `Audio Controller`, `Audio play operation in p`, …) are all **beyond `.text` and
   referenced by nothing in `.text`** — measured: zero xrefs. They are not the kernel
   entry points we need.
2. **structure around a known reference (call sites / constants).** Measured: the
   capture contains **0 direct calls and 0 address-taken references** to
   `FUN_SMP_RENDEZVOUS 0xB04440`; the same absence is what makes the barrier
   underivable from callers.
3. **a neighbouring-firmware image for byte-level matching.** Not available locally:
   `~/src/ps5-dumps/` holds only `k1360.bin` (plus the 88 MB all-zero console dump).
   Obtaining a 13.20/7.61 kernel would need a source with provenance — a separate
   question, and the one that would actually unblock items 5–7.

To locate a *global* (items 3, 4, 8, 9) you need a symbol, a naming string, or a code
pattern that pins the semantics. The hunt collected the data references of the known
IOMMU/UART/WiFi functions (e.g. `0x4fabd0 → 0x2c03940/0x2c03958`, `0x85d4e0 → 0x1a92060`,
`0x7b7890 → 0x3a2e908`) but several unrelated subsystems converge on the same addresses
(`0x391c310` appears in nearly every function), so the method does not isolate a
specific global. Reporting one of these as the answer would be a guess, and the
project's own rule requires an artifact, a layout and an independent check — none of
which exist here.

## What is *not* claimed

- No value was invented or copied from another firmware into the 13.60 table.
- The 7 remaining `UNKNOWN` fields stay `0` and the registry says why, per field.
- `IOMMU_SOFTC` was reclassified because the *code* is unambiguous; `DATA_BASE_GVMSPACE`
  was **not** reclassified because the code is not — the difference matters more than a
  tidier count.

## Where to go next (in order of information gained per unit of risk)

1. **A 13.20 or 7.61 kernel image with provenance.** It turns items 5–7 from
   "not derivable" into a byte-matching exercise, and would give items 8–9 a reference.
   This is the only step that changes the picture, and it needs no console.
2. **IOMMU softc from runtime** — `iommu.c` already reads it via `get_offset_va`; a
   single console session that prints the resolved pointer would identify item 3 the way
   the offset dump was supposed to. Gated like any other console work.
3. Items 2, 4 and 8–9 stay parked: none of them is on the path to the kernel entry.
