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


## Second pass: the reference-image route (2026-10-16, evening)

The one step that could still change the picture for items 5-7 was a neighbouring
kernel image. Result: **the route is closed, and not for lack of trying.**

1. **Official PUPs cannot be used offline.** The 13.20 recovery PUP was downloaded from
   the archive and verified (`1,403,945,984 B`, sha256 `c8308c81aae91e83…` = the
   archive's own value). It carries the `SLB2` container magic and is **encrypted
   throughout**: entropy **8.000 bit/byte at every sampled offset** (0%, 5%, 25%, 50%,
   75%, 95%). There is no plain region to extract.
2. **The console-side decryptor cannot help either.** `ps5-pup-decrypt` works *"by asking
   nicely ps5 to do it"*, and its README states the constraint outright: it only works on
   *the same version* or *a bigger version within the same `.XX`* (`5.02` on `5.50`, but
   **not** `6.00`) — we run 13.60 and need 13.20, so it refuses. The same README lists
   **"Not Decrypted Files (system, system_ex, wlan)"**: the segments it never decrypts
   are exactly where the kernel and the Wi-Fi firmware live.
3. **No public kernel dump exists for 13.20 or 7.61.** Targeted searches (repo names, "ps5
   13.20 kernel", "ps5 7.61 kernel", "ps5 kernel memory capture") return nothing but the
   13.60 capture we already hold (`terrafirma2021/ps5-13.60-kernel-dump`, which is where
   `k1360.bin` comes from).

So items 5-7 stay `UNKNOWN` for a reason that is now measured rather than assumed, and the
work they block is G2 (display/audio), not the kernel entry.

### Two in-capture routes were tried and did not isolate a value

- **Wi-Fi blob (items 8-9).** `hw/firmware.c` shows the semantic: the blob is *inside the
  kernel image* (`PS5_WIFI_FW_BOOT_PATH = "lib/nxp/pcieuartiw620_combo_v1.bin"`, read as
  `ktext + offset`), so it should be findable in the capture directly. Searched for every
  plausible marker — `pcieuartiw620`, `IW620`, `iw620`, `nxp`, `NXP`, `combo_v1`,
  `88W9098`, `W9098`, `btfm` — **all zero occurrences**. Firmware blobs carry no such
  strings, so identification would have to be structural (entropy + size + alignment),
  which yields candidates, not an identified value.
- **IOMMU softc (item 3).** `hw/iommu.c` reads it as a *global pointer variable*
  (`softc = kread64(softc_ptr)`), so the way to find it is the code that stores it. The
  softc's field offsets are known (`IOMMU_SC_MMIO_VA 0x40`, `CB2 0x78`, `CB3 0x80`,
  `EB 0x60b90`), and the last is highly distinctive — but scanning the capture for it hits
  **dozens of functions across 0xca5000-0xcbb000** and their RIP-relative globals
  (`0x3e11cc4`, `0x3589e80`, `0x3e0d9b8`, …) do not converge on one variable. The pattern
  is not unique, so no value is claimed.

Both attempts are recorded here instead of being dressed up as progress: a guessed global
would defeat the whole point of the registry's provenance rule.


## Third pass: the Wi-Fi blob, followed to the end of its chain (2026-10-16, late)

`hw/firmware.c` consumes `nxp/pcieuartiw620_combo_v1.bin` as `ktext + PS5_WIFI_FW_OFFSET`, so
the blob is inside the kernel image and the two fields would follow from having its bytes.
Followed the chain to see whether those bytes are public. They are not, and the chain is now
documented so this is not re-attempted:

1. `ps5-linux/ps5-linux-image` (docker/kernel-builder/build.sh) installs a helper
   `ps5-stage-firmware` that expects the file at **/efi/lib/nxp/pcieuartiw620_combo_v1.bin** --
   i.e. the user places it.
2. `Fredolx/proper-bazzite-ps5` (system_files/usr/bin/ps5-sync-boot) copies it from
   **/usr/lib/firmware/nxp/*iw620*** -- i.e. it assumes the distro ships it.
3. That project builds on **ghcr.io/ublue-os/bazzite-deck:stable**, and this workstation *is*
   bazzite-deck (`IMAGE_ID=bazzite-deck-44.20261012`). Its `/usr/lib/firmware/nxp/` holds five
   unrelated NXP files and **no iw620**; a disk-wide search for `*iw620*` finds nothing.
4. Its kernel image is public and was pulled: one layer, 46.5 MB, containing exactly
   `rpms/kernel-ps5-7.1.7-1.x86_64.rpm`. All 721 files extracted: the package carries
   `mlan.ko` and `moal.ko` and **no firmware blob**.
5. The `ps5-linux` organisation has five repositories (loader, patches, image, tools, mwifiex)
   and none carries firmware; kernel.org's linux-firmware has no iw620 file under any name
   tried; nxp-imx/mwifiex publishes no firmware asset.

Structural fallback, tried and also inconclusive: the expected size is bracketed by the known
3.00 (492,304 B) and 7.61 (497,636 B) values, so the capture was scanned for contiguous
high-entropy runs of 300-900 KB. Six candidates came back (320, 428, 432, 448, 732 and 796 KB),
none matching the bracket and none starting with an NXP-style header (`01 00 00 00 00 d0 0c 00`
is what the NXP helper next to it on this machine looks like). Without the real bytes the
candidates cannot be told apart, so no value is claimed.

Conclusion: the two Wi-Fi fields are not derivable from public sources. Whoever derived them
before left them at zero with the note "WiFi; not needed to boot", and the only place the blob
is known to exist in the clear is the console's own `wlan` segment -- encrypted, behind the
privilege blocker documented in `../docs/1360-unknown-offsets-hunt.md`.


## Fourth pass: the remaining items, one by one (2026-10-16, late evening)

**FUN_MP3_INVOKE = 0xA12D30.** The port calls it as mp3_invoke(cmd_id, req, rsp) with
cmd 21/22, so the symbol must be a three-argument command API. 0xA12D30 is one: edi is
stored and written into the IPC message, rsi is copied in as the request (0x1404 bytes),
rdx is used before returning as the response. It sits exactly 0xA10 below the verified
FUN_MP3_INITIALIZE, and 0xA10 is the same distance the 13.20 table has between those two
symbols. My first candidate, 0xA14130, was rejected by the same test: it takes a single
argument, so it is an internal helper.

**FUN_TRANSMITTER_CONTROL = 0xC0EAA0.** off_1320.c describes this symbol as a "generic
ATOM exec taking (int cmd, void *params)". Two independent methods agree on where it is
now: (1) the thunk 0x39B3B0 is called with edi=0x4C -- DIG1TRANSMITTERCONTROL, the very
constant our shellcode passes -- and rsi pointing at a struct built exactly like
dig_transmitter_control_parameters_v1_6, from display code that logs "[av control k]";
that thunk is `jmp 0xC0EAA0`, and 0xC0EAA0 reads edi as the command and rsi as the params
pointer; (2) 13.20's 0xC01ED0 plus the locally measured drift +0xCBD0 (from the verified
HV_MP_STARTUP_CALL pair) lands on exactly 0xC0EAA0. Two dead ends were rejected on the
way: 0x69EC00/0x6A00A0 take a struct pointer in rdi, not a (cmd, params) pair, and the
"PMD transmitter"/"SFP+"/"100baseFX" strings next to them are Ethernet, not display.

**IOMMU_SOFTC: no value, and upstream stopped needing it.** The aggregated reference table
found in the HV-Bypass repository (kernel/reference/ps5linux_offsets.c, 22 firmware blocks
from 3.00 to 7.61) carries IOMMU_SOFTC only for 3.00-4.51 and marks it
"// .IOMMU_SOFTC not needed" in all thirteen modern blocks. The tempting extrapolation was
tested and rejected: the older blocks hold IOMMU_SOFTC = DATA_BASE_GVMSPACE - 0x310C9A0
(- 0x30FC900 later) and 13.60's DATA_BASE_GVMSPACE is 0x3BAA570, which would put IOMMU_SOFTC
at 0x0AAA570 -- inside .text, impossible for a data global. So the difference is not
invariant across that layout change, and no value is claimed.

**PS5_WIFI_FW_OFFSET / SIZE: every route tried, all negative.** Beyond the public-source
chain already documented, the aggregated reference table covers 3.00-7.61 only and has no
13.xx block; the offsets progress 0x1274460 (3.00) -> 0x1655800 (7.61) and the sizes
492304 / 493000 / 493532 / 494536 / 497636, so the capture was scanned for contiguous
high-entropy runs whose *length* matches one of those sizes (512-byte windows, thresholds
7.5 / 7.0 / 6.5, tolerance +/-6 KB) and for entropy runs of 200-900 KB: no run matches any
known size, and no run is bounded in a way that identifies a firmware blob. Without the
blob's bytes or a 13.xx reference, the two fields cannot be pinned, and a guess here would
be indistinguishable from a wrong value.

## Where to go next (in order of information gained per unit of risk)

1. **A 13.20 or 7.61 kernel image with provenance.** It turns items 5–7 from
   "not derivable" into a byte-matching exercise, and would give items 8–9 a reference.
   This is the only step that changes the picture, and it needs no console.
2. **IOMMU softc from runtime** — `iommu.c` already reads it via `get_offset_va`; a
   single console session that prints the resolved pointer would identify item 3 the way
   the offset dump was supposed to. Gated like any other console work.
3. Items 2, 4 and 8–9 stay parked: none of them is on the path to the kernel entry.
