# 13.60 port — analyst recap (2026-10-16, 00:20 CEST)

Handoff for review. Repo `EmaCorona/ps5-linux-13.60`, branch
`feature/13.60-support` @ `17c1712` (upstream `pLabs5/pLinux5-NG:master`
untouched). Console: retail PS5, fw `0x13600007`, chain = Relapse -> kstuff ->
elfldr (port 9021), helper ps5upload on 19113/9120.

## 1. Objective

Bring the 13.60 port to the point where phase B (takeover after resume / Linux
boot) has every address it needs, without touching `master`.

## 2. What is implemented (already on the branch)

* `source/offsets/off_1360.c` + dispatch in `source/core/utils.c`;
  `include/hv/defeat/hv_defeat_1360.h` and `source/hv/defeat/hv_defeat_1360.c`
  (13.60 sibling of the 13.20 khook escape). Phase B is compiled out unless
  `PL5_1360_TAKEOVER=1`.
* `main.c`: `sceSystemStateMgrEnterStandby()` for fw >= 0x0800;
  "armed" adopted only when `.text` is really open (XOTEXT bit 58 clear).
* `tools/pupdec/` — on-console PUP decrypt (port of `zecoxao/ps5-pup-decrypt`
  to the payload SDK, paths moved to `/data`, logging to file).
* `tools/pl5-encsrv-probe.c`, `tools/pl5-verify-1360.c` (hardened, see §6).

## 3. Routes tested, with outcomes

**(a) Read kernel `.text` live — closed.**
CPU via kernel VA: faults/powers off. CPU via a self-made mapping of the
physical: panics. GPU via a retargeted GPU PTE with the system-coherent flag:
returns all `0xFF`.

**(b) GPU-DMA primitive — works, but `.text` is still refused.**
`/dev/gc` + `PACKET3_DMA_DATA` + GVAs are all solved on 13.60; retarget is
validated (pattern copy reproduced) and a kernel **`.data`** physical reads back
byte-identical to the CPU view. Same recipe on a `.text` physical returns 4096
bytes of `0xFF`, and the **HV reservation** (`0x062800000`, anchor `"hvcGF"` at
+0x1ba10) is refused the same way. Conclusion: `.text` and the HV carveout are
protected below the page-table permissions, for every reader.

**(c) Decrypt the firmware PUP on-console — closed on this console.**
The PUP is genuine **13.60.00 Recovery** (sha256
`e210451f789ebe46f55b13ae049894663b796163f7b094ab993218f1cb20aa97`, matches the
official 13.60 entry, 1,404,953,088 B). The ported tool runs, reads the PUP, and
gets `open("/dev/pup_update0") -> -1 errno=1` (EPERM). It stays EPERM after:
authid `0x4800000000000007` + caps `0xff*16`; authid `0x4800000000010003`;
attrs set; uid/ruid/svuid=0; and with `/dev/sc_fw_update0`. The elevation
*does* apply (authid reads back changed), so the gate is neither uid nor the
tested authid. **Question for review: what does that driver check, and is
on-console PUP decryption reachable at all on 13.60?**

**(d) Community live kernel capture — used, and verified.**
`terrafirma2021/ps5-13.60-kernel-dump` (`kernel-13.60-live.bin.gz`,
103,546,880 B decompressed, sha256 `c3f745e2…cddd` **matches the published
digest**). Layout: text `0x0..0xCC0000` at VA `0xffffffff9e3f0000`, data from
file offset `0xCC0000`. Because the text span is exactly `0xCC0000`,
**file offset == ktext-relative offset**. Authenticity: 11 known 13.60 gadgets
from `EchoStretch/Byepervisor-Reborn` `include/offsets/13_60.h` match
byte-for-byte at their offsets (the only two initial mismatches were wrong
expectations in the check script: `4883c428f3c3` = `add rsp,0x28; rep ret`,
`4758c3` = `pop r8; ret`).
Method: full linear disassembly (capstone) + RIP-relative data references, then
reading the code at each hit.

## 4. Values derived (ktext-relative), with evidence

| field | value | evidence |
| --- | --- | --- |
| hypercall-4 wrapper | `0xC16A10` | `mov eax,4; vmmcall; ret` (family 1..0x1f at 0xC16A10+) |
| `KERNEL_CFI_CHECK` | `0x44F8C0` | refs `"cfi_check_fail: data %p, caller %p, callee %p"`; `lock cmpxchg` "already reported" flag: UBSan CFI handler |
| `FUN_SMP_RENDEZVOUS` | `0xB04440` | refs `"smp rendezvous"`; then `mov eax,gs:[0x34]; shlx rax,rcx,rax; mov [g],rax` = `1<<cpuid` mask |
| `FUN_HV_IOMMU_SET_BUFFERS` | `0x4FB13D` | contains `"hv_iommu_set_guest_buffers completion error:%d"` |
| `FUN_HV_IOMM_WAIT_COMPLETION` | `0x4F9030` | contains `"IOMMU: wait command completion timed out: CB3SR: %016lx"` |
| `GAD_WRMSR_RET` | `0x255034` | unique `0f 30 c3`; sequence `xor eax,eax; xor edx,edx; wrmsr; ret` starts 0x255030 |
| (extra) `hv_iommu_enable_device` error site | `0x4FC81A` | contains `"hv_iommu_enable_device error:%d 0x%x"` |

Cross-check vs the 13.20 table: `KERNEL_CFI_CHECK` 0x44E5D0 -> 0x44F8C0
(+0x12F0), `FUN_SMP_RENDEZVOUS` 0xAF94E0 -> 0xB04440 (+0xAF60),
`GAD_WRMSR_RET` 0x254FF4 -> 0x255034 (+0x40). Growth is plausible.

## 5. Still open

* **Hypervisor values** — `HV_VMMCALL_HANDLER_PA`, `HV_CODE_CAVE_PA`,
  `HV_HANDLE_VMEXIT_PA`: the HV is a separate reservation, **not** in a kernel
  capture. Needs another source. Do not expect the dump to close these.
* Remaining zeroed data/other fields: `IOMMU_SOFTC`, `DATA_BASE_GVMSPACE`,
  `FUN_SMP_NO_RENDEVOUS_BARRIER`, `KERNEL_UART_OVERRIDE`, `G_VBIOS`,
  `FUN_TRANSMITTER_CONTROL`, `FUN_MP3_INITIALIZE`, `FUN_MP3_INVOKE`,
  `PS5_WIFI_FW_OFFSET/SIZE`. Several should be derivable from the same dump.
* `KERNEL_SYM_PMAP_STORE`: the repo's own dump reported `0x3B24FF8` as a *hint*
  while the offsets tables say `0x3B48FF8` — unresolved; must be settled before
  trusting either.
* **Armed khook across suspend is fatal** on this console (independent of the
  offsets). Whether phase B can work at all as designed is an open question.

## 6. Incident in this session (and the rule added)

While validating the derived offsets on the console I read
`ktext + 0x2D39000` — `KERNEL_CODE_CAVE`/`DATA_CAVE`, i.e. **inside `.text`** —
and the console powered off. Two entries in the same list (`0x83028`,
`0x82A60`) were **hypervisor**-relative values wrongly added to `ktext`.

Rule now enforced in `tools/pl5-verify-1360.c`: probe only `ktext + offset`
with `offset >= 0xCC0000`; anything below is skipped; HV-relative values are
never added to `ktext`; `.text` is never touched on the console by any path.
Console was off at the time of writing and needs a power-cycle plus a chain
re-run before the validation run can happen.

## 7. Ready to run once the console is back

1. `tools/pl5-verify-1360.elf` — read the 13.60 data symbols from the running
   kernel and compare with the dump; every (console - dump) delta for pointer
   slots should equal one constant (the KASLR slide), which validates the whole
   offset set.
2. Then derive the remaining data symbols from the dump with the same method.

## 8. Commits on the branch

`2c33408` -> `b8f0598` -> `236f28a` -> `171de4d` -> `989c4a2` -> `075c46e` ->
`69cbf99` -> `41449dc` -> `0473328` -> `b43775e` -> `3cee9d1` -> `440afad` ->
`7a16068` -> `91cf2f8` (offsets from the dump) -> `17c1712` (probe hardened +
incident documented; this recap).

---

# Round 2 — following the analyst's operational instructions

## Priority 0 — safety rules: DONE

`tools/pl5-verify-1360.c` was rewritten and rebuilt (`bin/pl5-verify-1360.elf`) with:

1. **hard blacklist** — any ktext-relative offset `< 0xCC0000` is refused before any read
   (`.text` is exactly 0xCC0000; below that is either HV-relative or misclassified);
2. **mandatory namespace** — every spec is `NS:OFFSET` with `NS` in
   `{KTEXT,HV,DATA,PHYS}`; a non-`KTEXT` namespace is refused outright, so namespaces
   can never be mixed (that is what powered the console off with `0x83028`/`0x82A60`);
3. **dry-run by default** — prints namespace, base, offset, resulting VA and the expected
   section from the dump layout; a read needs an explicit `--commit`;
4. **one spec per invocation** — a second spec is refused.

Exit codes: 2 usage, 3 non-KTEXT namespace, 4 offset in `.text`.

## Priority 2 — hypervisor values: out of scope for the kernel dump

Checked, then stopped (per instruction 2.1):

* `EchoStretch/Byepervisor-Reborn` — branch `main` only, no PRs, no issues; `include/offsets/13_60.h`
  has no HV PA values (same 21 gadgets + 14 symbols we already use).
* `PS5Dev/Byepervisor-Reborn` — `include/offsets/13_60.h` is byte-equivalent to the above
  (`HV_SYM_HEAP_BASE`/`HV_SYM_PCPUS` only, both HV-relative); no HV PA table.
* `NotSoTypicalGamer/HV-Bypass-13.60` (the project's own research) settles it:
  * `VMCB_PA.md` — **"not public, and not recoverable offline from `kdata_1360.bin`"**. Three independent
    negative scans: the 13.60 kernel `.data` holds **zero** u64 references into `0x62800000..0x62B00000`;
    no VMCB structure anywhere in the dump; only log-format strings and CPUID `0x8000000A` names.
  * `HV_VMCB_PA.md` — no genuine `VMRUN` instruction in the capture (every `0F 01 D8` is a
    word-boundary false positive inside 16-bit tables), no SVM MSR constants, no `movabs`
    physical-address literals.
  * The fixed HV PAs that are public all belong to **<= 7.61** (`HV_CODE_CAVE_PA 0x62806F00`,
    `HV_HANDLE_VMEXIT_PA 0x6283D800` for 7.0x–7.61, `HV_PML4_07xx 0x6282E1A0`,
    `HV_ENTRY_07xx 0x6282E1B8`).
  * On **8.00+ the HV moved off the `0x628xxxxx` carve-out**, so the old anchors do not apply.

**This also corrects one of our own earlier conclusions.** We probed the HV at
`0x062800000` (anchor `"hvcGF"` @ +0x1ba10) through the GPU and got `0xFF`, and read that as
"the HV carve-out is protected". The analyst's evidence is the better explanation: on 8.00+ that
address is simply **no longer the HV**, so `0xFF` is *reserved/unmapped*, not a refusal of a
protected region. The `.text` `0xFF` result is unaffected (there the same recipe reads a `.data`
physical byte-identically, which is what proves a below-page-table protection).

**Recovery route for the three PAs** (analyst's plan, not runnable offline): dump the HV code through
the Sonic-Iso root-0 NPT alias, disassemble for the moved anchors (the HV stores absolute PAs),
then confirm `vcb->vmcb` at `vCPU+0x08` via the DMAP; the IOMMU COMPLETION_WAIT (opcode `0x1`, not
`0x05`) then writes 0 to `VMCB+0x90`.

**Open contradiction to flag:** `HV-Bypass-13.60/kernel/13.60_OFFSET_HUNT.md` reports that the
`vmmcall` opcode (`0f 01 d9`) appears **0 times** in its `ktext_0.bin`, while the verified community
dump we use has the whole hypercall-wrapper family (`mov eax,N; vmmcall`) at `0xC16A10..0xC16B7E`
— immediately before `KERNEL_SYM_HV_MP_STARTUP_CALL = 0xC16EE0`, which matches the known offsets
table. Either `ktext_0.bin` is a different artifact (truncated / not the kernel text), or the two
captures differ. Worth resolving before either is quoted.

## Priority 1 — data-set validation: BLOCKED, console is off

The run needs the console in the exploit state. It is off since the incident in §6 (this recap's
previous section): my probe read `0x2D39000`, which is inside `.text`.

**Ready to run the moment the console is back** (no repo change needed, no new payload):

```
# dry run first (no read)
bin/pl5-verify-1360.elf KTEXT:0x3B48FF8
# then, one offset per invocation
bin/pl5-verify-1360.elf KTEXT:0x3B48FF8 --commit
```

Candidate data offsets for the delta test (all >= 0xCC0000, all with a known dump value):
`0x3B48FF8` (`PMAP_STORE`), `0x3BB4300` (`IDT`), `0x3BB6FE0` (`COMMON_TSS`), `0x3B49294`
(`DMPML4I`), `0x3B49298` (`DMPDPI`), `0x3B47E4C` (`PML4PML4I`), `0x3913B0` (ACPI hook site).
Expected: every `delta_i = console_i - dump_i` equals the same KASLR slide.

Console state at the time of writing: **OFF** (ping fail, 9021/9120 closed). Needs a power-cycle
and an exploit-chain re-run; nothing else is pending on my side.

---

# Priority 1 — data-set validation run (2026-10-16 00:32 CEST)

Console was back on (`ps5_kernel r229358/releases/13.60`, 9021/9120 open,
helper `ucred_elevated:true`). Tool: `bin/pl5-verify-1360.elf`, spec written to
`/data/pl5-verify-spec.txt` (elfldr hands a `payload_args` struct, not argv), one
offset per invocation, dry-run first.

## Inputs and raw outputs

```
DRY RUN KTEXT:0x3B48FF8 -> namespace KTEXT / offset 0x3b48ff8 / expected section: data /
                           resulting VA 0xffffffffa19a8ff8 / nothing read
COMMIT KTEXT:0x3B48FF8 -> raw=ffffffff9f1a441a
COMMIT KTEXT:0x3BB4300 -> raw=9e0c8e000020a300
COMMIT KTEXT:0x3BB6FE0 -> raw=9a807a4000000000
COMMIT KTEXT:0x3B49294 -> raw=00000124000001cc
COMMIT KTEXT:0x3B49298 -> raw=0000000000000124
COMMIT KTEXT:0x3B47E4C -> raw=a62180000000016f
STRING KTEXT:0x1311bfc -> raw=636568635f696663   (memory bytes: "cfi_chec")
STRING KTEXT:0x12daf92 -> raw=6f767a65646e6572   (memory bytes: "rendezvo")
```

Console kernel text base, from the tool's own VA: `0xffffffff9de60000`.
Dump kernel text base: `0xffffffff9e3f0000`. **Slide = -0x590000.**

## Same build: confirmed

The two string reads return, in memory order, exactly the dump's bytes at the same
ktext-relative offsets (`"cfi_chec"` = start of `cfi_check_fail: data %p, caller %p,
callee %p`, and `"rendezvo"` = start of `smp rendezvous`). (An initial comparison
looked like a byte reversal; that was an artifact of my own script re-parsing the
printed u64 hex as a big-endian byte string. The real memory bytes match.)

## Deltas (console - dump)

| offset | field | console | dump | delta |
| --- | --- | --- | --- | --- |
| `0x3b48ff8` | PMAP_STORE | `0xffffffff9f1a441a` | `0xffffffff9f73441a` | `0xffffffffffa70000` |
| `0x3bb4300` | IDT[0] | `0x9e0c8e000020a300` | `0x9e658e000020a300` | `0xffa7000000000000` |
| `0x3bb6fe0` | COMMON_TSS | `0x9a807a4000000000` | `0x97807a4000000000` | `0x300000000000000` |
| `0x3b49294` | DMPML4I | `0x1cc` | `0x11c` | `0xb0` |
| `0x3b49298` | DMPDPI | `0x124` | `0x1dc` | `0xffffffffffffff48` |
| `0x3b47e4c` | PML4PML4I | `0xa62180000000016f` | `0xa66180000000018c` | `0xffbfffffffffffe3` |

## Reading of the table

* **`PMAP_STORE`**: delta `-0x590000` — **exactly the slide**. This is a pointer into
  the kernel image, so it slides with it. Consistent.
* **`IDT[0]`**: the gate descriptor's `offset[31:16]` field (bits 48..63) differs by
  `-0x59`, i.e. `-0x590000` — again **exactly the slide**, for a descriptor pointing
  into kernel text. Consistent.
* **`COMMON_TSS`, `PML4PML4I`, `DMPML4I`, `DMPDPI`**: deltas differ. Expected:
  these hold *heap / page-table / index* values, not pointers into the kernel image, so
  they do not slide with ktext. Nothing here contradicts alignment — it only tells us the
  set is not a slide test for those fields.

**Status: the dump's ktext-relative offsets align with this console's running 13.60
kernel** (same build, slide `-0x590000`). The derived values in `off_1360.c` keep the
same relative offsets, so they remain valid. A slide test only works on image-pointing
values; that is now recorded so it is not repeated.

---

# Priority 1.3 — remaining data symbols from the dump

Method: string literals in `.data` -> RIP-relative xrefs (capstone, from the same
pass as before) -> enclosing function via the nearest preceding `call` target.
Console-validated values are read with the hardened probe (`KTEXT:` namespace only).

## Derived AND validated

| field | 13.60 value | evidence | console check |
| --- | --- | --- | --- |
| `G_VBIOS` | **`0x3DDB9F0`** | bytes `55 aa 6c e9 ff 01 00 00` = ROM signature `0x55AA` + size `0x6c*512`; the surrounding region carries the AMD VBIOS strings `113-AMDOBP-006`, `PCI_EXPRESS`, `OBP Generic VBIOS`, `(C) 1988-2010, Advanced Micro Devices, Inc.`, `ATOMBIOSBK-AMD VER016.002.000.006.000000`, `AMD ATOMBIOS`, `PCIR` | `KTEXT:0x3DDB9F0` -> raw `000001ffe96caa55`, **identical to the dump** |

13.20 was `0x3DB39F0`, so drift `+0x28000`; the low `9F0` is preserved.

## Candidates, NOT committed (no reliable way to pin them yet)

**MP3.** 13.20 anchors: `FUN_MP3_INVOKE = 0xA0A9D0`, `FUN_MP3_INITIALIZE = 0xA0B3E0`
(0x9A0 apart, invoke first). In 13.60 the whole mp3 cluster sits at
`0xA13E00..0xA17000`. Functions that reference mp3 log-name literals:

```
0xa13eeb  <- "mp3_open_session_for_ta_tmr"      0xa14130  <- "mp3_bl/tee command timed out"
0xa145b0  <- "mp3_process_exit_handler"         0xa14abc  <- "mp3_enable -> false"
0xa1510d  <- "mp3_bl/tee command timed out"     0xa15180  <- same
0xa15f87  <- "mp3_vslock failed! va=%lx size=%lx"
0xa16438 / 0xa1644c / 0xa16620 <- "mp3_ioctl_open_session"
0xa16f2a  <- "mp3_ioctl_get_debug_token"
```
No pair in that list is 0x9A0 apart, and the name literals are plain C strings (no
adjacent pointer table), so `INVOKE`/`INITIALIZE` cannot be assigned by evidence
alone. Needed: the 13.20 binary (or a symbol source) to diff, or the driver's
method table.

**`FUN_TRANSMITTER_CONTROL`.** 13.20 is `0xC01ED0`, but the only code referencing a
`transmitter_control` literal sits at `ktext+0x69EC00` / `ktext+0x6A00FA` — an order of
magnitude away. Either the 13.20 value names a different site, or the 13.60 function
does not use that literal. Left at 0.

**Still 0, and also 0 in the 13.20 table** (so not regressions, and no derivation
method yet): `IOMMU_SOFTC`, `DATA_BASE_GVMSPACE`, `FUN_SMP_NO_RENDEVOUS_BARRIER`,
`KERNEL_UART_OVERRIDE`, `PS5_WIFI_FW_OFFSET`, `PS5_WIFI_FW_SIZE`.
For the record, `firmware.c` needs the WiFi pair or it bails out by design
(`if (PS5_WIFI_FW_OFFSET == 0 || PS5_WIFI_FW_SIZE == 0) return -1`).

## Drift table 13.20 -> 13.60 (for estimating, not for committing)

| anchor | 13.20 | 13.60 | drift |
| --- | --- | --- | --- |
| `GAD_WRMSR_RET` | 0x254FF4 | 0x255034 | +0x40 |
| `KERNEL_CFI_CHECK` | 0x44E5D0 | 0x44F8C0 | +0x12F0 |
| `FUN_SMP_RENDEZVOUS` | 0xAF94E0 | 0xB04440 | +0xAF60 |
| `KERNEL_SYM_HV_MP_STARTUP_CALL` | 0xC0A310 | 0xC16EE0 | +0xCBD0 |
| `G_VBIOS` | 0x3DB39F0 | 0x3DDB9F0 | +0x28000 |

Drift grows with offset and is not linear, so interpolation is only a hint.

---

# P4.0 — death signature (documentary evidence; physical observation still missing)

Direction: P4 before P3. Nothing else runs until the signature is pinned.

## What "the death" actually is, from our own run records

Taken from `docs/1360-port-status.md` (recorded at the time of each run; the console's
`/data/plinux5.log` is truncated by `notify()` on every run, so the historical log is gone).

| run | what was armed | observed outcome | last log line |
| --- | --- | --- | --- |
| `PL5_DIAG=1` | escape + **armed khook** | console becomes unreachable **~5 s after arming**, **before** standby is requested | the `sceSystemStateMgrEnterStandby()` line is **absent** |
| `PL5_DIAG=5` | escape only, **no khook** | standby + resume **work**; payload continues and exits cleanly | `[W0] pre-suspend` present |
| `PL5_DIAG=4` (first) | escape armed | powered off by itself; no `[W0]`, no dump | — (root cause found: HDMI Device Link **ON** + USB power not *Always*; CEC powered it off. Operator fixed both settings.) |
| `PL5_DIAG=4` (after the fix) | escape armed | entered rest mode, **resumed ~5 min later**, helper survived | log **never advanced past "Going to rest mode"** — no `[W0]`, no `[W]`, no `[X]`, no dump |
| Byepervisor-Reborn reference build | reference khook | rest mode entered; operator reports power-off afterwards | — |

## The consequence that re-frames P4

Our evidence says the failure is **at arm time, not across suspend**: with the khook armed the
console dies ~5 s after arming, *before* `sceSystemStateMgrEnterStandby()` is ever called, while
escape-only survives standby + resume end to end.

That is precisely the case the plan calls out for **P4.1 Test A** ("installation only, no suspend").
So Test A is **already negative from the historical runs**, and the open question is narrower than
"DR7 across S3":

1. does merely **arming** kill it, or does the **#DB self-test** (the hook fires a `#DB` on
   `sys_getuid`) kill it because some other payload calls `sys_getuid` during those 5 s?
2. if arming alone kills it, which part is fatal: the `.text` write, the `DR7` write, or the
   `IDT`/IST-6 path?
3. `PL5_DIAG=5`'s clean standby+resume shows the S3 path itself is fine on this console.

## Evidence still missing (blocks the analyst's signature table)

The plan distinguishes the signature: clean power-off (LED off, no panic) vs hang (LED on, black
screen) vs visible panic on UART vs reset loop. We have **none of those physical observations** —
only "the console stopped answering on the network", which does not distinguish them.

* no UART/serial capture is available on this console through the current chain;
* `ps5upload`'s `klog` endpoint cannot help: the console is already off by the time it could be read;
* the payload log persists up to the moment of death (it ends at the arm), which is consistent with
  a sudden loss, but it cannot tell a clean power-off from a hang.

**Asked of the operator:** what does the console physically do at the moment of death
(LED state, screen, sound, whether it restarts by itself)? That single observation picks the row of
the signature table and therefore the intervention (arm post-resume vs IST-6 mapping vs payload fix).

Until that is answered, P4 does not advance: no code change, no `off_1360.c` edit, no combined test.

## P4.0 — SIGNATURE CONFIRMED (operator observation, 2026-10-16 00:40)

Operator: **"clean power-off, LED off"** (no panic screen, no restart loop). Combined with the
network evidence already recorded (`PL5_DIAG=1`: the console becomes unreachable; `PL5_DIAG=4`
after the settings fix: the console stayed reachable through rest mode and resumed), the rows of
the signature table that remain possible are:

* **clean power-off / orderly shutdown** — and *not* a hang (network would stay up longer) and
  *not* a visible panic (operator saw none).

### What this rules in and out

The plan's mapping for "clean power-off" is *"the resume doesn't complete -> DR7 zeroed, or the
vector is wrong -> arm post-resume"*. **That mapping does not fit the timing we measured.** The
console dies **~5 s after arming and before `sceSystemStateMgrEnterStandby()` is ever called**
(that log line is absent), so no resume is involved in the failure. Something issues an *orderly*
shutdown at (or shortly after) install time.

An orderly power-off is not what a faulting #DB, a bad vector or an unusable payload produce: those
give a hang or a panic. An orderly shutdown is what a **supervisor or watchdog decides** — on this
console the candidates are the secure/HV layer reacting to guest tampering, or a system-level
power request (the same class as the CEC/HDMI-Device-Link cause already found once and fixed).

## P4.1 — bisect plan (one variable per session, power-cycle between)

From the code, the surviving/dying delta is exactly `kh_install()`:

* `PL5_DIAG=5` = escape only (`.text` RW + XOTEXT clear) -> **survives standby + resume**;
* `PL5_DIAG=1` = escape + `kh_install()`, no RSI redirect -> **dies ~5 s after install**.

`kh_install()` (`source/byepervisor/khook.c`) does, in order:

1. read/save the #DB IDT gate (`KH_VEC_DB = 1`) and the IST slot — **reads only**;
2. validate the gate handler is inside the kernel image, and the TSS `RSP` shape — **reads only**;
3. build the arm/disarm/dispatch chains in a scratch page, including a **resumectx input struct
   with `KH_RC_DR7 = KH_DR7_BP0_EXEC`** (the DR7 arming happens through *resumectx*, not through a
   direct `mov dr7`, at install time);
4. **replace the #DB IDT gate** (`gate_encode` + `kwrite_q(db_gate)`) — a `.data` write to
   `idt_base + 16` (13.60: `0x3BB4300 + 0x10`), i.e. not a `.text` write.

So the variables to separate are, in this order:

* **A1 — reads only.** escape + step 1/2 (save + validate the gate). Expected: survives.
* **A2 — gate swap, no DR7/resumectx.** escape + step 1/2 + step 4 (write the #DB gate, staged
  chains, **no resumectx/DR7 arming**). If this dies -> the killer is the IDT-gate replacement
  (or its interaction with other payloads that also own vector 1). If it survives -> next.
* **A3 — DR7/resumectx arming, no gate swap.** escape + the resumectx DR7 arming alone. If this
  dies -> the **DR7 arming** is the killer, which on this console would mean the HV/secure layer
  treats a guest DR7 change as tampering and shuts the console down.

Each test: one session, one power-cycle, log the last line reached, then stop. `off_1360.c` is not
touched. Any offset that looks wrong gets logged and the run stops.

### Also to verify before A1 (cheap, no console risk)

Confirm the two settings that already bit us once are still as required
(**HDMI Device Link = Off**, **Supply Power to USB Ports = Always**). If a system update or a
settings reset re-enabled Device Link, A1..A3 would be measuring CEC again instead of the khook.

---

# P4.1 — first bisection results (console session 2026-10-16 00:47–00:50)

Built with a diagnostic skip-mask added to the vendored khook
(`kh_diag_skip_mask`, `KH_SKIP_{BIG,SCRATCH,IST,GATE,DR7}`) plus an
"install + heartbeat, never enter standby" mode for `PL5_DIAG >= 10`, so a run costs
seconds instead of a rest-mode cycle and the CEC variable is gone entirely.

| run | single variable | console | raw evidence |
| --- | --- | --- | --- |
| `diag13` | **control**: escape only, `kh_install` **skipped**, no standby | **SURVIVED** | escape page-table logs, then 20 heartbeats `[hb 00]..[hb 19]`, ping OK, 9021/9120 open |
| `diag11` | full install **minus the #DB IDT gate write** (`KH_SKIP_GATE`) | **SURVIVED** | `[B] chain built (384 bytes)`, `[D] kh_install rc=0`, `[E] core=15 ktext=0xffffffff9de60000 scratch=0xffffffffa0b99000 tgt=0xffffffff9ea76ee0 idt=0xffffffffa1a14300 tss=0xffffffffa1a16fe0`, then `!! signal 5 at 200002a6e (code 2)` — the #DB reached the **original** handler and killed only our process |
| `diag15` | full install, gate written, **resumectx `DR7 = 0`** (`KH_SKIP_DR7`) | **DIED** | the console stopped answering during the run; the HTTP request never returned |

## What these two points already exclude

* **The DR7 value is not the trigger.** With the gate in place but `DR7 = 0` the console still
  dies, so "the HV sees the debug registers armed" is refuted as the cause.
* What separates surviving from dying is whether the **#DB is routed into our chain** (gate
  swapped) and that chain then runs: privileged `resumectx`/`DBREG_RESUME` plus the trap-frame /
  IST manipulation. The `#DB` itself comes from `kh_trigger()` (`hv_defeat_1360.c:520`), which
  runs immediately after `[E]`.

## Next single variable

**`diag16` = full install, `kh_trigger()` never called** (no `#DB` at all), then heartbeat.
* dies -> merely having the swapped gate present is fatal (install-time write);
* survives -> the fatal step is the `#DB`/chain execution itself.

## Evidence to collect on the next boot

`/data/plinux5.log` is on disk and survives the power-off, so after the power cycle it should
still hold the **last line the diag15 run reached before dying** — the exact "last line before
death" the signature table wants. Read it before any new payload run.
