# 13.60 offsets derived from a community kernel dump (offline)

## Why not the console / the PUP

Two live routes were tried and are closed on this console:

1. **Reading kernel `.text` live** (CPU via kernel VA, dmap alias, or GPU-DMA
   retarget): the CPU path faults/powers off, the GPU path returns `0xFF`.
   The same GPU recipe reads kernel `.data` byte-identical, so `.text` is
   protected below the page-table permissions for every reader.
2. **Decrypting the firmware PUP on-console** with the EncryptService
   (`/dev/pup_update0`, ioctls `0xC0184402`/`0xC0184405`). The tool
   (`tools/pupdec`, a port of `zecoxao/ps5-pup-decrypt` to the payload SDK)
   runs correctly and reads `/data/PS5UPDATE.PUP` (a genuine **13.60.00
   Recovery** PUP, sha256 `e210451f789ebe46f55b13ae049894663b796163f7b094ab993218f1cb20aa97`),
   but every `open()` of the device fails with **EPERM** (`errno=1`),
   including after `kernel_set_ucred_authid(pid, 0x4800000000000007)`,
   `kernel_set_ucred_caps(pid, 0xff*16)`, `kernel_set_ucred_attrs`,
   `uid/ruid/svuid=0`, and with authid `0x4800000000010003`. `/dev/sc_fw_update0`
   behaves the same. The device gate is not the POSIX uid and not the ucred
   authid tested here.

## What was used instead

A community capture of the **running 13.60 kernel** (text + data, same boot):

* `terrafirma2021/ps5-13.60-kernel-dump`, `kernel-13.60-live.bin.gz`
* decompressed size 103,546,880 B, sha256
  `c3f745e25dc25ee7afef89eb418b295b6334bbefe8aa17e6886483c35d78cddd`
  (**matches the published digest exactly**)
* layout: kernel text 0x0..0xCC0000 at VA `0xffffffff9e3f0000`, kernel data
  from file offset 0xCC0000 at VA `0xffffffff9f0b0000`.
  Because text is exactly 0xCC0000 long, **file offset == ktext-relative
  offset** for the whole image, which makes every derived value a direct
  `off_1360.c` constant.

### Authenticity check performed before trusting it

Known 13.60 values from `EchoStretch/Byepervisor-Reborn` `include/offsets/13_60.h`
were compared byte-for-byte against the dump at their ktext-relative offsets
(11 gadgets: pivot `0x25213E`, `iretq` `0x257B3D`, pop rax/rcx/rdi/rsi/rdx/rsp/r8,
cld, ret). All matched; the two initial "mismatches" were wrong expectations in
the check script (`4883c428f3c3` = `add rsp,0x28; rep ret`, `4758c3` = `pop r8; ret`),
so 11/11 are consistent. The dump therefore corresponds to a real 13.60 kernel
with the same relative layout as the offsets table.

## Values derived

Found by accurate linear disassembly (capstone) with RIP-relative data
references, then confirmed by reading the code:

| field | value (ktext-relative) | evidence |
| --- | --- | --- |
| hypercall-4 wrapper | **0xC16A10** | `push rbp; mov rbp,rsp; mov eax,4; vmmcall; pop rbp; ret` |
| `KERNEL_CFI_CHECK` | **0x44F8C0** | function referencing `"cfi_check_fail: data %p, caller %p, callee %p"` (str `0xffffffff9f701bfc`) and using a `lock cmpxchg` "already reported" flag: UBSan CFI failure handler |
| `FUN_SMP_RENDEZVOUS` | **0xB04440** | references `"smp rendezvous"` (str `0xffffffff9f6caf8e`), then `mov eax,gs:[0x34]; shlx rax,rcx,rax; mov [g],rax` = CPU bitmask `1<<cpuid` |
| `FUN_HV_IOMMU_SET_BUFFERS` | **0x4FABD0** | function containing `"hv_iommu_set_guest_buffers completion error:%d"` (str `0xffffffff9f70236e`); **corrected in round 3** — the earlier `0x4FB13D` is mid-function, not an entry |
| `FUN_HV_IOMM_WAIT_COMPLETION` | **0x4F9030** | function containing `"IOMMU: wait command completion timed out: CB3SR: %016lx"` (str `0xffffffff9f77ffba`) |
| `GAD_WRMSR_RET` | **0x255034** | unique `0f 30 c3` in text; sequence `xor eax,eax; xor edx,edx; wrmsr; ret` starts at 0x255030 |
| (extra) `hv_iommu_enable_device` error site | 0x4FC81A | contains `"hv_iommu_enable_device error:%d 0x%x"` |

Cross-check against the 13.20 table (`off_1320.c`) shows plausible growth:
`KERNEL_CFI_CHECK` 0x44E5D0 -> 0x44F8C0 (+0x12F0), `FUN_SMP_RENDEZVOUS`
0xAF94E0 -> 0xB04440 (+0xAF60), `GAD_WRMSR_RET` 0x254FF4 -> 0x255034 (+0x40).

## Still not covered by this dump

* the **hypervisor** image: `HV_VMMCALL_HANDLER_PA`, `HV_CODE_CAVE_PA`,
  `HV_HANDLE_VMEXIT_PA` (the HV is a separate reservation, not in a kernel dump);
* shellcode/boot values: `G_VBIOS`, `FUN_TRANSMITTER_CONTROL`, `FUN_MP3_*`,
  `PS5_WIFI_FW_OFFSET/SIZE`, `KERNEL_UART_OVERRIDE`, `DATA_BASE_GVMSPACE`,
  `IOMMU_SOFTC`, `STOPPED_CPUS`, `FUN_STOP_CPUS`, `FUN_AS_LAPIC_EOI`,
  `FUN_HV_UNMAP_PT_TMR`, `FUN_MEMCPY`, `ACPIGBL_FACS`;
  several of these are data symbols and should be derivable from the same dump
  by symbol-string xref (the data span contains many symbol-like strings).

## Validation still owed on the console

The derived values are **not yet** confirmed against this console's running
kernel. A safe check is possible without reading `.text`: read a *data* symbol
(e.g. `KERNEL_SYM_PMAP_STORE`) through kernel R/W and compare with the dump.
Note the repo's own dump reported `KERNEL_SYM_PMAP_STORE = 0x3B24FF8` as a *hint*
while the offsets tables say `0x3B48FF8`; that discrepancy must be resolved
before trusting either. Reading `.text` on the console must remain avoided.

---

## Incident (2026-10-16): the console powered off while validating

The first validation run read `ktext + 0x2D39000`. Reading `.text` on this
console is fatal — the same effect already seen when dumping `.text` — and the
console powered off (unreachable on 9021/9120, no ping). Two entries in the same
list, `0x83028` and `0x82A60`, were also wrong: those are **hypervisor**-relative
values and must never be added to `ktext`.

> **Correction (round 3, 2026-10-16):** this paragraph used to claim that
> `0x2D39000` “lies inside the kernel `.text` region (any ktext-relative offset
> below `0xCC0000` does)”. That is arithmetically false — `0x2D39000` is *above*
> `.text` length `0xCC0000`, so it is a **kernel-data** offset. The power-off is
> therefore *not* explained by “.text is read-protected”; the cause of that
> specific read killing the console is still unexplained and is tracked as an
> open question. What is certain: the value is data-namespace, and it is
> Byepervisor's `KERNEL_SYM_DATA_CAVE`, not a code cave.

**Rule, now enforced in `tools/pl5-verify-1360.c`:** probe only kernel data
addresses, i.e. `ktext + offset` with `offset >= 0xCC0000`. The tool skips
anything below that and refuses HV-relative values outright. No `.text` address
may be touched on the console, by any path, ever.

Validation itself is still owed: it needs the console back on (exploit chain
re-run) and then a run of the hardened tool.


---

## Correction (2026-10-16, round 2)

The HV-carveout result above (`0x062800000` -> `0xFF`) was read as "the HV is protected like
`.text`". The project's own research (`NotSoTypicalGamer/HV-Bypass-13.60`, `kernel/VMCB_PA.md` and
`kernel/HV_RESEARCH.md`) is the better explanation: on firmware **8.00+ the hypervisor moved off the
`0x628xxxxx` carve-out**, and a scan of the 13.60 kernel `.data` finds **zero** references into
`0x62800000..0x62B00000`. So that address is likely *reserved/unmapped* and the `0xFF` is not a
permission refusal. The `.text` conclusion is unchanged and independently supported: the same
recipe reads a kernel `.data` physical byte-identically while `.text` returns `0xFF`.

The three hypervisor PAs (`HV_VMMCALL_HANDLER_PA`, `HV_CODE_CAVE_PA`, `HV_HANDLE_VMEXIT_PA`) are
therefore **out of scope for any kernel capture** on 8.00+; they need the NPT-alias HV dump route.

---

## Round 3 (2026-10-16): independent re-verification with a committed tool

Every kernel value claimed above was re-derived from scratch — without reading
`off_1360.c` — by `tools/verify_off_1360.py` (header/field/layout checks) and the
new `tools/verify_off_1360_dump.py` (dump checks). The dump check locates each
signature string in the image, finds its RIP-relative xrefs from `.text`, and
resolves the *strict* function entry of the enclosing function (padding + real
prologue), so it does not depend on any value already written in the tables.

Input: `~/src/ps5-dumps/k1360.bin`, sha256
`c3f745e25dc25ee7afef89eb418b295b6334bbefe8aa17e6886483c35d78cddd`, 103,546,880 B.

```
$ python3 tools/verify_off_1360.py <13_60.h>          -> PASS (57 values)
$ .venv-rea/bin/python tools/verify_off_1360_dump.py  -> 22/22 checks passed
```

### Confirmed (independently)

| field | value | how it was confirmed |
| --- | --- | --- |
| `KERNEL_CFI_CHECK` | `0x44F8C0` | strict entry; the `cfi_check_fail:` string xref `@0x44F925` sits inside it |
| `FUN_SMP_RENDEZVOUS` | `0xB04440` | strict entry; `smp rendezvous` xref `@0xB0444B` inside it |
| `FUN_HV_IOMM_WAIT_COMPLETION` | `0x4F9030` | strict entry; `IOMMU: wait command completion` xref `@0x4F90B9` inside it |
| `GAD_WRMSR_RET` | `0x255034` | bytes `0f 30 c3` (`wrmsr; ret`) |
| `GAD_ADD_RSP_28_POP_RBP_RET` | `0x25213E` | bytes `48 83 c4 28 f3 c3` = `add rsp,0x28; rep ret` (the doc's own note was right) |
| hypercall-4 wrapper | `0xC16A10` | decodes `push rbp; mov rbp,rsp; mov eax,4; vmmcall; pop rbp; ret` |
| `KERNEL_SYM_PMAP_STORE` | `0x3B48FF8` | Byepervisor-verbatim **and** the dump holds a live kernel VA `0xffffffff9f73441a` there; `0x3B24FF8` holds `00…` |

### Refuted

* **`FUN_HV_IOMMU_SET_BUFFERS` = `0x4FB13D` is wrong.** It is not a function
  entry (it decodes as `lea rax,[rip+…]` mid-function). The function holding the
  signature string starts at **`0x4FABD0`** (strict entry, next entry
  `0x4FB270`). The table now carries `0x4FABD0`.
* **`KERNEL_CODE_CAVE` = `0x2D39000` is wrong as a *code* cave.** `0x2D39000`
  is `>= .text` length `0xCC0000`, i.e. it is **data**-namespace: it is
  Byepervisor's `KERNEL_SYM_DATA_CAVE`. A code cave must be executable, and no
  13.60 code cave is evidenced. The field is now `0`; the high-FW vector never
  reads it (`main.c` stages `shellcode_kernel` only for `fw < 0x0800`), so this
  is inert for the port and stops the table advertising an unverified address.

### Still open (with the evidence that bounds it)

* Why `ktext + 0x2D39000` powered the console off is **not** explained by the
  `.text`-read-protection story (corrected above). The dump says the address is
  data; the console says reading it is fatal. The two facts are not reconciled
  by any evidence currently in the repo — tracked as an open question, not
  papered over.
* The three hypervisor PAs remain out of scope for a kernel capture (see the
  round-2 correction above): they need the NPT-alias HV dump route.


---

## Update — 2026-10-16: local Recovery PUP analysis and hypervisor-image boundary

### Input and container observations

The local artifact examined was the PS5 13.60.00 Recovery PUP with SHA-256
`e210451f789ebe46f55b13ae049894663b796163f7b094ab993218f1cb20aa97`.

The recorded container inspection identifies an outer SLB2 v3 container with
two entries and finds nested PUP headers at offsets `0x400` and
`0x4A5AE600`. The inner PUP headers are visible, while the payload following
the initial header fields remains encrypted in the examined files. No visible
segment-name entry identified as `hypervisor` or `hv` was found.

The tested offline extraction path did not produce a standalone hypervisor
image. The available public PUP-decryption utility depends on the console's
EncryptService; the console path documented for this test was denied with
`EPERM`. This is the result for the examined artifact and available tooling:
it does not establish a universal claim about every possible firmware
decryption path, but it means the current static inputs do not provide an
HV image from which the missing physical addresses can be derived.

### Kernel-image cross-check

The verified community kernel capture remains:

* SHA-256:
  `c3f745e25dc25ee7afef89eb418b295b6334bbefe8aa17e6886483c35d78cddd`
* Layout used for the analysis: text begins at VA
  `0xffffffff9e3f0000`; file offset is treated as ktext-relative offset
  only within the documented flat-image layout.

The capture was also represented as an ELF and examined with Ghidra headless
and REA. The recorded scan found 37 `vmmcall` instruction sites and zero
`vmrun`, `vmload`, or `vmsave` instruction sites. The observed
`vmmcall` sites are consistent with guest-side hypercall wrappers; they do
not expose the implementation of the hypervisor handler.

The wrapper at ktext-relative offset **`0xC16A10`** decodes as:

```asm
push rbp
mov  rbp, rsp
mov  eax, 4
vmmcall
pop  rbp
ret
```

This agrees with the raw-byte scan and the existing table value
`PL5_1360_FUN_VMMCALL_HC4`. The function
`FUN_HV_IOMMU_SET_BUFFERS = 0x4FABD0` is supported by its reference to
`hv_iommu_set_guest_buffers completion error:%d`. The existing findings for
`KERNEL_CFI_CHECK = 0x44F8C0` and
`FUN_SMP_RENDEZVOUS = 0xB04440` remain consistent with the dump analysis.

**Independence caveat:** the REA native provider in this run uses Ghidra
12.1.4, so the REA and Ghidra results are not two independent disassembly
engines. The independent cross-check for the wrapper is the raw-byte scan.
A previous claim of zero `vmmcall` instructions in `ktext` does not apply
to this exact dump: the recorded scan finds 37.

### Status of the three HV references

| Reference | Current conclusion | Reason |
| --- | --- | --- |
| `HV_VMMCALL_HANDLER_PA` | **Unknown; do not populate** | It denotes the hypervisor-side handler, not the guest wrapper at `0xC16A10`. No 13.60 HV image or equivalent static evidence is available in the examined inputs. |
| `HV_CODE_CAVE_PA` | **Leave unset unless the selected design demonstrably requires it** | No 13.60 executable HV cave has been identified from an HV image. Legacy values from firmware versions up to 7.61 are not evidence for 13.60. |
| `HV_HANDLE_VMEXIT_PA` | **Leave unset unless the selected design demonstrably requires it** | No 13.60 HV image or verified handler address is available in this analysis. |

Do not substitute the guest-side wrapper, a kernel offset, or a legacy
`0x628xxxxx` value for an HV physical address. Keep the existing fail-closed
guard on the takeover path; the kernel capture and PUP observations do not
justify removing it.

The remaining uncertainty is bounded: the kernel-side references listed above
have static evidence, while the three HV references do not have a verified
13.60 source image in the analyzed material.
