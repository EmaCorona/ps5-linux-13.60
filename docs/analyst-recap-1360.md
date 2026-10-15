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
