# The working 13.60 loader as a reference (Sonic ISO's 1360linux.elf)

While porting we had to resolve nine offsets that no public source documented. A working
loader turned up that already carries all of them, so it is used here as a **reference to
compare against** - never as a value to copy on faith. This file records what it is, how to
re-read it reproducibly, and what we did with each difference.

## Identity

| | |
| --- | --- |
| file | `1360linux.elf` |
| size | 237448 bytes |
| sha256 | `e51a0298cb2c97b71be0ddad9f070b574c110c899d9fe513562355272fc81226` |
| kind | ELF 64-bit x86-64 PIE, dynamically linked, **not stripped** |
| what it is | the 13.60 Linux loader published by Sonic ISO for testing |
| provenance | handed over by the operator; the same build is demonstrated booting Linux on a 13.60 console in a public video. Not a repository: no source, no documentation, no hash published upstream |

Being "not stripped" is what makes it readable: it keeps `set_offsets`, `get_offset_va`,
`dump_ps5_wifi_firmware`, `iommu_init`, `gpu_set_offsets` and friends.

## How it carries the offsets

`set_offsets()` reads the firmware version and copies one of **28 per-firmware structs**
(3.00 through 13.60) into a global `env_offset`; the boot code then reads fields out of
that global. The struct layout is the one in the upstream `include/offsets.h`
(IOMMU_SOFTC, VMSPACE_VM_VMID, VMSPACE_VM_PMAP, DATA_BASE_GVMSPACE, ACPIGBL_FACS, IDT,
COMMON_TSS, ... PS5_WIFI_FW_OFFSET, PS5_WIFI_FW_SIZE). `dump_ps5_wifi_firmware()` refuses to
run unless `env_offset+0x128` and `env_offset+0x130` are both non-zero - which is how the
Wi-Fi fields were pinned: those are exactly the 38th and 39th struct fields.

Reproduce with:

```
python3 tools/extract_elf_1360_table.py <path to 1360linux.elf>
```

The tool locates the table **by content** (it requires at least three of our independently
verified 13.60 anchors to sit at exactly the relative distances the struct demands) rather
than by a hardcoded address, then prints every field.

## The 13.60 table as it stands in that loader

```
+0x000  IOMMU_SOFTC                                0x3543a70  (55851632)
+0x008  VMSPACE_VM_VMID                            0x1ec  (492)
+0x010  VMSPACE_VM_PMAP                            0x1d8  (472)
+0x018  DATA_BASE_GVMSPACE                         0x3baa570  (62563696)
+0x020  ACPIGBL_FACS                               0x39c9490  (60593296)
+0x028  IDT                                        0x3bb4300  (62604032)
+0x030  COMMON_TSS                                 0x3bb6fe0  (62615520)
+0x038  STOPPED_CPUS                               0x0  (0)
+0x040  FUN_STOP_CPUS                              0x0  (0)
+0x048  FUN_AS_LAPIC_EOI                           0x0  (0)
+0x050  FUN_HV_UNMAP_PT_TMR                        0x0  (0)
+0x058  FUN_MEMCPY                                 0x2590b0  (2461872)
+0x060  GAD_ADD_RSP_28_POP_RBP_RET                 0x9e32b4  (10367668)
+0x068  GAD_IRETQ                                  0x257b3d  (2456381)
+0x070  GAD_POP_RAX_RET                            0xb8ca6e  (12110446)
+0x078  GAD_POP_RDI_RET                            0x28ce6d  (2674285)
+0x080  GAD_POP_RSI_RET                            0x34cb91  (3459985)
+0x088  GAD_POP_RDX_RET                            0x2a0f7b  (2756475)
+0x090  GAD_POP_RCX_RET                            0x2918b2  (2693298)
+0x098  GAD_POP_RSP_RET                            0xb8291b  (12069147)
+0x0a0  GAD_WRMSR_RET                              0x255034  (2445364)
+0x0a8  GAD_MOV_QWORD_PTR_RDI_RSI_POP_RBP_RET      0x3d3f2a  (4013866)
+0x0b0  HOOK_ACPI_WAKEUP_MACHDEP                   0x0  (0)
+0x0b8  KERNEL_CODE_CAVE                           0xcb92c0  (13341376)
+0x0c0  FUN_PRINTF                                 0x25d410  (2479120)
+0x0c8  FUN_HV_IOMMU_SET_BUFFERS                   0xc16b00  (12675840)
+0x0d0  FUN_HV_IOMM_WAIT_COMPLETION                0xc16a40  (12675648)
+0x0d8  FUN_SMP_RENDEZVOUS                         0xb03ba0  (11549600)
+0x0e0  FUN_SMP_NO_RENDEVOUS_BARRIER               0x261e08  (2498056)
+0x0e8  HV_CODE_CAVE_PA                            0x62806f00  (1652584192)
+0x0f0  HV_HANDLE_VMEXIT_PA                        0x62847375  (1652847477)
+0x0f8  KERNEL_UART_OVERRIDE                       0x21f9598  (35624344)
+0x100  KERNEL_CFI_CHECK                           0x44f8c0  (4520128)
+0x108  G_VBIOS                                    0x3ddb9f0  (64862704)
+0x110  FUN_TRANSMITTER_CONTROL                    0xc0eaa0  (12642976)
+0x118  FUN_MP3_INITIALIZE                         0xa14130  (10567984)
+0x120  FUN_MP3_INVOKE                             0xa12d30  (10562864)
+0x128  PS5_WIFI_FW_OFFSET                         0x1518160  (22118752)
+0x130  PS5_WIFI_FW_SIZE                           0x7a248  (500296)
```

## Differences against ours, and what was done with each

| campo | nostro | loro | esito |
| --- | --- | --- | --- |
| `IOMMU_SOFTC` | `0x3543a70` | `0x3543a70` | **uguale** |
| `VMSPACE_VM_VMID` | `0x1ec` | `0x1ec` | **uguale** |
| `VMSPACE_VM_PMAP` | `0x1d8` | `0x1d8` | **uguale** |
| `DATA_BASE_GVMSPACE` | `0x3baa570` | `0x3baa570` | **uguale** |
| `ACPIGBL_FACS` | — | `0x39c9490` | solo loro (riferimento) |
| `IDT` | `0x3bb4300` | `0x3bb4300` | **uguale** |
| `COMMON_TSS` | `0x3bb6fe0` | `0x3bb6fe0` | **uguale** |
| `STOPPED_CPUS` | — | `0x0` | solo loro (riferimento) |
| `FUN_STOP_CPUS` | — | `0x0` | solo loro (riferimento) |
| `FUN_AS_LAPIC_EOI` | — | `0x0` | solo loro (riferimento) |
| `FUN_HV_UNMAP_PT_TMR` | — | `0x0` | solo loro (riferimento) |
| `FUN_MEMCPY` | — | `0x2590b0` | solo loro (riferimento) |
| `GAD_ADD_RSP_28_POP_RBP_RET` | `0x25213e` | `0x9e32b4` | **divergente** |
| `GAD_IRETQ` | `0x257b3d` | `0x257b3d` | **uguale** |
| `GAD_POP_RAX_RET` | `0x2912a1` | `0xb8ca6e` | **divergente** |
| `GAD_POP_RDI_RET` | `0x28ce6d` | `0x28ce6d` | **uguale** |
| `GAD_POP_RSI_RET` | `0x34cb91` | `0x34cb91` | **uguale** |
| `GAD_POP_RDX_RET` | `0x2a0f7b` | `0x2a0f7b` | **uguale** |
| `GAD_POP_RCX_RET` | `0x2918b2` | `0x2918b2` | **uguale** |
| `GAD_POP_RSP_RET` | `0x291c42` | `0xb8291b` | **divergente** |
| `GAD_WRMSR_RET` | `0x255034` | `0x255034` | **uguale** |
| `GAD_MOV_QWORD_PTR_RDI_RSI_POP_RBP_RET` | — | `0x3d3f2a` | solo loro (riferimento) |
| `HOOK_ACPI_WAKEUP_MACHDEP` | `0x3913b0` | `0x0` | **divergente** |
| `KERNEL_CODE_CAVE` | — | `0xcb92c0` | solo loro (riferimento) |
| `FUN_PRINTF` | `0x4add60` | `0x25d410` | **divergente** |
| `FUN_HV_IOMMU_SET_BUFFERS` | `0xc16b00` | `0xc16b00` | **uguale** |
| `FUN_HV_IOMM_WAIT_COMPLETION` | `0xc16a40` | `0xc16a40` | **uguale** |
| `FUN_SMP_RENDEZVOUS` | `0xb03ba0` | `0xb03ba0` | **uguale** |
| `FUN_SMP_NO_RENDEVOUS_BARRIER` | `0xb03960` | `0x261e08` | **divergente** |
| `HV_CODE_CAVE_PA` | — | `0x62806f00` | solo loro (riferimento) |
| `HV_HANDLE_VMEXIT_PA` | — | `0x62847375` | solo loro (riferimento) |
| `KERNEL_UART_OVERRIDE` | — | `0x21f9598` | solo loro (riferimento) |
| `KERNEL_CFI_CHECK` | `0x44f8c0` | `0x44f8c0` | **uguale** |
| `G_VBIOS` | `0x3ddb9f0` | `0x3ddb9f0` | **uguale** |
| `FUN_TRANSMITTER_CONTROL` | `0xc0eaa0` | `0xc0eaa0` | **uguale** |
| `FUN_MP3_INITIALIZE` | `0xa14130` | `0xa14130` | **uguale** |
| `FUN_MP3_INVOKE` | `0xa12d30` | `0xa12d30` | **uguale** |
| `PS5_WIFI_FW_OFFSET` | `0x1518160` | `0x1518160` | **uguale** |
| `PS5_WIFI_FW_SIZE` | — | `0x7a248` | solo loro (riferimento) |

Decisions, with the evidence for each:

* **`FUN_SMP_RENDEZVOUS` -> `0xB03BA0` (aligned).** Our `0xB04440` came from the
  "smp rendezvous" string xref, but that function has **zero callers** in the kernel: it is
  the one that *prints* the string. `0xB03BA0` has six or more callers, and two independent
  sources use it. Ours stays recorded as the alternative.
* **`FUN_HV_IOMMU_SET_BUFFERS` -> `0xC16B00`, `FUN_HV_IOMM_WAIT_COMPLETION` -> `0xC16A40`
  (aligned).** Theirs are `vmmcall` wrappers (the SET_BUFFERS one is literally
  `mov eax,6 ; vmmcall` and returns through r8/r9), which matches the ABI our own shellcode
  declares: `hv_iommu_set_buffers(cb2_pa, cb3_pa, ...)`. Our previous values pointed at
  IOMMU-**driver** functions (they reference `iommu io`, `iommu bsf`, `iommu_pci_attach`) -
  the wrong side for a field named `HV_iommu`.
* **`VMSPACE_VM_VMID` -> `0x1EC` (aligned).** The loader carries `0x1EC` in both its 13.60
  and its 12.00 tables, and leaves the field zero ("not needed") from 5.00 to 11.00; `0x1E4`
  appears only on 3.00-4.51. Ours was a stale value inherited from older firmware.
* **`VMSPACE_VM_PMAP` stays `0x1D8` (dispute settled).** The loader uses the same `0x1D8` we
  derived, against the payload SDK's `0x2E8`, so the SDK number belongs to a different
  structure or build. The registry entry is no longer `DISPUTED`.
* **`FUN_MP3_INITIALIZE` -> `0xA14130` (aligned, flagged).** This is the one divergence that
  is not settled by reasoning: a signature string ("[MP3] failed to init message thread")
  ties the name to our `0xA13740`, while a loader that *boots* uses `0xA14130`. They are
  container and sender - our function is 2544 bytes and **calls** theirs. Both are real
  entries, so a wrong choice fails loudly rather than subtly; a hardware run decides.
* **Same target, different convention** (verified by decoding, not assumed):
  `FUN_SMP_NO_RENDEZVOUS_BARRIER` theirs `0x261E08` is `jmp 0xB03960` = our value;
  `FUN_PRINTF` theirs `0x25D410` is `jmp 0x4ADD60` = our value.
* **Gadgets** (`GAD_POP_RAX_RET`, `GAD_ADD_RSP_28_POP_RBP_RET`, `GAD_POP_RSP_RET`) differ
  because a kernel contains many valid instances of each pattern. Different picks, not
  disagreements.
* **Fields we leave at zero by design** and that this loader fills for its own HV path:
  `HV_CODE_CAVE_PA` `0x62806f00`, `HV_HANDLE_VMEXIT_PA` `0x62847375`,
  `KERNEL_UART_OVERRIDE` `0x21f9598`, `KERNEL_CODE_CAVE` `0xcb92c0`,
  `HOOK_ACPI_WAKEUP_MACHDEP` (ours has a value, theirs zero). Our registry documents why each
  is out of the path we take; if the takeover path is ever enabled, these are the numbers a
  working loader uses.
* **Fields only it has** (`ACPIGBL_FACS`, `FUN_MEMCPY`, `STOPPED_CPUS`, `FUN_STOP_CPUS`,
  `FUN_AS_LAPIC_EOI`, `FUN_HV_UNMAP_PT_TMR`, `GAD_MOV_QWORD_PTR_RDI_RSI_POP_RBP_RET`): listed
  for reference; they belong to the 5.00-6.02 hypervisor path the upstream header describes,
  which our 13.60 work does not take.

## What this does and does not settle

It settles the mapping (proved by re-reading six other firmwares) and the fields above. It
does **not** prove our payload runs: the loader is evidence about *values*, not about our
code. The one open question it leaves is `FUN_MP3_INITIALIZE`, and that one needs hardware.
