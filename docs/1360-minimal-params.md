# Minimal parameter set for the 13.60 build

Derived from the code that the selected high-firmware vector actually executes, not from the shape of
the shared `offset_list` and not from the 3.00–7.61 path. Method: for each candidate, find its use in
`source/hv/defeat/hv_defeat_1360.c` and `source/shellcode/hv_takeover/takeover.S`; a value that
appears only in `source/boot/prepare_resume.c` is not on this path at all
([`BOOT-REQUIREMENTS-1360.md`](BOOT-REQUIREMENTS-1360.md) explains why).

## Required by phase B

| parameter | namespace | source | state |
| --- | --- | --- | --- |
| `PL5_1360_HV_VMMCALL_HANDLER_PA` | hypervisor physical | hypervisor image — **not obtainable from a kernel capture** | **unknown** → placeholder `#error` |
| `PL5_1360_FUN_VMMCALL_HC4` | kernel text | the 13.60 capture: the hypercall-4 wrapper at `0xC16A10` (`push rbp; mov rbp,rsp; mov eax,4; vmmcall; pop rbp; ret`) | placeholder in the source, but the value is **named in the guard message itself**; filling it is a transcription, not a discovery |
| `env_offset.KERNEL_CFI_CHECK` | kernel text | capture, dump-verified (`0x44F8C0`) | set |
| `env_offset.FUN_SMP_RENDEZVOUS` | kernel text | capture, dump-verified (`0xB04440`); `takeover.S` has the per-firmware `OFF_FUN_SMP_RENDEZVOUS` (`0xaf94e0` for 13.20, `0xb04440` for 13.60) | set |
| the gadget/symbol cluster | kernel text/data | see the table in `hv_defeat_1360.c` (lines ~228–258) and the registry | set |

Plus `PL5_TAKEOVER_FW=1360`, which makes the blob carry the 1360 values instead of 13.20's — a build
parameter, not an address.

**Minimal blocking set = one item**: `PL5_1360_HV_VMMCALL_HANDLER_PA`. Everything else that phase B
needs is already in the tree or is a transcription of a value the code quotes.

## Explicitly *not* required

| parameter | why it looks required but is not |
| --- | --- |
| `HV_CODE_CAVE_PA` | zero references in `hv_defeat_1360.c` and in `takeover.S`. The Byepervisor high-FW vector runs from `startup_mp`, not from a fixed VMEXIT cave. It is read only by `prepare_sck_args()`, which the 13.60 path never calls |
| `HV_HANDLE_VMEXIT_PA` | same: read only by `prepare_sck_args()` |
| `KERNEL_CODE_CAVE` | legacy vectors only; the high-FW path stages into `KERNEL_SYM_DATA_CAVE` |
| `IOMMU_SOFTC`, `KERNEL_UART_OVERRIDE`, `FUN_SMP_NO_RENDEVOUS_BARRIER` | `prepare_sck_args()` only |
| `G_VBIOS`, `FUN_TRANSMITTER_CONTROL`, `FUN_MP3_*` | display/audio bring-up on the legacy path; not read on 13.60 |
| `PS5_WIFI_FW_*` | optional, and its absence is handled (`hw/firmware.c:97`) |

The two `HV_*_PA` fields above are the clearest example of the trap the plan warns about: they are
present in the shared struct, they have plausible-looking 13.20 values, and they are **not used by
this vector**. Chasing them would have produced a build that "enabled" phase B with parameters nothing
reads.

## Consequence

The 13.60 phase B is blocked by exactly one unknown, and that unknown is the one a kernel capture
cannot supply. That is consistent with [`1360-hv-source-search.md`](1360-hv-source-search.md):
`BLOCKED`, phase B off, and the independent work (hook design, resume contract, boot data, tests)
completed instead.
