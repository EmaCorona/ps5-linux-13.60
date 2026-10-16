# 13.60 boot requirements — which unresolved values actually block what

The 13.60 table has several fields left at `0`. This file answers, for each one, **what it blocks** —
with the call site that decides it — so that "zero" is never read as "missing" and no gap is filled
just because the shared struct has a slot for it.

## The fact that decides most of the table

`source/main.c` stages the legacy kernel shellcode only below 0x0800:

```c
if (fw < 0x0800) {
    if (prepare_resume(&shellcode_kernel, &shellcode_kernel_len)) { ... }
} else {
    notify("high-FW: skipping legacy shellcode_kernel staging.\n");
}
```

13.20 and 13.60 take the `else` branch. `prepare_resume()` — and therefore `prepare_sck_args()`,
which is the only *writer* of the `shellcode_kernel_args` structure — is never called on the 13.60
path. Every field whose only reader lives in `source/boot/prepare_resume.c` is consequently **not
required by the path this port actually runs**, whatever it may be required by on a 3.xx–7.xx
console.

`KERNEL_CFI_CHECK` is the exception that proves the rule: it is written there too, but it is *also*
read by `hv_defeat_1360.c` (phase-A CFI patch and its read-back check), so it is required — and it
has a value (`0x44F8C0`, derived from the capture).

## Requirement matrix

`blocks` is the disposition used by the registry and enforced by
`tools/check_offset_registry.py`: `boot_minimal` (a value is mandatory for reaching the kernel entry
point), `phase_b` (mandatory only for the post-resume takeover), `optional` (absence is handled),
`none` (not on this path at all).

| field(s) | value | reader (call site) | on the 13.60 path? | blocks |
| --- | --- | --- | --- | --- |
| gadget/symbol cluster used by `hv_defeat_1360.c` (lines 228–258: `KERNEL_SYM_HV_MP_STARTUP_CALL`, `KERNEL_SYM_PMAP_STORE`, `KERNEL_SYM_DATA_CAVE`, `KERNEL_SYM_DMPML4I`, `KERNEL_SYM_DMPDPI`, `KERNEL_SYM_PML4PML4I`, `IDT`, `COMMON_TSS`, `HV_SYM_HEAP_BASE`, `HV_SYM_PCPUS`, `HV_LOADER_PA_REGULAR`, the `GAD_*` set) | set | `hv_defeat_1360()` arm/escape | **yes** | `boot_minimal` |
| `KERNEL_CFI_CHECK` | `0x44F8C0` | `hv_defeat_1360.c:187/760/769` (phase-A patch + verify) | **yes** | `boot_minimal` |
| `FUN_PRINTF`, `FUN_HV_IOMMU_SET_BUFFERS`, `FUN_HV_IOMM_WAIT_COMPLETION`, `FUN_SMP_RENDEZVOUS` | set | `prepare_sck_args()` only, in C | no (legacy vector); `FUN_SMP_RENDEZVOUS` matters again for phase B | `phase_b` |
| `FUN_SMP_NO_RENDEVOUS_BARRIER` | `0` | `prepare_sck_args()` | no | `none` — the shellcode can supply its own no-op |
| `IOMMU_SOFTC` | `0` | `prepare_sck_args()`, `hw/iommu.c` | no (IOMMU setup is in the legacy kernel shellcode) | `none` |
| `KERNEL_UART_OVERRIDE` | `0` | `prepare_sck_args()` | no | `none` |
| `KERNEL_CODE_CAVE` | `0` | `prepare_sck_args()` (guarded `== 0`), legacy `hv_defeat_0304/0506/0607` | no | `none` — and `0x2D39000` is kernel **data**, not a code cave |
| `HV_CODE_CAVE_PA`, `HV_HANDLE_VMEXIT_PA` | `0` | `prepare_sck_args()` | no — the Byepervisor vector runs from `startup_mp` | `none` |
| `G_VBIOS` | `0x3DDB9F0` (**DISPUTED**) | `prepare_sck_args()` | no | `none` for the current path; the dispute itself is the open item |
| `FUN_TRANSMITTER_CONTROL`, `FUN_MP3_INITIALIZE`, `FUN_MP3_INVOKE` | `0` | `prepare_sck_args()` | no | `none` for the current path; needed only if display/audio support is claimed |
| `PS5_WIFI_FW_OFFSET`, `PS5_WIFI_FW_SIZE` | `0` | `hw/firmware.c:97` ← `dump_device_firmwares()` ← `boot/loader.c:164` (runs for 13.60 too) | yes, but **fails gracefully**: it notifies `PS5 WiFi firmware offset missing for firmware 1360` and `loader.c` logs `Continuing` | `optional` |
| `DATA_BASE_GVMSPACE` | `0` | `hw/gpu.c:295` in `gpu_init()` | **`gpu_init()` has no caller in this tree** | `none` (dead on this tree — see below) |
| `IOMMU_SOFTC`, `VMSPACE_VM_ID`, … struct offsets | `0x1E4`/`0x1D8` set | escape helpers | yes | `boot_minimal` where set |
| `HV_VMMCALL_HANDLER_PA` | **no value for 13.60** | phase-B takeover | only with `PL5_1360_TAKEOVER=1` | `phase_b` — phase B stays off, see [`1360-hv-pas-offline-verdict.md`](1360-hv-pas-offline-verdict.md) |

## The minimal goal, stated

Two goals must not be conflated:

1. **minimal**: the Linux kernel is reached and begins initialising (no display, no audio, no Wi-Fi);
2. **usable**: Linux comes up with display, network and audio.

The path currently implemented targets (1), and the evidence above says so structurally: the fields
that carry display/audio/Wi-Fi bring-up live in the legacy `shellcode_kernel_args` structure, which
the 13.60 path never populates. Claiming (2) on 13.60 would require either a different boot chain or
a deliberate decision to populate those fields — starting with proving what `G_VBIOS` actually is.

Nothing here says (1) is achieved: it is not. This matrix only fixes what each `0` means, so that a
future hardware session does not chase fields that the 13.60 path never reads.

## Observation worth a follow-up

`gpu_init()` — the only reader of `DATA_BASE_GVMSPACE` and of the VMSPACE struct offsets — is not
called from anywhere in `source/`. Either the GPU path is reached from code that does not exist yet,
or it is dead and its zero fields are misleading. Recorded as an observation, not acted on here.
