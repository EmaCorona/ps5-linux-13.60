#include "offsets.h"

/*
 * Firmware 13.60 (high-FW, Byepervisor vector).
 *
 * Kernel/HV symbol and gadget offsets are taken verbatim from
 * Byepervisor-Reborn's include/offsets/13_60.h
 * (g_sym_map_1360[] / g_gadget_map_1360[]):
 *   https://github.com/EchoStretch/Byepervisor-Reborn/blob/main/include/offsets/13_60.h
 *
 * The field order below matches include/offsets/offsets.h and is kept
 * structurally identical to off_1320.c so the two can be diffed against
 * Byepervisor's 13_20.h / 13_60.h pair. Unlike 13.20, 13.60 has no local
 * dumps yet, so only the values Byepervisor publishes are filled in; every
 * other field is left 0 and carries an explicit TODO.
 *
 * NOTE: as on 13.20 the kernel text base is KERNEL_ADDRESS_TEXT_BASE =
 * 0xFFFFFFFF9B600000 (phys 0x1B600000; generic PS5 rule VA = phys +
 * 0xFFFFFFFF80000000). Like every other entry, values below are raw offsets
 * from that base.
 *
 * Fields left at 0 are still unknown for 13.60 -- see the "13.60 port" section
 * of README.md. The escape (phase A) runs with only the values present here;
 * the post-resume takeover (phase B) additionally needs the fields marked
 * "phase B" below, which are NOT in Byepervisor's 13_60.h and must come from a
 * real 13.60 console dump (tools/pl5-offsets.c).
 */
offset_list off_1360 = {
    /* Loader utils -- VMSPACE_VM_PMAP is stable across 13.xx (Byepervisor
     * hardcodes 0x1D8 for 13.00/13.20/13.60). GVMSPACE not needed here. */
    .IOMMU_SOFTC = 0,
    .VMSPACE_VM_VMID = 0x1E4,
    .VMSPACE_VM_PMAP = 0x1D8,
    .DATA_BASE_GVMSPACE = 0,
    /* Kernel symbols (Byepervisor 13_60.h) */
    .HOOK_ACPI_WAKEUP_MACHDEP = 0x3913B0,
    /* No 13.60 code cave is evidenced. This field previously carried
     * 0x2D39000, which is Byepervisor's KERNEL_SYM_DATA_CAVE: a *data*
     * address (0x2D39000 > .text length 0xCC0000), not executable, and
     * therefore not a code cave. The high-FW (Byepervisor) vector never uses
     * this field -- main.c stages shellcode_kernel only for fw < 0x0800 -- so
     * leaving it 0 is safe and stops the 13.60 table from advertising a
     * plausible-looking but unverified address. See tools/verify_off_1360_dump.py. */
    .KERNEL_CODE_CAVE = 0,
    .FUN_PRINTF = 0x4ADD60,
    /* HV IOMMU helpers, confirmed against the 13.60 kernel dump
     * (tools/verify_off_1360_dump.py, sha256 c3f745e2...cddd):
     *   FUN_HV_IOMMU_SET_BUFFERS 0x4FABD0 is the strict function entry that
     *     contains "hv_iommu_set_guest_buffers completion error:%d" (str
     *     @0x131236e, xref @0x4FB231). The previously recorded 0x4FB13D is
     *     NOT an entry -- it decodes as `lea rax,[rip+...]` mid-function. */
    .FUN_HV_IOMMU_SET_BUFFERS = 0x4FABD0, /* confirmed: strict entry, holds the signature string */
    .FUN_HV_IOMM_WAIT_COMPLETION = 0x4F9030, /* confirmed: strict entry, "IOMMU: wait command completion" */
    /* TODO(13.60) phase B: smp_rendezvous wrapper (13.20: 0xAF94E0). Needed by
     * the post-resume takeover to drive the multi-core VMMCALL rendezvous.
     * Not published in Byepervisor's 13_60.h; locate from a live dump. */
    .FUN_SMP_RENDEZVOUS = 0xB04440, /* derived from 13.60 kernel dump */
    /* TODO(13.60): the no-op setup/teardown barrier is still unidentified; the
     * shellcode can substitute its own no-op, so this may stay unused. */
    .FUN_SMP_NO_RENDEVOUS_BARRIER = 0,
    /* The Byepervisor vector runs from startup_mp, not a fixed VMEXIT cave */
    .HV_CODE_CAVE_PA = 0,
    .HV_HANDLE_VMEXIT_PA = 0,
    /* TODO(13.60): UART override not yet located */
    .KERNEL_UART_OVERRIDE = 0,
    /* TODO(13.60) phase B: out-of-line UBSan CFI failure handler (13.20:
     * 0x44E5D0); patched to `ret` (0xC3) so raw function-pointer callbacks
     * pass. Not published in Byepervisor's 13_60.h; locate from a live dump
     * (same "cfi_check_fail" signature the offsets tool scans for). */
    .KERNEL_CFI_CHECK = 0x44F8C0, /* derived from 13.60 kernel dump */
    /* TODO(13.60): display bring-up symbols not yet located (needed for the
     * Linux boot path, not for the escape). */
    .G_VBIOS = 0x3DDB9F0, /* VBIOS ROM (0x55AA sig, AMD ATOMBIOS) — derived from the 13.60 dump and validated on-console */
    .FUN_TRANSMITTER_CONTROL = 0,
    .FUN_MP3_INITIALIZE = 0,
    .FUN_MP3_INVOKE = 0,
    /* TODO(13.60): WiFi firmware blob not yet located */
    .PS5_WIFI_FW_OFFSET = 0,
    .PS5_WIFI_FW_SIZE = 0,
    /* Gadgets (Byepervisor-Reborn 13_60.h) */
    .GAD_ADD_RSP_28_POP_RBP_RET = 0x25213E,
    .GAD_IRETQ = 0x257B3D,
    .GAD_POP_RAX_RET = 0x2912A1,
    .GAD_POP_RCX_RET = 0x2918B2,
    .GAD_POP_RDI_RET = 0x28CE6D,
    .GAD_POP_RSI_RET = 0x34CB91,
    .GAD_POP_RDX_RET = 0x2A0F7B,
    .GAD_POP_RSP_RET = 0x291C42,
    /* TODO(13.60): WRMSR gadget not published and not used by the high-FW
     * vector (legacy 6.xx-7.xx ROP only); left 0. */
    .GAD_WRMSR_RET = 0x255034, /* derived from 13.60 kernel dump */
    /* Byepervisor high-FW vector */
    .KERNEL_SYM_DMPML4I = 0x3B49294,
    .KERNEL_SYM_DMPDPI = 0x3B49298,
    .KERNEL_SYM_PML4PML4I = 0x3B47E4C,
    .KERNEL_SYM_SYS_GETUID = 0x2A8D60,
    .KERNEL_SYM_HV_MP_STARTUP_CALL = 0xC16EE0,
    .KERNEL_SYM_MP_STARTUP_INIT_VECTOR = 0x269FB8,
    .KERNEL_SYM_PMAP_STORE = 0x3B48FF8, /* Byepervisor-verbatim; dump holds a kernel VA (0xffffffff9f73441a) there, 0x3B24FF8 holds 0x00 */
    .KERNEL_SYM_DATA_CAVE = 0x2D39000, /* kernel-data namespace: >= .text length 0xCC0000 */
    /* HV-relative, NOT ktext-relative: both are < .text length, so they must
     * never be added to ktext (doing so is what powered the console off). */
    .HV_SYM_HEAP_BASE = 0x83028,   /* HV image, relative to the HV base */
    .HV_SYM_PCPUS = 0x82A60,       /* HV image, relative to the HV base */
    /* HV reservation base: not firmware-specific (regular vs pro SoC), same
     * value as 13.20. Regular = 0x062800000; pro = 0x8E0800000. */
    .HV_LOADER_PA_REGULAR = 0x062800000,
    .HV_LOADER_PA_PRO = 0x8e0800000,
    .GAD_POP_R8 = 0xB8CA6D,
    .GAD_STORE_RCX_R8 = 0x474389,
    .GAD_OR_RCX_EAX = 0x321EA0,
    .GAD_SET_DR7 = 0xA07BA6,
    .GAD_ST_RCX_RAX = 0x2BB28F,
    .GAD_STORE_RDI8_RCX = 0x32693F,
    .GAD_ST_RCX_RDX = 0x82B915,
    .GAD_MOV_RAX_RSI = 0x8E3A44,
    .GAD_MOV_RAX_RDI = 0xBECDEA,
    .GAD_REP_MOVSB = 0x25D027,
    .GAD_CLD = 0x30644F,
    .GAD_RET_TRAMP = 0x2912A2,
    .GAD_DBREG_RESUME = 0x2529D8,
    .IDT = 0x3BB4300,
    .COMMON_TSS = 0x3BB6FE0,
};
