#include "offsets.h"

/*
 * Firmware 13.60 (high-FW, Byepervisor vector).
 *
 * Value provenance. Every field below carries a tag:
 *
 *   [STATIC]   KNOWN_STATIC              evidenced offline only. Either
 *                                        Byepervisor-Reborn's
 *                                        include/offsets/13_60.h (kernel
 *                                        symbol/gadget map) or the community
 *                                        13.60 kernel capture analysed in
 *                                        docs/1360-offsets-from-dump.md and
 *                                        re-checked independently by
 *                                        tools/verify_off_1360_dump.py
 *                                        (sha256 c3f745e2...cddd).
 *   [HW]       KNOWN_HARDWARE_VALIDATED  additionally confirmed on the console.
 *   [UNKNOWN]  no evidenced value yet; kept 0 on purpose.
 *   [DISPUTED] the sources disagree about the value; kept as-is, not evidence.
 *   [N/A-1360] not required by the 13.60 path (legacy vector only).
 *
 * The kernel text base is KERNEL_ADDRESS_TEXT_BASE = 0xFFFFFFFF9B600000
 * (phys 0x1B600000; generic PS5 rule VA = phys + 0xFFFFFFFF80000000); every
 * kernel value below is a raw offset from that base. HV-image values are
 * hypervisor-relative, NOT ktext-relative, and must never be added to ktext
 * (that is what powered the console off -- see HV_SYM_HEAP_BASE / HV_SYM_PCPUS).
 *
 * No console validation of the kernel values is claimed here. The capture was
 * analysed offline and validation is still owed
 * (docs/1360-offsets-from-dump.md, "Validation still owed on the console").
 * Reading kernel .text on 13.60 powers the console off and must never be used to
 * "verify" a value; phase-B addresses that live in the HV image cannot come from
 * a kernel capture at all (docs/1360-hv-pas-offline-verdict.md).
 *
 * The field order matches include/offsets/offsets.h and is kept structurally
 * identical to off_1320.c so the two tables can be diffed against
 * Byepervisor's 13_20.h / 13_60.h pair.
 */
offset_list off_1360 = {
    /* Loader utils -- VMSPACE_VM_PMAP is stable across 13.xx (Byepervisor
     * hardcodes 0x1D8 for 13.00/13.20/13.60). GVMSPACE not needed here. */
    .IOMMU_SOFTC = 0,                    /* [UNKNOWN] not covered by the dump */
    .VMSPACE_VM_VMID = 0x1E4,            /* [STATIC]  Byepervisor 13_60.h */
    .VMSPACE_VM_PMAP = 0x1D8,            /* [DISPUTED] the old provenance was WRONG: Byepervisor 13_60.h has no such field.
                                             ps5-payload-dev SDK case 0x13600000 gives VM_PMAP = 0x2E8 and
                                             P_ROOT = 0x1D0 (which matches our 3.00 table). Value kept because the
                                             escape path works with it and the capture cannot settle it. */
    .DATA_BASE_GVMSPACE = 0x3BAA570,   /* corroborated: independent 13.60 measurement anchored on the IDT (idt-0x9D90, gap stable on 11.60/12.70/13.60); our IDT at the same anchor re-verified 256/256 gates */
    /* Kernel symbols (Byepervisor 13_60.h) */
    .HOOK_ACPI_WAKEUP_MACHDEP = 0x3913B0, /* [STATIC] Byepervisor 13_60.h */
    /* [N/A-1360] No 13.60 code cave is evidenced. This field previously carried
     * 0x2D39000, which is Byepervisor's KERNEL_SYM_DATA_CAVE: a *data* address
     * (0x2D39000 > .text length 0xCC0000), not executable, and therefore not a
     * code cave. The high-FW (Byepervisor) vector never uses this field --
     * main.c stages shellcode_kernel only for fw < 0x0800 -- so leaving it 0 is
     * safe and stops the 13.60 table from advertising a plausible-looking but
     * unverified address. See tools/verify_off_1360_dump.py. */
    .KERNEL_CODE_CAVE = 0,
    .FUN_PRINTF = 0x4ADD60,              /* [STATIC] Byepervisor 13_60.h; verified as a strict function entry (shape only, not identity) */
    /* HV IOMMU helpers, confirmed against the 13.60 kernel dump
     * (tools/verify_off_1360_dump.py, sha256 c3f745e2...cddd):
     *   FUN_HV_IOMMU_SET_BUFFERS 0x4FABD0 is the strict function entry that
     *     contains "hv_iommu_set_guest_buffers completion error:%d" (str
     *     @0x131236e, xref @0x4FB231). The previously recorded 0x4FB13D is
     *     NOT an entry -- it decodes as `lea rax,[rip+...]` mid-function. */
    .FUN_HV_IOMMU_SET_BUFFERS = 0x4FABD0,   /* [STATIC] strict entry, holds the signature string */
    .FUN_HV_IOMM_WAIT_COMPLETION = 0x4F9030, /* [STATIC] strict entry, "IOMMU: wait command completion" */
    /* [STATIC] smp_rendezvous wrapper (13.20: 0xAF94E0). Needed by the
     * post-resume takeover to drive the multi-core VMMCALL rendezvous. Derived
     * from the 13.60 capture: strict entry, references "smp rendezvous"
     * (docs/1360-offsets-from-dump.md; verify_off_1360_dump.py). Not published
     * in Byepervisor's 13_60.h. */
    .FUN_SMP_RENDEZVOUS = 0xB04440,
    /* [UNKNOWN] the no-op setup/teardown barrier is still unidentified; the
     * shellcode can substitute its own no-op, so this may stay unused. */
    .FUN_SMP_NO_RENDEVOUS_BARRIER = 0xB03960,   /* verified: no-op body push rbp;mov rbp,rsp;pop rbp;ret; the stub at 0x261E08 jmps exactly here */
    .HV_CODE_CAVE_PA = 0,
    .HV_HANDLE_VMEXIT_PA = 0,
    .KERNEL_UART_OVERRIDE = 0,           /* [UNKNOWN] UART override not yet located */
    /* [STATIC] out-of-line UBSan CFI failure handler (13.20: 0x44E5D0), patched
     * to `ret` (0xC3) so raw function-pointer callbacks pass. Derived from the
     * 13.60 capture: strict entry holding the "cfi_check_fail: data %p, caller
     * %p, callee %p" string (verify_off_1360_dump.py). Not published in
     * Byepervisor's 13_60.h. */
    .KERNEL_CFI_CHECK = 0x44F8C0,
    /* [DISPUTED] display bring-up value, required by the Linux boot path (not by
     * the escape). The sources disagree: this table claims "derived from the
     * 13.60 dump and validated on-console", but docs/1360-offsets-from-dump.md
     * lists G_VBIOS under "Still not covered by this dump" and
     * docs/1360-port-status.md section 5 lists it among the symbols still
     * unknown. Value left as-is; do not cite it as evidence until one statement
     * is withdrawn (reconcile in Task 11). */
    .G_VBIOS = 0x3DDB9F0,
    .FUN_TRANSMITTER_CONTROL = 0,        /* [UNKNOWN] display bring-up; needed for the Linux boot path, not the escape */
    .FUN_MP3_INITIALIZE = 0xA13740,   /* verified: SIG "[MP3] failed to init message thread" -> 1 xref -> fn 0xA13740 (entry, prologue) */
    .FUN_MP3_INVOKE = 0,                 /* [UNKNOWN] audio; needed for the Linux boot path, not the escape */
    /* [UNKNOWN] WiFi firmware blob not yet located */
    .PS5_WIFI_FW_OFFSET = 0,
    .PS5_WIFI_FW_SIZE = 0,
    /* Gadgets. Byepervisor-Reborn 13_60.h unless noted; the 11 pivot/iretq/pop*/
    /* /cld/ret gadgets were also byte-compared against the 13.60 capture. */
    .GAD_ADD_RSP_28_POP_RBP_RET = 0x25213E, /* [STATIC] dump-verified: 48 83 c4 28 f3 c3 */
    .GAD_IRETQ = 0x257B3D,               /* [STATIC] dump-verified: 48 cf */
    .GAD_POP_RAX_RET = 0x2912A1,         /* [STATIC] dump-verified: 58 c3 */
    .GAD_POP_RCX_RET = 0x2918B2,         /* [STATIC] dump-verified: 59 c3 */
    .GAD_POP_RDI_RET = 0x28CE6D,         /* [STATIC] dump-verified: 5f c3 */
    .GAD_POP_RSI_RET = 0x34CB91,         /* [STATIC] dump-verified: 5e c3 */
    .GAD_POP_RDX_RET = 0x2A0F7B,         /* [STATIC] dump-verified: 5a c3 */
    .GAD_POP_RSP_RET = 0x291C42,         /* [STATIC] dump-verified: 5c c3 */
    /* [STATIC] WRMSR gadget (`0f 30 c3`), derived from the 13.60 capture. Not
     * published by Byepervisor and not used by the high-FW vector (legacy
     * 6.xx-7.xx ROP only), but the bytes are evidenced, so it is not left 0. */
    .GAD_WRMSR_RET = 0x255034,
    /* Byepervisor high-FW vector */
    .KERNEL_SYM_DMPML4I = 0x3B49294,     /* [STATIC] Byepervisor 13_60.h */
    .KERNEL_SYM_DMPDPI = 0x3B49298,      /* [STATIC] Byepervisor 13_60.h */
    .KERNEL_SYM_PML4PML4I = 0x3B47E4C,   /* [STATIC] Byepervisor 13_60.h */
    .KERNEL_SYM_SYS_GETUID = 0x2A8D60,   /* [STATIC] Byepervisor 13_60.h */
    .KERNEL_SYM_HV_MP_STARTUP_CALL = 0xC16EE0,      /* [STATIC] Byepervisor 13_60.h */
    .KERNEL_SYM_MP_STARTUP_INIT_VECTOR = 0x269FB8,  /* [STATIC] Byepervisor 13_60.h */
    .KERNEL_SYM_PMAP_STORE = 0x3B48FF8,  /* [STATIC] Byepervisor-verbatim; dump holds a kernel VA (0xffffffff9f73441a) there, 0x3B24FF8 holds 0x00 */
    .KERNEL_SYM_DATA_CAVE = 0x2D39000,   /* [STATIC] Byepervisor 13_60.h; kernel-data namespace: >= .text length 0xCC0000 */
    /* HV-relative, NOT ktext-relative: both are < .text length, so they must
     * never be added to ktext (doing so is what powered the console off). */
    .HV_SYM_HEAP_BASE = 0x83028,         /* [STATIC] HV image, relative to the HV base */
    .HV_SYM_PCPUS = 0x82A60,             /* [STATIC] HV image, relative to the HV base */
    /* HV reservation base: not firmware-specific (regular vs pro SoC), same
     * value as 13.20. Regular = 0x062800000; pro = 0x8E0800000. */
    .HV_LOADER_PA_REGULAR = 0x062800000, /* [STATIC] not firmware-specific */
    .HV_LOADER_PA_PRO = 0x8e0800000,     /* [STATIC] not firmware-specific */
    .GAD_POP_R8 = 0xB8CA6D,              /* [STATIC] dump-verified: 47 58 c3 */
    .GAD_STORE_RCX_R8 = 0x474389,        /* [STATIC] Byepervisor 13_60.h */
    .GAD_OR_RCX_EAX = 0x321EA0,          /* [STATIC] Byepervisor 13_60.h */
    .GAD_SET_DR7 = 0xA07BA6,             /* [STATIC] Byepervisor 13_60.h */
    .GAD_ST_RCX_RAX = 0x2BB28F,          /* [STATIC] Byepervisor 13_60.h */
    .GAD_STORE_RDI8_RCX = 0x32693F,      /* [STATIC] Byepervisor 13_60.h */
    .GAD_ST_RCX_RDX = 0x82B915,          /* [STATIC] Byepervisor 13_60.h */
    .GAD_MOV_RAX_RSI = 0x8E3A44,         /* [STATIC] Byepervisor 13_60.h */
    .GAD_MOV_RAX_RDI = 0xBECDEA,         /* [STATIC] Byepervisor 13_60.h */
    .GAD_REP_MOVSB = 0x25D027,           /* [STATIC] Byepervisor 13_60.h */
    .GAD_CLD = 0x30644F,                 /* [STATIC] Byepervisor 13_60.h */
    .GAD_RET_TRAMP = 0x2912A2,           /* [STATIC] Byepervisor 13_60.h */
    .GAD_DBREG_RESUME = 0x2529D8,        /* [STATIC] Byepervisor 13_60.h */
    .IDT = 0x3BB4300,                    /* [STATIC] Byepervisor 13_60.h */
    .COMMON_TSS = 0x3BB6FE0,             /* [STATIC] Byepervisor 13_60.h */
};
