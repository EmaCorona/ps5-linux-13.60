/*
 * db_trampoline — Stage 1 of the #DB hook: decide before touching the frame.
 *
 * This is the gate's entry point required by docs/1360-khook-design.md section 4:
 * the IDT gate must point HERE, not at the pivot gadget, so the frame is untouched
 * on the foreign path and forwarding is a plain jump.
 *
 * Runs in kernel context on the armed core, entered by the CPU with
 *   RSP -> the #DB frame: RIP, CS, RFLAGS, RSP, SS   (vector 1 has no error code)
 *
 * Behaviour:
 *   OURS    -> skip the frame exactly as the pivot does (add rsp,0x28) and return
 *              into the staged chain.
 *   FOREIGN -> restore every register touched and jump to the saved original
 *              handler with the frame exactly as the CPU left it.
 *
 * No calls, no libc, no stack use of its own: only rax and rcx are touched and both
 * are saved/restored, so the interrupted context is intact on the foreign path and
 * the chain owns the registers on the ours path.
 *
 * Firmware independence: no firmware address appears here. Every value is read from
 * the verification block whose offsets are the contract in
 * include/byepervisor/khook_trampoline_block.h.
 *
 * Each check carries a marker line of the form   MARKER CHECK <id>
 * (a plain comment word, not a nested comment) so tests/run_tests.py can assert that
 * every condition of kh_trap_decide() in include/byepervisor/khook_ownership.h is
 * either implemented here or explicitly marked STRUCTURAL.
 */
#include "byepervisor/khook_trampoline_defs.h"

    .section .entry_point,"ax",@progbits
    .global db_trampoline
    .type db_trampoline, @function
db_trampoline:
.Lentry:
    push %rax
    push %rcx

    /* rcx = the scratch page base. The trampoline is staged at scratch + KH_TR_OFF_CODE
     * and .Lentry is its first byte, so the base is derived from the entry label, NOT
     * from the current instruction pointer: using the current RIP would be off by the
     * instruction's own offset within the trampoline. Nothing needs patching. */
    lea   .Lentry(%rip), %rcx
    sub   $KH_TR_OFF_CODE, %rcx

    /* CHECK gate_is_ours - IDT[1] still holds what we installed. If a restore (or
     * anyone else) put the original gate back, this trap is not ours to handle. The
     * gate address is read from the block, so it is the real runtime address. */
    movq  KH_TR_OFF_BLOCK + KH_TR_GATE_ADDR(%rcx), %rax
    test  %rax, %rax
    jz    .Lforeign
    movq  (%rax), %rax
    cmpq  KH_TR_OFF_BLOCK + KH_TR_GATE_LO(%rcx), %rax
    jne   .Lforeign
    movq  KH_TR_OFF_BLOCK + KH_TR_GATE_ADDR(%rcx), %rax
    movq  8(%rax), %rax
    cmpq  KH_TR_OFF_BLOCK + KH_TR_GATE_HI(%rcx), %rax
    jne   .Lforeign

    /* CHECK armed */
    cmpq  $0, KH_TR_OFF_BLOCK + KH_TR_ARMED(%rcx)
    je    .Lforeign

    /* CHECK dr6_bs - a #DB that is not a breakpoint trap is not ours. */
    mov   %dr6, %rax
    test  $0x4000, %rax
    jz    .Lforeign

    /* CHECK cookie_magic */
    movabs $KH_TRAP_COOKIE_MAGIC, %rax
    cmpq  %rax, KH_TR_OFF_BLOCK + KH_TR_COOKIE(%rcx)
    jne   .Lforeign

    /* CHECK seq - a trap left over from a previous arming. */
    movq  KH_TR_OFF_BLOCK + KH_TR_SEQ(%rcx), %rax
    cmpq  KH_TR_OFF_BLOCK + KH_TR_EXPECT_SEQ(%rcx), %rax
    jne   .Lforeign

    /* CHECK rip - the interrupted RIP must be the one the trigger recorded. The
     * frame starts 16 bytes above RSP (two pushes). */
    movq  0x10(%rsp), %rax
    cmpq  KH_TR_OFF_BLOCK + KH_TR_EXPECT_RIP(%rcx), %rax
    jne   .Lforeign

    /* CHECK cs */
    movq  0x18(%rsp), %rax
    cmpq  KH_TR_OFF_BLOCK + KH_TR_EXPECT_CS(%rcx), %rax
    jne   .Lforeign

    /* CHECK tf - the trigger sets RFLAGS.TF; without it this is not our single
     * step. */
    testq $KH_RFLAG_TF, 0x20(%rsp)
    jz    .Lforeign

    /* STRUCTURAL core - only one core's TSS IST slot is armed and the IST is
     * per-core, so a #DB on any other core never reaches this code: it enters that
     * core's untouched gate path. Enforced by staging, not by a runtime compare.
     *
     * STRUCTURAL already_triggered - the chain's own live state is the armed flag
     * and the sequence number above; the oneshot disarm clears armed. */

    /* OURS: the frame is ours to consume. Skip it exactly as the pivot gadget does
     * and return into the first chain qword. */
    pop   %rcx
    pop   %rax
    add   $0x28, %rsp
    ret

.Lforeign:
    /* Carry the handler through memory so both registers can be restored before the
     * jump: the interrupted context must look untouched. The slot address is derived
     * from the entry label, so it follows the code wherever it was staged. */
    movq  KH_TR_OFF_BLOCK + KH_TR_HANDLER(%rcx), %rax
    lea   .Lentry + KH_TR_OFF_BLOCK + KH_TR_TARGET - KH_TR_OFF_CODE(%rip), %rcx
    movq  %rax, (%rcx)
    pop   %rcx
    pop   %rax
    jmp   *.Lentry + KH_TR_OFF_BLOCK + KH_TR_TARGET - KH_TR_OFF_CODE(%rip)
.Lend:
    .size db_trampoline, .Lend - db_trampoline
