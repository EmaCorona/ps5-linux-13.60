/* khook_trampoline_defs — the shared numeric contract, includable from C AND assembly.
 *
 * The Stage-1 trampoline (source/shellcode/db_trampoline/db_trampoline.S) can only
 * compare values at fixed offsets, and it is assembled, not compiled: values must
 * arrive as preprocessor macros. Duplicating them in the assembly would mean two
 * sources of truth for the same layout, which is how a frame offset gets "fixed" in
 * one place and not the other.
 *
 * So: this file holds only #defines, with no includes and no C code, and it is
 * included by khook_frame.h, khook_ownership.h, khook_trampoline_block.h and the
 * assembly. GAS runs .S through the C preprocessor, so the same file works there.
 */
#ifndef KH_TRAMPOLINE_DEFS_H
#define KH_TRAMPOLINE_DEFS_H

/* ---- #DB frame (vector 1, IST gate, no error code) ---- */
#define KH_DB_FRAME_QWORDS 5
#define KH_DB_FRAME_BYTES 0x28

#define KH_FRAME_RIP_OFF 0x00
#define KH_FRAME_CS_OFF 0x08
#define KH_FRAME_RFLAGS_OFF 0x10
#define KH_FRAME_RSP_OFF 0x18
#define KH_FRAME_SS_OFF 0x20

/* What the pivot gadget consumes before it returns into the staged chain. */
#define KH_PIVOT_SKIP_BYTES KH_DB_FRAME_BYTES

/* RFLAGS bits: TF is what the trigger sets, RF is what the chain sets so the
 * resumed instruction does not re-trigger. */
#define KH_RFLAG_TF 0x100
#define KH_RFLAG_RF 0x10000

/* ---- trap ownership ---- */
#define KH_TRAP_COOKIE_MAGIC 0x4B48434F4F4B4945 /* "KHCOOKIE" */

/* ---- Stage-1 trampoline placement inside the khook's scratch page ---- */
#define KH_TR_OFF_CODE 0x1000
#define KH_TR_OFF_BLOCK 0x1100

#define KH_TR_ARMED 0x00
#define KH_TR_COOKIE 0x08
#define KH_TR_SEQ 0x10
#define KH_TR_EXPECT_SEQ 0x18
#define KH_TR_EXPECT_RIP 0x20
#define KH_TR_EXPECT_CS 0x28
#define KH_TR_HANDLER 0x30
#define KH_TR_TARGET 0x38
#define KH_TR_GATE_ADDR 0x40
#define KH_TR_GATE_LO 0x48
#define KH_TR_GATE_HI 0x50
#define KH_TR_BLOCK_SIZE 0x58

#define KH_TR_CODE_SIZE_MIN 0x40

#endif /* KH_TRAMPOLINE_DEFS_H */
