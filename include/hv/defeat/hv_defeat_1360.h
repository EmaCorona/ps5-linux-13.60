#ifndef HV_DEFEAT_1360_H
#define HV_DEFEAT_1360_H

#include <stddef.h>

/*
 * High-firmware (8.xx+) hypervisor defeat for 13.60, based on the same
 * Byepervisor khook escape used for 13.20. See hv_defeat_1360.c for the design
 * and README.md ("13.60 port") for the values still missing for the
 * post-resume takeover.
 */
int hv_defeat_1360(void *shellcode_kernel, size_t shellcode_kernel_len);

/*
 * Second phase, run after waking from rest mode (once break_hv has disabled
 * NPT). On 13.20 this takes over the hypervisor and boots Linux; on 13.60 the
 * takeover addresses are not known yet, so (unless built with
 * -DPL5_1360_TAKEOVER=1) it confirms the escape and returns with the console
 * resumed, HV defeated.
 */
int hv_defeat_1360_post_resume(void);

/*
 * P4.4b (diagnostic, PL5_DIAG=18): arm a hook that was staged without the
 * #DB gate / IST writes. Called right before the standby request so the #DB
 * hijack is live only across the sleep.
 */
int hv_defeat_1360_arm(void);

#endif

/* Inverse of the escape: restore .text XOTEXT/RW and drop the ARMED marker. */
int hv_defeat_1360_restore(void);
