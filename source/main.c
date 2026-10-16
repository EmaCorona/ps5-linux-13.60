#include "hv_defeat_0304.h"
#include "hv_defeat_0506.h"
#include "hv_defeat_0607.h"
#include "hv_defeat_1320.h"
#include "hv_defeat_1360.h"
#include "loader.h"
#include "prepare_resume.h"
#include "utils.h"

#ifdef PL5_VERIFY_MODE
int pl5_verify_offsets(void);
#endif
#include <signal.h>
#include <unistd.h>

/* Official standby request (as used by Byepervisor-Reborn). The legacy
 * event-flag path (enter_rest_mode) does not flush the TLB, so a post-resume
 * read of kernel .text still hits a stale execute-only entry and panics. */
int sceSystemStateMgrEnterStandby(void);

static void diag_sig(int sig, siginfo_t *si, void *ctx) {
  (void)ctx;
  notify("!! signal %d at %p (code %d).\n", sig, si ? si->si_addr : 0,
         si ? si->si_code : 0);
  _exit(128 + sig);
}

int main(void) {
  struct sigaction sa;
  sa.sa_sigaction = diag_sig;
  sa.sa_flags = SA_SIGINFO;
  sigemptyset(&sa.sa_mask);
  sigaction(SIGTRAP, &sa, 0);
  sigaction(SIGSEGV, &sa, 0);
  sigaction(SIGBUS, &sa, 0);
  sigaction(SIGILL, &sa, 0);
  sigaction(SIGFPE, &sa, 0);
  if (setup_env()) {
    notify("Something went wrong during initialization.\nPlease make sure "
           "your fw is supported.");
    return -1;
  }

#if PL5_1360_RESUME_REPORT_ONLY
  /* T5 exists for one firmware only: its staging rewrites the 13.60 page tables.
   * Refuse before anything is written rather than run the cycle on a target whose
   * numbers were not derived for it. */
  if (fw != 0x1360) {
    notify("report-only resume diagnostic: fw=%#x is not 13.60; refusing.\n", fw);
    return -1;
  }
#endif

#ifdef PL5_DISARM_MODE
  /* WS3: ripristina .text (XOTEXT su, RW giu') e azzera il marker ARMED.
   * Nessun armo, nessuno standby: consegna un kernel pulito senza riavviare. */
  return hv_defeat_1360_restore();
#endif

#ifdef PL5_VERIFY_MODE
  /* WS2: diagnostica di sola verifica. Gira subito dopo setup_env() (che ha gia'
   * popolato env_offset) e esce: nessun fetch dell'immagine, nessun escape,
   * nessun armo, nessuno standby. Vedi tools/pl5-verify-offsets.c. */
  return pl5_verify_offsets();
#endif

#if !defined(PL5_OFFSETS_MODE) && !PL5_1360_RESUME_REPORT_ONLY
  if (fetch_linux(&linux_i)) {
    notify("Something went wrong while installing linux files.\n");
    return -1;
  }
#endif
#if PL5_1360_RESUME_REPORT_ONLY
  /* T5 never boots Linux: it asks whether the *escape staging* survives the sleep.
   * fetch_linux() would drag the images in for a boot that never happens, and it
   * also calls dump_device_firmwares() -- a disk write that has nothing to do with
   * this diagnostic. Measured: without this skip the payload died at "File bzImage
   * not found at default paths" *before* the escape, so the test never reached its
   * subject and the console never slept. */
  notify("13.60: report-only build: Linux install skipped (T5 never boots).\n");
#endif

  int is_1320 = 0;
  int is_1360 = 0;
  void *shellcode_kernel = NULL;
  size_t shellcode_kernel_len = 0;
  if (fw < 0x0800) {
    /* Legacy vectors hand off to shellcode_kernel via the ACPI-wakeup ROP, so
     * it must be staged in the kernel cave before sleeping. */
    if (prepare_resume(&shellcode_kernel, &shellcode_kernel_len)) {
      notify("Something went wrong while preparing resume.\n");
      return -1;
    }
  } else {
    /* The high-FW (Byepervisor khook) vectors boot via shellcode_hv staged from
     * post_resume(); they never use shellcode_kernel, so skip the legacy kernel
     * cave staging + page-table rewrite entirely (fewer arm-time deviations). */
    notify("high-FW: skipping legacy shellcode_kernel staging.\n");
  }

  if ((0x0300 <= fw) && (fw < 0x0500)) {
    if (hv_defeat_0304(shellcode_kernel, shellcode_kernel_len))
      goto err;
  } else if ((0x0500 <= fw) && (fw < 0x0650)) {
    if (hv_defeat_0506(shellcode_kernel, shellcode_kernel_len))
      goto err;
  } else if ((0x0650 <= fw) && (fw < 0x0800)) {
    if (hv_defeat_0607(shellcode_kernel, shellcode_kernel_len))
      goto err;
  } else if ((0x0800 <= fw) && (fw < 0x1400)) {
    /* 13.xx share the Byepervisor khook escape; only env_offset differs. */
    if (fw == 0x1320) {
      if (hv_defeat_1320(shellcode_kernel, shellcode_kernel_len))
        goto err;
      is_1320 = 1;
    } else if (fw == 0x1360) {
      if (hv_defeat_1360(shellcode_kernel, shellcode_kernel_len))
        goto err;
      is_1360 = 1;
    } else {
      goto err;
    }
  } else {
    goto err;
  }

#ifdef PL5_OFFSETS_MODE
  notify("Finished preparation. Going to rest mode in 5 seconds.\nPlease wait "
         "for the orange light to stop blinking, then wake the console to "
         "continue the offset dump.\n");
#else
  notify("Finished preparation. Going to rest mode in 5 seconds.\nPlease wait "
         "for the orange light to stop "
         "blinking and then wakeup to Linux :)\n");
#endif

#if PL5_DIAG >= 10 && PL5_DIAG < 18 && !PL5_1360_RESUME_REPORT_ONLY
  /* P4 bisection: never enter standby; just prove how long the install survives.
   * T5 opts out on purpose: the standby those stages skip is the whole point. */
  notify("13.60: P4 diag=%d — install done; heartbeat, standby SKIPPED\n", PL5_DIAG);
  for (int __i = 0; __i < 20; __i++) {
    notify("13.60: [hb %02d]\n", __i);
    sleep(1);
  }
  return 0;
#endif
  sleep(5);
  if (fw >= 0x0800) {
    /* High-FW: use the real standby path (Byepervisor design) so the TLB is
     * actually invalidated across the suspend/resume cycle. */
#if PL5_DIAG == 18
    if (is_1360)
      hv_defeat_1360_arm();   /* arm-late: hijack live only across the sleep */
#endif
    notify("high-FW: sceSystemStateMgrEnterStandby()...\n");
    sceSystemStateMgrEnterStandby();
  } else {
    enter_rest_mode();
  }

  /* On 13.20/13.60 the console comes back from rest mode with NPT disabled;
   * finish the takeover from here (runs on the BSP once we wake). */
  if (is_1320)
    hv_defeat_1320_post_resume();
#if PL5_1360_RESUME_REPORT_ONLY
  /* T5: report-only cycle. Nothing was armed, so there is no vector to wait for
   * and no takeover to run: report the post-wake state and exit, leaving elfldr
   * free for the next payload. hv_defeat_1360_post_resume() is deliberately NOT
   * called -- it is the continuation T5 exists to separate from the staging.
   * (is_1320 cannot be set in this build: the guard right after setup_env()
   * refuses any firmware other than 13.60.) */
  if (is_1360) {
    hv_defeat_1360_report_resume();
    return 0;
  }
#else
  if (is_1360)
    hv_defeat_1360_post_resume();
#endif

#ifdef PL5_OFFSETS_MODE
  /* Offsets payload: hv_defeat_1320_post_resume() has already dumped the
   * offsets and returned. Exit cleanly so elfldr is free to take the next
   * payload (the normal payload instead sleeps forever to keep the booted
   * kernel/shellcode alive). */
  notify("high-FW: offset payload done; exiting.\n");
  return 0;
#else
  while (1) {
    sleep(30);
  }

  return 0;
#endif

err:
  notify("Something went wrong while defeating Hypervisor.\nPlease make sure "
         "your fw is supported.");
  return -1;
}
