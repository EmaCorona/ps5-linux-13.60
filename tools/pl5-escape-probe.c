/*
 * pl5-escape-probe.c -- diagnostic payload for the high-FW escape and for the
 * kernel .text read path.
 *
 * Answers two questions on a live console, without rest mode:
 *   1. does the escape actually clear XOTEXT on the kernel .text PTE?
 *   2. why does reading .text through the direct-map alias fail?
 *
 * It never reads .text through its own kernel VA (that faults/panics); the
 * read probes go through the dmap, which is the safe path.
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

static void leaf(const char *tag, uint64_t pmap, uint64_t va) {
  uint64_t e = 0, a;
  a = find_pde(pmap, va, &e);
  notify("probe: %s pde @%#lx=%#lx xotext=%lu rw=%lu ps=%lu\n", tag,
         (unsigned long)a, (unsigned long)e,
         (unsigned long)PDE_FIELD(e, XOTEXT), (unsigned long)PDE_FIELD(e, RW),
         (unsigned long)PDE_FIELD(e, PS));
  a = find_pte(pmap, va, &e);
  notify("probe: %s pte @%#lx=%#lx xotext=%lu rw=%lu nx=%lu\n", tag,
         (unsigned long)a, (unsigned long)e,
         (unsigned long)PDE_FIELD(e, XOTEXT), (unsigned long)PDE_FIELD(e, RW),
         (unsigned long)PDE_FIELD(e, EXECUTE_DISABLE));
}

static uint64_t pa_of(uint64_t pmap, uint64_t va) {
  uint64_t e = 0;
  if (find_pte(pmap, va, &e) == 0xFFFFFFFFFFFFFFFFull)
    return 0;
  return PDE_ADDR(e) | (va & 0xFFF);
}

static int try_read(const char *tag, uint64_t va) {
  uint8_t buf[16];
  int rc = kernel_copyout((intptr_t)va, buf, sizeof(buf));
  notify("probe: read %s @%#lx rc=%d (%s)\n", tag, (unsigned long)va, rc,
         rc == 0 ? "OK" : "FAILED");
  return rc;
}

/* Clear XOTEXT/RW on whatever maps `va` (kernel pmap). Returns 1 if written. */
static int open_mapping(uint64_t pmap, uint64_t va) {
  uint64_t e = 0, a;
  int hit = 0;
  a = find_pde(pmap, va, &e);
  if (a != 0xFFFFFFFFFFFFFFFFull && PDE_FIELD(e, XOTEXT)) {
    CLEAR_PDE_BIT(e, XOTEXT);
    SET_PDE_BIT(e, RW);
    kwrite64(a, e);
    hit = 1;
  }
  a = find_pte(pmap, va, &e);
  if (a != 0xFFFFFFFFFFFFFFFFull && PDE_FIELD(e, XOTEXT)) {
    CLEAR_PDE_BIT(e, XOTEXT);
    SET_PDE_BIT(e, RW);
    kwrite64(a, e);
    hit = 1;
  }
  return hit;
}

int main(void) {
  uint64_t kernel_pmap, kpa, dmap_va;
  int pde_hits = 0, pte_hits = 0;

  if (set_offsets()) {
    notify("probe: set_offsets failed (unsupported fw)\n");
    return 1;
  }
  if (init_global_vars()) {
    notify("probe: init_global_vars failed\n");
    return 1;
  }
  kernel_set_ucred_authid(getpid(), 0x4800000000000007);
  kernel_pmap = kdlsym(KERNEL_SYM_PMAP_STORE);

  notify("probe: fw=%04x ktext=%#lx kdata=%#lx cr3=%#lx dmap=%#lx kernel_pmap=%#lx\n",
         fw, (unsigned long)ktext, (unsigned long)kdata, (unsigned long)cr3,
         (unsigned long)dmap, (unsigned long)kernel_pmap);

  /* --- question 1: does the escape clear XOTEXT on the .text PTE? --------- */
  leaf("BEFORE", kernel_pmap, ktext);
  escape_kernel_text(kernel_pmap, &pde_hits, &pte_hits);
  notify("probe: escape done pde_hits=%d pte_hits=%d\n", pde_hits, pte_hits);
  leaf("AFTER ", kernel_pmap, ktext);

  /* --- question 2: can we read .text through the direct map if we map it? ---
   * The dmap alias of the kernel image is deliberately unmapped (PTE = 0). The
   * alias VA has never been accessed, so unlike the kernel VA it cannot have a
   * stale XOTEXT TLB entry. Map it ourselves (present|RW, no XOTEXT) and read.
   */
  kpa = pa_of(kernel_pmap, ktext);
  dmap_va = dmap + kpa;
  notify("probe: ktext pa=%#lx dmap_alias=%#lx\n", (unsigned long)kpa,
         (unsigned long)dmap_va);

  for (int i = 0; i < 4; i++) {
    uint64_t va = ktext + (uint64_t)i * 0x1000;
    uint64_t pa = pa_of(kernel_pmap, va);
    uint64_t d_va = dmap + pa;
    uint64_t e2 = 0;
    uint64_t pte_addr = find_pte(kernel_pmap, d_va, &e2);
    uint8_t buf[16];
    int rc;

    if (pte_addr == 0xFFFFFFFFFFFFFFFFull) {
      notify("probe: page %d pa=%#lx dmap pte ADDR MISSING\n", i,
             (unsigned long)pa);
      continue;
    }
    notify("probe: page %d pa=%#lx dmap_pte @%#lx=%#lx\n", i,
           (unsigned long)pa, (unsigned long)pte_addr, (unsigned long)e2);
    if (e2 == 0) {
      uint64_t nv = (pa & 0x000FFFFFFFFFF000ULL) | 0x3ULL; /* present|rw */
      kwrite64(pte_addr, nv);
      notify("probe: mapped dmap alias, pte=%#lx\n", (unsigned long)nv);
    }
    rc = kernel_copyout((intptr_t)d_va, buf, sizeof(buf));
    notify("probe: read dmap page %d rc=%d bytes=%02x %02x %02x %02x %02x %02x %02x %02x\n",
           i, rc, buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7]);
  }

  notify("probe: done (no rest mode entered)\n");
  return 0;
}
