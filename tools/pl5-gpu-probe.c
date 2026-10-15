/*
 * pl5-gpu-probe.c -- read-only reconnaissance of the PS5 13.60 GPUVM (GPU page
 * tables). It allocates the three direct-memory buffers the GPU-DMA primitive
 * needs, resolves the VMID, enumerates gvmspace[0..15] and dumps the first
 * entries of each GPU page directory. It never retargets a leaf and never
 * submits a DMA packet, so it cannot corrupt GPU state.
 *
 * Purpose: pin down, on the real console, the values the 13.60 GPU-DMA read
 * needs (gvmspace array location, page_dir_va/size/start_va, leaf granularity)
 * before any code is allowed to rewrite a GPU leaf.
 */
#include "utils.h"

#include <fcntl.h>
#include <ps5/kernel.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "byepervisor/kdlsym.h"

/* ps5-hen / GPU-DMA constants (see include/hw/gpu.h) */
#define PROT_GPU_READ 0x10
#define PROT_GPU_WRITE 0x20
#define MAP_NO_COALESCE 0x00400000ULL
#define GPU_DIRECT_MEM_TYPE 0xbULL
#define DMEM_SIZE 0x200000ULL

/* 13.60 candidates (analyst's measurements) */
#define OFF_VMSPACE_VM_VMID 0x1FCULL
#define OFF_DATA_GVMSPACE 0x2EEA570ULL
#define GVMSPACE_STRIDE 0x100ULL
#define OFF_GVM_PAGE_DIR_VA 0x38ULL
#define OFF_GVM_START_VA 0x08ULL
#define OFF_GVM_SIZE 0x10ULL

int sceKernelAllocateDirectMemory(off_t search_start, off_t search_end,
                                  size_t len, size_t alignment, int memory_type,
                                  off_t *phys_out);
int sceKernelMapDirectMemory(void **addr, size_t len, int prot, int flags,
                             off_t phys, size_t alignment);

static void dump_words(const char *tag, uint64_t va, int n) {
  for (int i = 0; i < n; i += 2) {
    uint64_t a = 0, b = 0;
    kread(va + i * 8, &a, 8);
    kread(va + (i + 1) * 8, &b, 8);
    notify("probe: %s[%d] @%#lx = %#lx %#lx\n", tag, i,
           (unsigned long)(va + i * 8), (unsigned long)a, (unsigned long)b);
  }
}


/* ---- GPU page-table walk (13.60 model: 5 levels for 8 KB leaves) -------- */
#define GPU_PTR_MASK   0x0000FFFFFFFFFFC0ULL /* table pointers, bits 6..47  */
#define GPU_LEAF8K_MASK 0x0000FFFFFFFFE000ULL /* 8 KB leaf, bits 13..47     */
#define GPU_LEAF2M_MASK 0x0000FFFFFFE00000ULL /* 2 MB leaf, bits 21..47     */

static uint64_t rd64v(uint64_t va) {
  uint64_t v = 0;
  kernel_copyout((intptr_t)va, &v, 8);
  return v;
}

/* Walk pdb2 (a kernel VA) down to the leaf for GPU VA `gva`. Returns 2/8/4 for
 * the leaf granularity, or -1. Fills the leaf PTE's dmap VA and raw value. */
static int gpu_walk(const char *tag, uint64_t pdb2_va, uint64_t gva,
                    uint64_t *leaf_va_out, uint64_t *leaf_val_out) {
  uint64_t i4 = (gva >> 39) & 0x1FF, e, t;
  e = rd64v(pdb2_va + i4 * 8);
  if (!(e & 1))
    return -1;
  t = dmap + (e & GPU_PTR_MASK);
  uint64_t i3 = (gva >> 30) & 0x1FF;
  e = rd64v(t + i3 * 8);
  if (!(e & 1))
    return -1;
  t = dmap + (e & GPU_PTR_MASK);
  uint64_t i2 = (gva >> 21) & 0x1FF;
  e = rd64v(t + i2 * 8);
  notify("gpuprobe: %s lvl2[%lu] @%#lx = %#lx is_pte=%lu tf=%lu frag=%lu\n", tag,
         i2, (unsigned long)(t + i2 * 8), (unsigned long)e,
         (unsigned long)((e >> 54) & 1), (unsigned long)((e >> 56) & 1),
         (unsigned long)((e >> 59) & 0xF));
  if (!(e & 1))
    return -1;
  if ((e >> 54) & 1) { /* 2 MB leaf at level 2 */
    *leaf_va_out = t + i2 * 8;
    *leaf_val_out = e;
    return 2;
  }
  t = dmap + (e & GPU_PTR_MASK);
  if ((e >> 56) & 1) { /* TF: 8 KB leaf sub-table */
    uint64_t i1 = (gva >> 16) & 0x1F;
    e = rd64v(t + i1 * 8);
    if (!(e & 1))
      return -1;
    t = dmap + (e & GPU_LEAF8K_MASK);
    uint64_t i0 = (gva >> 13) & 0x7;
    e = rd64v(t + i0 * 8);
    notify("gpuprobe: %s leaf8k[%lu] @%#lx = %#lx phys=%#lx bit50=%lu\n", tag,
           i0, (unsigned long)(t + i0 * 8), (unsigned long)e,
           (unsigned long)(e & GPU_LEAF8K_MASK),
           (unsigned long)((e >> 50) & 1));
    *leaf_va_out = t + i0 * 8;
    *leaf_val_out = e;
    return 8;
  }
  /* The entry below the 64 KB table is the 8 KB leaf *sub-table* pointer when
   * TF (bit 56) is set; the real 8 KB leaf PTE lives one level further down,
   * indexed by (gva >> 13) & 0x7. */
  uint64_t i1 = (gva >> 16) & 0x1F;
  e = rd64v(t + i1 * 8);
  notify("gpuprobe: %s ptb[%lu] @%#lx = %#lx tf=%lu frag=%lu\n", tag, i1,
         (unsigned long)(t + i1 * 8), (unsigned long)e,
         (unsigned long)((e >> 56) & 1), (unsigned long)((e >> 59) & 0xF));
  if (!(e & 1))
    return -1;
  uint64_t sub = dmap + (e & GPU_LEAF8K_MASK);
  uint64_t i0 = (gva >> 13) & 0x7;
  e = rd64v(sub + i0 * 8);
  notify("gpuprobe: %s leaf8k[%lu] @%#lx = %#lx phys=%#lx bit50=%lu\n", tag, i0,
         (unsigned long)(sub + i0 * 8), (unsigned long)e,
         (unsigned long)(e & GPU_LEAF8K_MASK), (unsigned long)((e >> 50) & 1));
  *leaf_va_out = sub + i0 * 8;
  *leaf_val_out = e;
  return 8;
}

int main(void) {
  uint64_t curproc, vmspace, vmid, kdata_base;
  int fd;

  if (set_offsets()) {
    notify("gpuprobe: set_offsets failed\n");
    return 1;
  }
  if (init_global_vars()) {
    notify("gpuprobe: init_global_vars failed\n");
    return 1;
  }
  kernel_set_ucred_authid(getpid(), 0x4800000000000007);

  kdata_base = KERNEL_ADDRESS_DATA_BASE;
  curproc = kernel_get_proc(getpid());
  vmspace = kread64(curproc + KERNEL_OFFSET_PROC_P_VMSPACE);
  vmid = kread64(vmspace + OFF_VMSPACE_VM_VMID);
  notify("gpuprobe: fw=%04x ktext=%#lx kdata=%#lx dmap=%#lx\n", fw,
         (unsigned long)ktext, (unsigned long)kdata, (unsigned long)dmap);
  notify("gpuprobe: proc=%#lx vmspace=%#lx vmid(+0x1FC)=%#lx (u32=%u)\n",
         (unsigned long)curproc, (unsigned long)vmspace, (unsigned long)vmid,
         (unsigned)(vmid & 0xFFFFFFFF));

  /* ---- the three buffers the primitive needs ---------------------------- */
  struct {
    const char *name;
    off_t off;
    void *va;
  } bufs[3] = {{"victim", 0, 0}, {"staging", 0, 0}, {"cmd", 0, 0}};

  for (int i = 0; i < 3; i++) {
    int ret = sceKernelAllocateDirectMemory(0, 0x400000000ULL, DMEM_SIZE,
                                            DMEM_SIZE, (int)GPU_DIRECT_MEM_TYPE,
                                            &bufs[i].off);
    if (ret != 0) {
      notify("gpuprobe: allocate %s failed 0x%x\n", bufs[i].name, ret);
      return 1;
    }
    ret = sceKernelMapDirectMemory(&bufs[i].va, DMEM_SIZE,
                                   PROT_READ | PROT_WRITE | PROT_GPU_READ |
                                       PROT_GPU_WRITE,
                                   (int)MAP_NO_COALESCE, bufs[i].off, DMEM_SIZE);
    if (ret != 0) {
      notify("gpuprobe: map %s failed 0x%x\n", bufs[i].name, ret);
      return 1;
    }
    memset(bufs[i].va, 0, DMEM_SIZE);
    notify("gpuprobe: %s va=%#lx off=%#lx\n", bufs[i].name,
           (unsigned long)(uintptr_t)bufs[i].va, (unsigned long)bufs[i].off);
  }

  /* put a recognisable pattern in the victim for a later DMA self-test */
  for (int i = 0; i < 8; i++)
    ((volatile uint64_t *)bufs[0].va)[i] = 0xDEADBEEF00000000ULL | (uint64_t)i;

  fd = open("/dev/gc", O_RDWR);
  if (fd < 0)
    fd = open("/dev/gc0", O_RDWR);
  notify("gpuprobe: /dev/gc fd=%d\n", fd);

  /* ---- enumerate gvmspace[0..15] ---------------------------------------- */
  int found = 0;
  for (int vm = 0; vm < 16; vm++) {
    uint64_t base =
        kdata_base + OFF_DATA_GVMSPACE + (uint64_t)vm * GVMSPACE_STRIDE;
    uint64_t pd = 0, start = 0, size = 0;
    kread(base + OFF_GVM_PAGE_DIR_VA, &pd, 8);
    kread(base + OFF_GVM_START_VA, &start, 8);
    kread(base + OFF_GVM_SIZE, &size, 8);

    if (pd == 0 && start == 0 && size == 0)
      continue;
    found++;
    notify("gpuprobe: gvmspace[%d] @%#lx page_dir_va=%#lx start=%#lx size=%#lx\n",
           vm, (unsigned long)base, (unsigned long)pd, (unsigned long)start,
           (unsigned long)size);

    dump_words("  va", pd, 4);
    dump_words("  pa", dmap + (pd & 0x000FFFFFFFFFF000ULL), 4);
  }
  notify("gpuprobe: gvmspace entries seen=%d\n", found);

  /* Our allocate/map returned CPU VAs; on 13.60 the GPU VM is a full 48-bit
   * space and the garlic buffers land at a fixed high GPU VA base (0xc80000000
   * for the first allocation, +2 MB each). Walk every populated tree for those
   * three GPU VAs to find the victim/staging/cmd leaves. */
  static const uint64_t gvas[3] = {0xc80000000ULL, 0xc80200000ULL, 0xc80400000ULL};
  static const char *gnames[3] = {"victim", "staging", "cmd"};
  for (int vm = 0; vm < 16; vm++) {
    uint64_t base =
        kdata_base + OFF_DATA_GVMSPACE + (uint64_t)vm * GVMSPACE_STRIDE;
    uint64_t pd = 0, size = 0;
    kread(base + OFF_GVM_PAGE_DIR_VA, &pd, 8);
    kread(base + OFF_GVM_SIZE, &size, 8);
    if (!pd || !size)
      continue;
    if (pd >> 48 == 0) /* the top level is a kernel VA, not a physical */
      pd = dmap + (pd & 0x000FFFFFFFFFF000ULL);
    for (int k = 0; k < 3; k++) {
      uint64_t lv = 0, lval = 0;
      int gran = gpu_walk(gnames[k], pd, gvas[k], &lv, &lval);
      notify("gpuprobe: vmid=%d %s gva=%#lx -> gran=%d leaf@%#lx val=%#lx\n", vm,
             gnames[k], (unsigned long)gvas[k], gran, (unsigned long)lv,
             (unsigned long)lval);
    }
  }

  notify("gpuprobe: done (no retarget, no DMA submitted)\n");
  return 0;
}
