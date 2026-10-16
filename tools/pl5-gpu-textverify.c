/*
 * pl5-gpu-textverify.c -- WS2b: verifica dei sei valori in .text attraverso la GPU.
 *
 * Perche' la GPU: il kernel traduce .text con la propria GPUVM per-VMID, quindi la
 * lettura non passa dalla protezione CPU-side (NPT/nda) che rende pericolosa la
 * lettura del VA del kernel. La lettura via direct map (tentata prima) ha
 * restituito byte con la forma di una page-table entry, quindi quel metodo e'
 * stato scartato: questa e' la via documentata dal repo (pl5-gpu-read).
 *
 * Sequenza, deliberatamente conservativa:
 *   0. gate di validita' del metodo: ritargetta una vittima fresca su una pagina
 *      di .data e confronta il risultato GPU con la lettura CPU. Se non combacia,
 *      il metodo non e' affidabile in questa esecuzione e NON si leggono i valori.
 *   1. per ognuna delle 4 regioni 2 MB che coprono i 6 indirizzi: una vittima
 *      FRESCA (la GPU cachea la traduzione: una foglia gia' tradotta non va mai
 *      ritargettata due volte), ritargettata sulla regione, poi DMA della pagina.
 *   2. ogni foglia toccata viene ripristinata.
 * Verdetto per indirizzo: prologo 55 48 89 (push rbp; mov rbp,rsp) o thunk e9.
 */
#include "utils.h"

#include <errno.h>
#include <fcntl.h>
#include <ps5/kernel.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

#include "byepervisor/kdlsym.h"
#include "byepervisor/paging.h"

#define PROT_GPU_READ 0x10
#define PROT_GPU_WRITE 0x20
#define MAP_NO_COALESCE 0x00400000ULL
#define DMEM_SIZE 0x200000ULL
#define GC_SUBMIT_IOCTL 0xC0108102ULL

#define OFF_DATA_GVMSPACE 0x2EEA570ULL
#define GVMSPACE_STRIDE 0x100ULL
#define OFF_GVM_PAGE_DIR_VA 0x38ULL
#define DEV_VMID 6

#define GPU_PTR_MASK 0x0000FFFFFFFFFFC0ULL
#define GPU_LEAF2M_MASK 0x0000FFFFFFE00000ULL

int sceKernelAllocateDirectMemory(off_t search_start, off_t search_end,
                                  size_t len, size_t alignment, int memory_type,
                                  off_t *phys_out);
int sceKernelMapDirectMemory(void **addr, size_t len, int prot, int flags,
                             off_t phys, size_t alignment);

static uint64_t g_kdata, g_dev_pd;
static int g_fd = -1;
static int g_pass, g_fail, g_inconclusive;

static uint64_t rd64v(uint64_t va) {
  uint64_t v = 0;
  kernel_copyout((intptr_t)va, &v, 8);
  return v;
}

static int walk(uint64_t gva, uint64_t *leaf_va, uint64_t *leaf_val) {
  uint64_t e = rd64v(g_dev_pd);
  if (!(e & 1)) return -1;
  uint64_t t = dmap + (e & GPU_PTR_MASK);
  e = rd64v(t + ((gva >> 30) & 0x1FF) * 8);
  if (!(e & 1)) return -1;
  uint64_t pdt = dmap + (e & GPU_PTR_MASK);
  e = rd64v(pdt + ((gva >> 21) & 0x1FF) * 8);
  if (!(e & 1)) return -1;
  if ((e >> 54) & 1) { *leaf_va = pdt + ((gva >> 21) & 0x1FF) * 8; *leaf_val = e; return 2; }
  uint64_t ptb = dmap + (e & GPU_PTR_MASK);
  e = rd64v(ptb + ((gva >> 16) & 0x1F) * 8);
  if (!(e & 1) || !((e >> 56) & 1)) return -1;
  uint64_t sub = dmap + (e & GPU_PTR_MASK);
  *leaf_va = sub + ((gva >> 13) & 0x7) * 8;
  *leaf_val = e;
  return 8;
}

static int dma(uint64_t cmd_cpu_va, uint64_t src, uint64_t dst, uint32_t len) {
  uint32_t *p = (uint32_t *)cmd_cpu_va;
  uint32_t hdr = (1u << 31) | (2u << 25) | (1u << 27) | (2u << 13) | (1u << 15);
  p[0] = ((3u & 3) << 30) | ((5u & 0x3FFF) << 16) | ((0x50u & 0xFF) << 8) | ((1u & 1) << 1);
  p[1] = hdr;
  p[2] = (uint32_t)(src & 0xFFFFFFFF); p[3] = (uint32_t)(src >> 32);
  p[4] = (uint32_t)(dst & 0xFFFFFFFF); p[5] = (uint32_t)(dst >> 32);
  p[6] = len & 0x1FFFFF;
  uint64_t desc_va = cmd_cpu_va + 0x1000;
  uint64_t *d = (uint64_t *)desc_va;
  d[0] = ((cmd_cpu_va & 0xFFFFFFFFULL) << 32) | 0xC0023F00ULL;
  d[1] = ((7ULL & 0xFFFFFULL) << 32) | ((cmd_cpu_va >> 32) & 0xFFFFULL);
  struct { uint32_t pipe_id, count; uint64_t cmd_buf_ptr; } sub = {0, 1, desc_va};
  int rc = (g_fd >= 0) ? ioctl(g_fd, GC_SUBMIT_IOCTL, &sub) : -1;
  usleep(300000);
  return rc;
}

/* legge una pagina fisica attraverso una vittima fresca; ritorna 0 se ok */
static int gpu_read_page(uint64_t victim_va, uint64_t target2m, uint64_t in2m,
                         uint64_t cmd_va, uint8_t *out, int n) {
  uint64_t lv = 0, lval = 0;
  int gran = walk(victim_va, &lv, &lval);
  if (gran != 2 || !(lval & 1)) return -1;
  uint64_t nv = (lval & ~GPU_LEAF2M_MASK) | (target2m & GPU_LEAF2M_MASK) | (1ULL << 50);
  kwrite64(lv, nv);
  memset((void *)cmd_va, 0, 0x1000);
  int rc = dma(cmd_va, victim_va + in2m, cmd_va, 0x1000);
  memcpy(out, (void *)cmd_va, (size_t)n);
  kwrite64(lv, lval);   /* ripristina sempre */
  return rc;
}

int main(void) {
  uint64_t bufs[6][2];
  static const char *names[6] = {"cmd", "val", "r44", "rA0", "rB0", "rC0"};
  uint64_t text_pa = 0, pe = 0;
  int method_ok = 0;

  if (set_offsets() || init_global_vars()) { notify("textverify: init failed\n"); return 1; }
  kernel_set_ucred_authid(getpid(), 0x4800000000000007);
  g_kdata = KERNEL_ADDRESS_DATA_BASE;

  {
    uint64_t base = g_kdata + OFF_DATA_GVMSPACE + (uint64_t)DEV_VMID * GVMSPACE_STRIDE;
    uint64_t pd = 0;
    kread(base + OFF_GVM_PAGE_DIR_VA, &pd, 8);
    g_dev_pd = pd;
    if (!pd) { notify("textverify: dev vmid tree missing\n"); return 1; }
  }

  for (int i = 0; i < 6; i++) {
    off_t off = 0; void *va = NULL;
    if (sceKernelAllocateDirectMemory(0, 0x400000000ULL, DMEM_SIZE, DMEM_SIZE, 0xb, &off) != 0 ||
        sceKernelMapDirectMemory(&va, DMEM_SIZE, PROT_READ | PROT_WRITE | PROT_GPU_READ | PROT_GPU_WRITE,
                                 (int)MAP_NO_COALESCE, off, DMEM_SIZE) != 0) {
      notify("textverify: alloc/map %s failed\n", names[i]); return 1;
    }
    bufs[i][0] = (uint64_t)(uintptr_t)va; bufs[i][1] = (uint64_t)off;
    memset(va, 0, DMEM_SIZE);
  }
  g_fd = open("/dev/gc", O_RDWR);
  if (g_fd < 0) g_fd = open("/dev/gc0", O_RDWR);

  uint64_t cmd_va = bufs[0][0];
  notify("textverify: fw=%04x ktext=%#lx fd=%d\n", fw, (unsigned long)ktext, g_fd);

  {
    uint64_t kpm = kdlsym(KERNEL_SYM_PMAP_STORE);
    if (find_pte(kpm, ktext, &pe) != 0xFFFFFFFFFFFFFFFFull)
      text_pa = PDE_ADDR(pe) | (ktext & 0xFFF);
    notify("textverify: ktext pa=%#lx\n", (unsigned long)text_pa);
    if (!text_pa) return 1;
  }

  /* ---- gate: il metodo funziona in questa esecuzione? ---- */
  {
    uint64_t kpm = kdlsym(KERNEL_SYM_PMAP_STORE);
    uint64_t dtarget = KERNEL_ADDRESS_DATA_BASE + 0x1000, dpe = 0, cpu_w0 = 0;
    if (find_pte(kpm, dtarget, &dpe) != 0xFFFFFFFFFFFFFFFFull) {
      uint64_t dpa = PDE_ADDR(dpe) | (dtarget & 0xFFF);
      kernel_copyout((intptr_t)dtarget, &cpu_w0, 8);
      uint8_t g[16];
      if (gpu_read_page(bufs[1][0], dpa & ~0x1FFFFFULL, dpa & 0x1FFFFFULL, cmd_va, g, 16) == 0) {
        uint64_t gw0 = 0; memcpy(&gw0, g, 8);
        method_ok = (gw0 == cpu_w0);
        notify("textverify: GATE cpu=%#lx gpu=%#lx -> %s\n", (unsigned long)cpu_w0,
               (unsigned long)gw0, method_ok ? "METHOD-OK" : "METHOD-MISMATCH");
      } else notify("textverify: GATE: lettura non riuscita\n");
    }
  }
  if (!method_ok) {
    notify("textverify: IL METODO NON E' AFFIDABILE IN QUESTA ESECUZIONE: nessun verdetto sui valori\n");
    notify("textverify: ==== RESULT pass=%d fail=%d inconclusive=%d -> METODO NON VALIDO ====\n",
           g_pass, g_fail, g_inconclusive + 6);
    return 0;
  }

  /* ---- i sei valori: 4 regioni 2 MB, una vittima fresca ciascuna ---- */
  {
    struct tcheck { const char *name; uint64_t off; int region; } t[] = {
      {"KERNEL_CFI_CHECK",             0x44F8C0ULL, 2},
      {"FUN_MP3_INVOKE",               0xA12D30ULL, 3},
      {"FUN_MP3_INITIALIZE",           0xA14130ULL, 3},
      {"FUN_SMP_NO_RENDEVOUS_BARRIER", 0xB03960ULL, 4},
      {"FUN_SMP_RENDEZVOUS",           0xB03BA0ULL, 4},
      {"FUN_TRANSMITTER_CONTROL",      0xC0EAA0ULL, 5},
    };
    for (unsigned i = 0; i < sizeof t / sizeof t[0]; i++) {
      uint64_t tpa = text_pa + t[i].off;
      uint8_t g[16];
      char d[128];
      if (gpu_read_page(bufs[t[i].region][0], tpa & ~0x1FFFFFULL, tpa & 0x1FFFFFULL, cmd_va, g, 16) != 0) {
        notify("textverify: %-28s INCONCLUSIVO (lettura non riuscita)\n", t[i].name);
        g_inconclusive++; continue;
      }
      int prologue = (g[0] == 0x55 && g[1] == 0x48 && g[2] == 0x89);
      int thunk = (g[0] == 0xE9);
      snprintf(d, sizeof d, "%02x %02x %02x %02x %02x %02x", g[0], g[1], g[2], g[3], g[4], g[5]);
      if (prologue || thunk) {
        notify("textverify: %-28s PASS  prologo %s %s\n", t[i].name, d,
               prologue ? "(push rbp; mov rbp,rsp)" : "(thunk e9)");
        g_pass++;
      } else {
        notify("textverify: %-28s FAIL  bytes %s (prologo assente)\n", t[i].name, d);
        g_fail++;
      }
    }
  }

  notify("textverify: ==== RESULT pass=%d fail=%d inconclusive=%d ====\n",
         g_pass, g_fail, g_inconclusive);
  return g_fail ? 1 : 0;
}
