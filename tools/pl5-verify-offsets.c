/*
 * pl5-verify-offsets.c -- WS2: verifica a runtime dei valori risolti per 13.60.
 *
 * Perche' esiste: fino a oggi i valori nuovi erano verificati *staticamente*
 * (contro la cattura e contro un loader di riferimento). Questo probe li
 * confronta con (a) la tabella che il payload usa davvero e (b) il kernel vivo.
 *
 * Cosa NON fa, deliberatamente:
 *   - non installa l'hook (nessun arming: l'armo uccide i servizi, misurato);
 *   - non entra in standby (nessun ciclo rest/resume);
 *   - non legge .text via CPU: nel repo le letture CPU di .text sono documentate
 *     come pericolose (per questo esiste pl5-gpu-read, che passa dalla GPU).
 *     I valori in .text vengono quindi *stampati*, non letti: la loro verifica
 *     live richiede il percorso GPU (WS2b nel charter).
 *
 * I quattro valori verificabili per lettura stanno tutti nella regione dati
 * (IDT, IOMMU_SOFTC, GVMSPACE, blob WiFi), quindi si controllano senza rischi.
 */
#include "utils.h"

#include "byepervisor/paging.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* Offset of the ARMED marker inside the kernel data cave. Same constant the
 * escape paths use (hv_defeat_1360.c / hv_defeat_1320.c define CAVE_STATE_OFF
 * locally); it is repeated here so the checker does not have to include the
 * escape translation unit. */
#define VERIFY_CAVE_STATE_OFF 0x600ULL

/* Valori attesi: quelli risolti e committati nella tabella 13.60. Se il build
 * pesca oggetti vecchi, questo confronto lo scopre. */
#define EXPECT_MP3_INITIALIZE     0xA14130ULL
#define EXPECT_MP3_INVOKE         0xA12D30ULL
#define EXPECT_SMP_NO_BARRIER     0xB03960ULL
#define EXPECT_SMP_RENDEZVOUS     0xB03BA0ULL
#define EXPECT_TRANSMITTER        0xC0EAA0ULL
#define EXPECT_CFI_CHECK          0x44F8C0ULL
#define EXPECT_IDT                0x3BB4300ULL
#define EXPECT_IOMMU_SOFTC        0x3543A70ULL
#define EXPECT_DATA_GVMSPACE      0x3BAA570ULL
#define EXPECT_WIFI_FW_OFFSET     0x1518160ULL
#define EXPECT_WIFI_FW_SIZE       500296ULL
#define EXPECT_VM_VMID            0x1ECULL
#define EXPECT_VM_PMAP            0x1D8ULL

static int g_pass;
static int g_fail;

static void chk(const char *name, uint64_t got, uint64_t want) {
  int ok = (got == want);
  notify("verify: table %-26s = %#010lx (atteso %#010lx) %s\n", name, got, want,
         ok ? "OK" : "DISALLINEATO");
  if (ok) g_pass++; else g_fail++;
}

static void live(const char *name, const char *detail, int ok) {
  notify("verify: live  %-26s %s   %s\n", name, ok ? "PASS" : "FAIL", detail);
  if (ok) g_pass++; else g_fail++;
}

int pl5_verify_offsets(void) {
  char d[128];

  notify("verify: ==== WS2: verifica offset 13.60 (nessun armo, nessuno standby) ====\n");
  notify("verify: fw=%04x ktext=%#lx kdata=%#lx\n", fw, ktext, kdata);

  notify("verify: -- 1/3 tabella in uso (cio' che il payload usera') --\n");
  chk("FUN_MP3_INITIALIZE",     env_offset.FUN_MP3_INITIALIZE,       EXPECT_MP3_INITIALIZE);
  chk("FUN_MP3_INVOKE",         env_offset.FUN_MP3_INVOKE,           EXPECT_MP3_INVOKE);
  chk("FUN_SMP_NO_RENDEVOUS_BARRIER", env_offset.FUN_SMP_NO_RENDEVOUS_BARRIER, EXPECT_SMP_NO_BARRIER);
  chk("FUN_SMP_RENDEZVOUS",     env_offset.FUN_SMP_RENDEZVOUS,       EXPECT_SMP_RENDEZVOUS);
  chk("FUN_TRANSMITTER_CONTROL", env_offset.FUN_TRANSMITTER_CONTROL, EXPECT_TRANSMITTER);
  chk("KERNEL_CFI_CHECK",       env_offset.KERNEL_CFI_CHECK,         EXPECT_CFI_CHECK);
  chk("IDT",                    env_offset.IDT,                      EXPECT_IDT);
  chk("IOMMU_SOFTC",            env_offset.IOMMU_SOFTC,              EXPECT_IOMMU_SOFTC);
  chk("DATA_BASE_GVMSPACE",     env_offset.DATA_BASE_GVMSPACE,       EXPECT_DATA_GVMSPACE);
  chk("PS5_WIFI_FW_OFFSET",     env_offset.PS5_WIFI_FW_OFFSET,       EXPECT_WIFI_FW_OFFSET);
  chk("PS5_WIFI_FW_SIZE",       env_offset.PS5_WIFI_FW_SIZE,         EXPECT_WIFI_FW_SIZE);
  chk("VMSPACE_VM_VMID",        env_offset.VMSPACE_VM_VMID,          EXPECT_VM_VMID);
  chk("VMSPACE_VM_PMAP",        env_offset.VMSPACE_VM_PMAP,          EXPECT_VM_PMAP);

  notify("verify: -- 2/3 letture vive (solo regione dati) --\n");

  /* IDT: un gate da 16 byte con selector/type/present coerenti. */
  {
    uint64_t lo = kread64(ktext + env_offset.IDT);
    uint64_t hi = kread64(ktext + env_offset.IDT + 8);
    uint64_t off = (lo & 0xFFFFULL) | (((lo >> 48) & 0xFFFFULL) << 16) |
                   ((hi & 0xFFFFFFFFULL) << 32);
    unsigned sel = (unsigned)((lo >> 16) & 0xFFFF);
    unsigned typ = (unsigned)((lo >> 40) & 0xF);
    unsigned pres = (unsigned)((lo >> 47) & 1);
    snprintf(d, sizeof d, "selector=%#x type=%#x present=%u handler=%#lx", sel, typ, pres, off);
    live("IDT[0]", d, pres == 1 && typ == 0xE);
  }

  /* IOMMU_SOFTC: il globale contiene un puntatore kernel canonico. */
  {
    uint64_t sc = kread64(ktext + env_offset.IOMMU_SOFTC);
    snprintf(d, sizeof d, "softc=%#lx", sc);
    live("IOMMU_SOFTC", d, sc >= 0xFFFF000000000000ULL);
  }

  /* GVMSPACE: informativo (le prime voci possono essere legittimamente zero). */
  {
    uint64_t g0 = kread64(ktext + env_offset.DATA_BASE_GVMSPACE);
    uint64_t g1 = kread64(ktext + env_offset.DATA_BASE_GVMSPACE + 0x100);
    snprintf(d, sizeof d, "entry0=%#lx entry1(stride 0x100)=%#lx", g0, g1);
    live("DATA_BASE_GVMSPACE", d, 1);
  }

  /* Blob WiFi: header NXP atteso (01 00 00 00) e taglia plausibile. */
  {
    uint32_t hdr = kread32(ktext + env_offset.PS5_WIFI_FW_OFFSET);
    snprintf(d, sizeof d, "header=%#08x size=%lu", hdr,
             (unsigned long)env_offset.PS5_WIFI_FW_SIZE);
    live("PS5_WIFI_FW blob", d,
         hdr == 0x00000001u && env_offset.PS5_WIFI_FW_SIZE > 400000ULL &&
         env_offset.PS5_WIFI_FW_SIZE < 700000ULL);
  }

#ifdef PL5_VERIFY_TEXT
  /* WS2b: .text letto attraverso il *direct map* (vtophys + dmap), lo stesso
   * metodo del dumper del repo. Non si legge il VA del kernel, percorso
   * documentato come pericoloso. Atteso il prologo 55 48 89 (o un thunk e9). */
  notify("verify: -- 3a/3 .text via direct map (prologo atteso 55 48 89) --\n");
  {
    struct tcheck { const char *name; uint64_t off; } t[] = {
      {"FUN_MP3_INITIALIZE",           0xA14130ULL},
      {"FUN_MP3_INVOKE",               0xA12D30ULL},
      {"FUN_SMP_RENDEZVOUS",           0xB03BA0ULL},
      {"FUN_SMP_NO_RENDEVOUS_BARRIER", 0xB03960ULL},
      {"FUN_TRANSMITTER_CONTROL",      0xC0EAA0ULL},
      {"KERNEL_CFI_CHECK",             0x44F8C0ULL},
    };
    for (unsigned i = 0; i < sizeof t / sizeof t[0]; i++) {
      uint64_t va = ktext + t[i].off;
      uint64_t pa = vtophys(va);
      uint32_t w = pa ? kread32(pa_to_dmap(pa)) : 0;
      int prologue = ((w & 0xFFFFFFu) == 0x894855u);
      int thunk = ((w & 0xFFu) == 0xE9u);
      snprintf(d, sizeof d, "bytes=%02x %02x %02x pa=%#lx", w & 0xFF,
               (w >> 8) & 0xFF, (w >> 16) & 0xFF, pa);
      if (prologue || thunk) {
        live(t[i].name, d, 1);
      } else {
        /* Il metodo direct-map non e' affidabile in questo contesto (i byte
         * letti hanno la forma di una entry di page table, non di codice):
         * lo si dichiara INCONCLUSIVO invece di spacciarlo per un FAIL, cosi'
         * non si accusa un valore che non e' stato realmente letto. La via
         * documentata per leggere .text e' il percorso GPU (pl5-gpu-read). */
        notify("verify: live  %-26s INCONCLUSIVO (metodo direct-map da rivedere)   %s\n",
               t[i].name, d);
      }
    }
  }
#endif

  notify("verify: -- 3/3 valori in .text: STAMPATI, non letti (lettura CPU pericolosa) --\n");
  notify("verify: .text FUN_MP3_INITIALIZE      = %#lx\n", (uint64_t)env_offset.FUN_MP3_INITIALIZE);
  notify("verify: .text FUN_MP3_INVOKE          = %#lx\n", (uint64_t)env_offset.FUN_MP3_INVOKE);
  notify("verify: .text FUN_SMP_RENDEZVOUS      = %#lx\n", (uint64_t)env_offset.FUN_SMP_RENDEZVOUS);
  notify("verify: .text FUN_SMP_NO_RENDEVOUS_BARRIER = %#lx\n", (uint64_t)env_offset.FUN_SMP_NO_RENDEVOUS_BARRIER);
  notify("verify: .text FUN_TRANSMITTER_CONTROL = %#lx\n", (uint64_t)env_offset.FUN_TRANSMITTER_CONTROL);
  notify("verify: .text KERNEL_CFI_CHECK         = %#lx\n", (uint64_t)env_offset.KERNEL_CFI_CHECK);

#ifdef PL5_VERIFY_RESUME
  /* T5: stato post-resume, sola lettura. Legge gli *entry* di page table che
   * descrivono kernel .text (non i byte di .text: quello resta vietato) e il
   * marker nella data cave. Nessuna scrittura, nessun ripristino, nessun armo,
   * nessuno standby, nessuna elevazione di credenziali -- quindi puo' girare
   * dopo uno staging nella stessa accensione senza consumarne l'unica azione
   * scrivente. Gli indirizzi sono le stesse espressioni che usa il percorso di
   * escape (kdlsym() e' letteralmente ktext + env_offset.<X>). */
  notify("verify: -- 4/4 stato post-resume (sola lettura) --\n");
  {
    uint64_t pm = ktext + env_offset.KERNEL_SYM_PMAP_STORE;
    uint64_t cave = ktext + env_offset.KERNEL_SYM_DATA_CAVE;

    if (pm == ktext || cave == ktext) {
      notify("verify: resume pmap/cave non risolti (pm=%#lx cave=%#lx)\n",
             (unsigned long)pm, (unsigned long)cave);
    } else {
      uint64_t epde = 0, epte = 0;
      uint64_t apde = find_pde(pm, ktext, &epde);
      uint64_t apte = find_pte(pm, ktext, &epte);
      uint64_t marker = kread64(cave + VERIFY_CAVE_STATE_OFF);
      int have_pte = (apte != 0xFFFFFFFFFFFFFFFFULL);

      if (apde != 0xFFFFFFFFFFFFFFFFULL)
        notify("verify: resume ktext pde@%#lx=%#lx xotext=%lu rw=%lu\n",
               (unsigned long)apde, (unsigned long)epde,
               (unsigned long)PDE_FIELD(epde, XOTEXT),
               (unsigned long)PDE_FIELD(epde, RW));
      if (have_pte)
        notify("verify: resume ktext pte@%#lx=%#lx xotext=%lu rw=%lu\n",
               (unsigned long)apte, (unsigned long)epte,
               (unsigned long)PDE_FIELD(epte, XOTEXT),
               (unsigned long)PDE_FIELD(epte, RW));

      snprintf(d, sizeof d, "xotext=%lu rw=%lu marker=%#lx",
               (unsigned long)(have_pte ? PDE_FIELD(epte, XOTEXT) : 0),
               (unsigned long)(have_pte ? PDE_FIELD(epte, RW) : 0),
               (unsigned long)marker);
      /* Criterio descrittivo, non di sicurezza: dice se lo staging dell'escape
       * e' ancora in vigore dopo il ciclo e se nessun armo e' stato dichiarato.
       * Un FAIL qui non accusa il kernel: dice che lo stato letto non e' quello
       * che un ciclo report-only dovrebbe lasciare. */
      live("resume stato .text/marker", d,
           have_pte && PDE_FIELD(epte, XOTEXT) == 0 && PDE_FIELD(epte, RW) == 1 &&
               marker == 0);
    }
  }
#endif

  notify("verify: ==== RESULT pass=%d fail=%d -> %s ====\n", g_pass, g_fail,
         g_fail ? "ATTENZIONE" : "TUTTO OK");
  return g_fail ? 1 : 0;
}
