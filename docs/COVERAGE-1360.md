# Copertura su 13.60 — misurata, non stimata

Risponde a "a che livello siamo" con numeri ricavati dal registro
(`tools/offset_registry.json`, 57 voci) e dalle esecuzioni su console registrate nel diario.

## 1. Il registro

| classe | voci | quota |
| --- | --- | --- |
| `KNOWN_STATIC` (valore + provenienza + verificatore) | **53** | 93% |
| `NOT_REQUIRED_FOR_1360_PATH` (zero perché non letto sul percorso 13.60) | **4** | 7% |
| `DISPUTED` | 0 | — |

Per namespace: `KTEXT_REL` 36 · `KDATA_REL` 11 · `PHYSICAL` 4 · `STRUCT_OFF` 2 · `HV_REL` 2 · `NONE` 2.

I quattro zeri: `KERNEL_CODE_CAVE`, `HV_CODE_CAVE_PA`, `HV_HANDLE_VMEXIT_PA`, `KERNEL_UART_OVERRIDE`.
Non sono "mancanti": sono **fuori dal percorso** del vettore khook (`prepare_sck_args()`, cioè il percorso
legacy). Nessuno di essi serve alla fase A.

**Fuori dalla tabella** c'è però il valore che blocca la fase B: `HV_VMMCALL_HANDLER_PA` per 13.60 è
`UNKNOWN` (classe `UNKNOWN`, valore `null`, in `takeover_requirements`). Non è ricavabile dal guest: è un
indirizzo *fisico dentro l'hypervisor*. Per 13.20 è noto (`0x62847375`), per 13.60 no.

## 2. Profondità di verifica (dei 53 con valore)

| livello | quanti | come |
| --- | --- | --- |
| confrontati con la tabella in uso e con i valori attesi | **13** | T2, eseguito 3 volte (17 PASS) |
| controlli strutturali **vivi** (gate IDT, `IOMMU_SOFTC`, `GVMSPACE`, blob WiFi) | **4** | T2, letti dal kernel vivo |
| **solo statici** (due fonti indipendenti, mai letti live) | **6** | sono in `.text`, non leggibile: né via CPU né via GPU (misurato) |

Quindi: il registro è completo per il percorso **attuale**, ma la verifica *live* copre 17 controlli su 53
valori, e 6 valori non saranno verificabili finché esiste un modo di leggere `.text`.

## 3. Copertura per fase (ciò che è dimostrato **su hardware**)

| # | fase | stato | prova |
| --- | --- | --- | --- |
| 1 | escape (fase A): `.text` scrivibile, XOM off | ✅ **dimostrato** | T5, T5b: `[X] xotext=0 rw=1` |
| 2 | staging sopravvive a standby/resume | ✅ **dimostrato** | T5: `xotext=0 rw=1` dopo il risveglio, `verify-resume` esterno |
| 3 | installazione della catena sopravvive a standby/resume | ✅ **dimostrato** | T5b: idem, con catena installata |
| 4 | **armo** (scritture gate `#DB` + IST) | ❌ **mai dimostrato** | è la configurazione che ha ucciso i servizi; **blocco n.1** |
| 5 | redirect RSI + trigger (l'hook che scatta) | ❌ mai in una configurazione sopravvissuta | — |
| 6 | takeover post-resume (fase B) | ❌ **non compilabile** | `make PL5_1360_TAKEOVER=1` → 2 `#error` (`HV_VMMCALL_HANDLER_PA`, `FUN_VMMCALL_HC4` a 0): **blocco n.2** |
| 7 | boot Linux | ❌ mai raggiunto | dipende da 4+5+6 |

**Sintesi: 3 fasi su 7 dimostrate** (escape, staging, installazione). Le 4 che mancano per il boot non
mancano per un'unica causa, ma per due blocchi distinti: **una fase non provata** (l'armo) e **un valore non
ricavabile dal guest** (l'indirizzo HV del dispatcher).

## 4. Le due strade verso il boot, e perché sono entrambe chiuse

| strada | come funziona | blocco |
| --- | --- | --- |
| **1. khook + takeover** (quella su cui il progetto punta) | armo dell'hook prima del sonno → al resume `break_hv` disabilita NPT → patch del dispatcher VMEXIT + VMMCALL forzato → `shellcode_hv` avvia Linux | **1 valore HV** + la fase dell'armo da dimostrare |
| **2. legacy ACPI-ROP** (usata per fw < 0x800) | `prepare_resume()` fa lo staging di `shellcode_kernel` nel cave **prima** del sonno; il risveglio passa dalla ROP ACPI | non è cablata per 13.60 (`main.c` salta lo staging legacy per fw ≥ 0x800) e richiede i **4 valori oggi a zero** (`KERNEL_CODE_CAVE`, `HV_CODE_CAVE_PA`, `HV_HANDLE_VMEXIT_PA`, `KERNEL_UART_OVERRIDE`) — cioè 4 incognite al posto di 1 |

La strada 1 ha meno incognite: è per questo che è quella battuta.

## 5. Cosa farebbe un'installazione Linux

`fetch_linux()` oggi **aborta** (manca `bzImage`), quindi il payload esce prima dell'escape. Fornendo le
immagini il percorso ordinario proseguirebbe — ma il boot avviene **solo** in fase B, che è **non
compilabile**. Senza fase B il payload farebbe: installazione immagini (+ `dump_device_firmwares()`, una
scrittura su disco) → escape → standby → resume → `post_resume()` che **rifiuta** (`g_armed=0`, nessun armo
compilato) → console su, **nessun boot**.

Quindi: l'installazione Linux è un **input della fase B**, non una scorciatoia. Non attraversa nessuno dei
due blocchi e ne aggiunge una variabile (e una scrittura) all'accensione sotto test. L'unica cosa che
imparerebbe è se l'installazione delle immagini turba il ciclo — una variante di T5b, di valore marginale
rispetto al rischio.

## 6. Cosa servirebbe davvero, in ordine di rendimento

1. **il valore `HV_VMMCALL_HANDLER_PA` per 13.60** — da un dump HV reale (non ne abbiamo uno verificato: il
   wrapper guest `0xC16A10` è un'altra entità) oppure da una fonte esterna con verifica indipendente
   (metodo T23: affermazione esterna + verifica su una cattura). Sblocca la fase B e quindi il boot.
2. **capire se l'armo sopravvive al ciclo** — è la fase con il rischio più alto, ed è l'unica variabile del
   percorso rimasta non misurata. Da progettare con la stessa disciplina di T5/T5b.
3. Per la fase B serve anche che il blob condiviso accetti `PL5_TAKEOVER_FW=1360`: oggi rifiuta un firmware
   con valori ignoti (di proposito).

---

## 7. Confronto con l'altro payload (`1360linux.elf`)

Metodo: per ognuno dei 56 valori numerici del nostro registro, ricerca dell'encoding nel binario
(`sha256 e51a0298…`) e verifica se l'occorrenza cade nella finestra della voce 13.60 (offset
179000–180000).

| dimensione | esito |
| --- | --- |
| **offset kernel** | **parità**: 42/56 dei nostri valori sono nella voce 13.60 dell'altro payload; **nessuno** dei nostri cade altrove nel file |
| campi che noi tracciamo e loro **non** hanno nel record | 14 (simboli HV `HV_SYM_PCPUS`/`HV_SYM_HEAP_BASE`, `GAD_POP_RAX_RET`, `GAD_POP_RSP_RET`, e le funzioni del percorso legacy: `KERNEL_SYM_SYS_GETUID`, `HOOK_ACPI_WAKEUP_MACHDEP`, `FUN_PRINTF`, `FUN_SMP_NO_RENDEVOUS_BARRIER`, …) |
| **indirizzi fisici HV** | **loro li hanno, noi no**: `0x62806f00` (code cave) e `0x62847375` (handler HV) stanno dentro la stessa finestra |
| provenienza | noi: registro per-campo con `provenance` + `verified_by` + verifica live su console; loro: citano `HVBUG/findings/LINUX-OFFSETS-13.60-DERIVED.md` (non pubblico) e derivano `H` **a runtime dalla mappa EFI** |

**Verdetto: dietro sulla capacità, avanti sulla verificabilità.** Il divario è localizzato — i valori HV, cioè
la fase B — non diffuso. Gli offset kernel sono gli stessi (e i nostri 13.60 erano già stati risolti *da questo
stesso artefatto*).

Cautela sul metodo di questo confronto, da non dimenticare: la finestra di 1000 byte **contiene due voci
adiacenti** (la vicina sembra il 13.20) e sconfina in un blocco di **codice** (dai +600 in poi i valori sono
byte d'istruzione). Perciò il conteggio "valori loro che noi non abbiamo" **non** è stato riportato: non è
separabile senza prima fissare i confini dei record. Due falsi positivi già identificati: `0x7a248` è il
nostro `PS5_WIFI_FW_SIZE` (500296, nel registro in decimale) e i valori della voce adiacente non sono "loro".
