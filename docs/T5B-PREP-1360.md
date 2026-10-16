# T5b — installazione della catena senza armo: preparazione offline

Stato: **preparato e verificato offline. NON eseguito sulla console.**

Branch: `analysis/t5-resume-report-only`. La domanda sperimentale e i vincoli vengono dal piano
dell'analista (post-T5); i fatti sul motore vengono dal codice, non dai commenti.

---

## 1. Flusso di controllo, fase per fase

Distinzione esplicita richiesta: *staging* ≠ *installazione* ≠ *armo* ≠ *redirect* ≠ *standby* ≠
*resume* ≠ *takeover*. Per ogni fase: funzioni, condizioni, scritture.

| # | fase | funzioni | condizione che la governa | scritture nel kernel |
| --- | --- | --- | --- | --- |
| 1 | **staging** | `kernel_set_ucred_authid`, `escape_kernel_text`, `map_payload_executable` (kernel pmap **e** pmap del processo) | percorso di escape (`PL5_DIAG != 0`, `!= 5`) | ucred del processo; per ogni pagina di `.text`: `CLEAR XOTEXT` + `SET RW` su **PDE e PTE** e riscrittura dell'entry (~3264+3264 nel run misurato); `CLEAR EXECUTE_DISABLE` su PML4E/PDPE/PDE(/PTE) della pagina payload |
| 2 | **installazione della catena** | `install_resume_hook` → `kwrite(scratch+0x1000, break_hv)`, `kwrite64(oracle,0)`, `kh_init`, `kh_set_*`, `kh_chain_*`, `kh_install` | oggi: `#if PL5_1360_ARM_HOOK`; con T5b: `#if PL5_1360_INSTALL_NO_ARM` | copia di `break_hv` nella data cave; oracle azzerato; **catena grande** (sopprimibile `KH_SKIP_BIG`); **immagine della scratch** (sopprimibile `KH_SKIP_SCRATCH`); `probe_write` transitorio write+restore sulla regione della catena (`khook.c:398`) |
| 3 | **armo (gate + IST)** | dentro `kh_install`: `kwrite_q(ist, arm_chain)`, `kwrite_q(db_gate+8,…)`, `kwrite_q(db_gate,…)`. Da sola: **`kh_arm()`**, che scrive *esattamente e solo* queste due | sopprimibile con `KH_SKIP_IST` / `KH_SKIP_GATE`; il build di T5b le forza a zero | **TSS IST slot** → catena d'armo; **gate `#DB` (IDT vettore 1)** → pivot. Sono le due scritture che rendono l'hook vivo |
| 4 | **redirect RSI** | `kh_set_resume_rsi`, `kh_set_resume_rdx` + blocco memcpy/gadget della catena | `redirect = (PL5_DIAG >= 2)` | nessuna: modifica la catena in memoria |
| 5 | **trigger** | `kh_trigger` (o `db_trigger` con ARM_HOOK) | non chiamata per `PL5_DIAG == 16`/`18`; **T5b la salta** | 3 parole nella scratch (`KH_OFF_RESUME+KH_RC_RBP`, arm_rip_slot, arm_rsp_slot) + single-step via TF |
| 6 | **standby** | `sceSystemStateMgrEnterStandby()` (`fw >= 0x800`) | `PL5_DIAG` fuori da 10..17, oppure `PL5_1360_RESUME_REPORT_ONLY=1` | nessuna (è la richiesta di sospensione) |
| 7 | **resume + post-resume** | `hv_defeat_1360_post_resume()` → attesa cookie, `log_reopen`, settling; oppure `hv_defeat_1360_report_resume()` (sola lettura) | report-only → `report_resume`; takeover → solo `PL5_1360_TAKEOVER=1` | report-only: **nessuna**. Takeover: patch del dispatcher HV + VMMCALL (fase B, non compilata di default) |

Prima della fase 1, `main.c` chiama `fetch_linux()` — **saltata** nel percorso report-only, perché
richiede `bzImage`/`initrd.img` e chiama `dump_device_firmwares()` (una scrittura su disco) per un boot
che non avviene. Misurato: senza quel salto il payload moriva *prima* dell'escape.

### La separazione è dichiarata dal motore, non assunta da noi

`source/byepervisor/khook.c`:

* `kh_arm()` — *"Arm the hook on its own: write only the TSS IST slot and the #DB IDT gate."*
* `kh_install()` — *"…can run with KH_SKIP_IST|KH_SKIP_GATE so the hijack is not live until this
  call."*

Quindi **armo = due scritture, sopprimibili**; installazione = tutto il resto. È questa la base di T5b.

### Inventario: cosa può scrivere nel kernel, in totale

| scrittura | dove | sopprimibile |
| --- | --- | --- |
| ucred del processo | `hv_defeat_1360` | no (parte dello staging) |
| PDE/PTE di `.text` (~6.5k entry) | `escape_kernel_text` | no (è lo staging) |
| `EXECUTE_DISABLE` della pagina payload | `map_payload_executable` | no |
| `break_hv` nella cave | `install_resume_hook` | no |
| oracle = 0 | `install_resume_hook` | no |
| catena grande | `kh_install` | `KH_SKIP_BIG` |
| immagine della scratch | `kh_install` | `KH_SKIP_SCRATCH` |
| `probe_write` transitorio | `kh_install` (su `big`) | no |
| **TSS IST slot** | `kh_install` / `kh_arm` | **`KH_SKIP_IST`** |
| **gate `#DB`** | `kh_install` / `kh_arm` | **`KH_SKIP_GATE`** |
| DR7 dentro l'immagine della scratch | `kh_install` | `KH_SKIP_DR7` (vedi §5) |
| 3 parole + TF | `kh_trigger` | non chiamandola |

---

## 2. Modifiche proposte e realizzate

Nuovo flag **`PL5_1360_INSTALL_NO_ARM`** (default **0**):

* **guardie di compilazione** (fail-closed): richiede `PL5_1360_RESUME_REPORT_ONLY=1`; richiede
  `ARM_HOOK=0`, `ACK_EXPERIMENTAL_ARMING=0`, `TAKEOVER=0`, `STAGE_PRE_SLEEP=0`; richiede
  `PL5_DIAG < 10` (gli stadi P4 assegnano `kh_diag_skip_mask` da soli e sovrascriverebbero la
  maschera). Ogni violazione è un `#error`, non un commento;
* **maschera da letterali**: `kh_diag_skip_mask = KH_SKIP_IST | KH_SKIP_GATE;` sia al call site sia
  dentro l'installazione, così il valore non dipende da stato esterno;
* **trigger saltato** (`#if PL5_1360_INSTALL_NO_ARM` è il primo ramo del blocco trigger);
* **redirect spento**: `install_resume_hook(cave_addr, /*redirect=*/0)`;
* **post-resume report-only** (ereditato da `PL5_1360_RESUME_REPORT_ONLY`);
* **target dedicato** `make … t5b-install-no-arm` → `bin/pl5-t5b-install-no-arm.elf`, che rifiuta di
  costruire senza entrambi i flag;
* flag aggiunto al **configuration stamp** e all'**intestazione di run** (`install_no_arm=%d`).

File toccati: `Makefile`, `source/hv/defeat/hv_defeat_1360.c`, `source/core/utils.c`,
`tests/run_tests.py`. Nessuna modifica a `main.c` (il percorso report-only era già quello giusto) e
nessuna al motore khook: la separazione esisteva già nel motore, T5b la usa.

---

## 3. Test automatici aggiunti ed esiti

| test | cosa pretende | esito |
| --- | --- | --- |
| `t5b: install-no-arm flag is fail-closed and off by default` | guardie presenti + default 0 | PASS |
| `t5b: hijack writes suppressed by a literal mask` | la maschera è un letterale (≤4 occorrenze previste) | PASS (4) |
| `t5b: trigger skipped and redirect off` | ramo che salta il trigger + `redirect=0` | PASS |
| `t5b: arming calls stay behind their arming guard` | percorre lo **stack delle guardie** e pretende che ogni chiamata in grado di armare (`kh_arm`, `db_gate_install`, `db_trigger`) stia dietro la propria guardia | PASS (9 siti controllati) |

Più i test di T5 già presenti (fail-closed del flag, salto dell'installazione Linux).

Comandi eseguiti e relativi esiti:

| comando | esito |
| --- | --- |
| `python3 tools/check_offset_registry.py` | **0 failed / 0 warning** (57 voci) |
| `python3 tools/verify_off_1360.py --structure-only` | **PASS** |
| `python3 tests/run_tests.py` | **synthetic 44/46**; `real 0/2` e `package 0/4` **SKIP** per progetto |
| `git diff --check` | pulito |

Un `SKIP` non è un PASS: la lane `real` richiede `PL5_TEST_REAL_DUMP=1` e la cattura (non vendored),
la lane `package` un payload costruito (`PL5_TEST_ELF=1`) e l'SDK — che su questo host **non** è
installato (la build gira in container).

### Guardie provate costruendo (non solo lette)

| prova | esito atteso | osservato |
| --- | --- | --- |
| `INSTALL_NO_ARM=1` senza report-only | fallisce | `#error` (riga 259) |
| + `ARM_HOOK=1` + `ACK=1` | fallisce | `#error` (guardia del report-only, riga 167) |
| + `TAKEOVER=1` | fallisce | `#error` (riga 167) |
| + `STAGE_PRE_SLEEP=1` | fallisce | `#error` (riga 167) |
| `PL5_DIAG=16` | fallisce | `#error` (riga 262) |
| target senza i due flag | fallisce | rifiuto con il comando corretto (exit 2) |
| build ordinaria di default | riesce | `make -j4` OK |
| T5 (`REPORT_ONLY`) + `INSTALL_NO_ARM` insieme | coerente | compila; il ramo `INSTALL_NO_ARM` ha la precedenza |

---

## 4. Artefatti, commit e hash

| artefatto | configurazione | SHA-256 |
| --- | --- | --- |
| `pl5-t5b-install-no-arm-74290bb.elf` | `PL5_DIAG=4 RESUME_REPORT_ONLY=1 INSTALL_NO_ARM=1` (arm/ack/takeover/stage=0) | `3f0fd6852950fd4c5fa5d6969054d87bdd0d248ce89a0c31bc33c50b84a57469` |
| `pl5-t5-report-only-13cd264.elf` | T5 (eseguito) | `4f13743feb2866f3149358e8a02a8edc10dd3cb7e0cbc54e8aead89502d8e528` |
| `pl5-default-74290bb.elf` | build ordinaria, per confronto di regressione | `bccc75d13b78d0c9d43889d714adfb6c6091a3d118807875f3a12a4d1c68016f` |

Conservati in `~/src/ps5-dumps/pl5-artifacts/` con `CONFIG-*.txt` e `SHA256SUMS-*.txt`.
Commit su `analysis/t5-resume-report-only`: `74290bb` (codice+test), più il commit di questo documento.

**Riproducibilità**: due build dello stesso target differiscono per i 16 byte contigui della nota
`NT_GNU_BUILD_ID`; azzerandola, gli SHA coincidono (misurato su `verify-offsets`). L'hash identifica
l'artefatto, non la configurazione in astratto — per questo è registrato con il suo comando.

---

## 5. Rischi e limiti dell'esperimento

**Che cosa T5b isola**: le *scritture dell'installazione* (break_hv nella cave, oracle, catena grande,
immagine della scratch, `probe_write`) con l'hook **mai vivo**.

**Rischi residui, dichiarati:**

1. le scritture vanno nella **data cave** del kernel (`KERNEL_SYM_DATA_CAVE`): se quella regione
   intersecasse qualcosa che il percorso di resume usa, le scritture potrebbero contare — ed è
   esattamente l'ipotesi sotto test, non un effetto collaterale;
2. `probe_write` scrive **e ripristina** una parola: un fault lì sarebbe immediato, non al resume;
3. l'immagine della scratch contiene `DR7 = KH_DR7_BP0_EXEC` (il flag non aggiunge `KH_SKIP_DR7`,
   deliberatamente: si vuole l'immagine *reale*). È **inerte** perché solo la catena la legge, e la
   catena non può partire senza gate/IST. Va però detto: è un valore di debug-arming presente in
   memoria;
4. la **maschera è un letterale in questo build**, ma `kh_diag_skip_mask` resta un globale mutabile.
   Nel build T5b le altre assegnazioni stanno dentro `PL5_DIAG >= 10`, escluso dalla guardia; questo è
   verificato staticamente, non garantito dal linguaggio;
5. il ciclo standby/resume **non è annullabile**: se qualcosa va storto, si recupera con spegnimento
   completo, non con un comando.

**Limiti — cosa T5b NON copre**: il trampolino (`db_stage`/`db_gate_install`, compilati solo con
`ARM_HOOK=1`); il redirect RSI; il trigger e quindi l'esecuzione della catena; il takeover
post-resume. Un esito positivo di T5b **non** autorizza a concludere nulla su queste fasi.

**Come leggere gli esiti:**
* console sana + `verify-resume` con `xotext=0 rw=1 marker=0` → le scritture dell'installazione non
  rompono il ciclo; il sospetto si sposta su **armo/redirect/trigger/takeover**;
* console sana **ma** stato diverso dal previsto → registrare *quale* differenza, senza reinterpretare;
* blocco della console → l'installazione (o le sue scritture) è una causa sufficiente; il log sul
  media è l'unica traccia, e **l'assenza di righe nel log non è prova di danno al kernel**.

---

## 6. Protocollo hardware proposto — NON eseguito

Da sottoporre all'operatore per decisione esplicita. Vale la regola del charter: **una sola azione che
scrive per accensione**.

**Pre-flight**: jailbreak attivo (helper 200, elfldr 200); `tools/pl5-save-logs.sh <IP>` **prima** di
tutto (il log è a slot singolo: un avvio successivo cancella il precedente); `make verify-offsets` →
atteso `pass=17 fail=0`.

**Build**: `make PL5_DIAG=4 PL5_1360_RESUME_REPORT_ONLY=1 PL5_1360_INSTALL_NO_ARM=1
PL5_BUILD_COMMIT=<sha> t5b-install-no-arm`, poi registrare SHA-256 e configurazione.

**Esecuzione**: caricare l'artefatto in `/data/`, lanciarlo **da solo**; la console entra in standby
dopo ~5 s → risvegliarla a mano; tornata: salvare subito il log, poi `make verify-resume` e
`make verify-offsets` (entrambi di sola lettura, quindi ripetibili nella stessa accensione). Nessun
altro payload scrivente.

**Criteri di successo**: `[R0]` con `install_no_arm=1` nel log; righe `[T5b]` di installazione
presenti, nessun `kh_trigger`; `verify-resume` → `xotext=0 rw=1 marker=0` (`pass=18 fail=0`);
`verify-offsets` → `pass=17 fail=0`; console raggiungibile e stabile ≥ 5 min.

**Criteri di arresto**: console che perde i servizi, non risponde, o risultati diversi dall'atteso in
`verify-resume` → stop, nessun altro payload, nessun disarmo automatico, raccolta del log, spegnimento
completo, ritorno a T2 dopo il recupero. Nessuna ripetizione per "ottenere un risultato migliore".
