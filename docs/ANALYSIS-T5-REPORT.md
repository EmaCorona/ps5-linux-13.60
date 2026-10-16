# Analisi T5 — staging, standby e resume (13.60)

Branch di analisi: **`analysis/t5-resume-report-only`** (worktree separato, nessun effetto sui branch
esistenti). Questo documento è il resoconto del lavoro *offline*: branch e revisioni, registro delle prove,
spiegazione tecnica del percorso `PL5_DIAG`/standby/post-resume, modifiche isolate, esiti dei controlli
automatici, specifica di T5 e ciò che resta non dimostrato.

La console **non è stata toccata** in nessuna fase di questo lavoro.

---

## 1. Branch e revisioni

| branch | HEAD | ruolo |
| --- | --- | --- |
| `feature/13.60-support` | `3e35bd0b73ecdfefb69279055cd953cbc4472c6f` | **baseline congelata** (verificata intatta prima e dopo) |
| `testing` | `0274e5e0a9e8bd54eb0ec226e1b03ad058b298ee` | charter + diario T2/T3 |
| `feature/safe-reliable-process` | `06287e0a65f7f99974cfbcfef0904f3995d61df6` | i due documenti per l'analista |
| **`analysis/t5-resume-report-only`** | (questo branch) | lavoro di questa analisi |

Costruzione: worktree separato `~/src/ps5-linux-13.60-t5` creato da **`testing` @ `0274e5e`**, poi
cherry-pick dei due commit documentali:

- `11e98c2` → `0a30d78` (`docs/ANALYST-BRIEFING-1360.md`)
- `06287e0` → `dc613c0` (`docs/ANALYST-NEXT-STEPS-1360.md`)

Nessun reset, nessun force-push, nessuna riscrittura di storia. Il diario di `testing` non è stato
sovrascritto: il cherry-pick aggiunge due file nuovi e non tocca quelli già presenti.

---

## 2. Registro delle prove (fatti / ripetuti / deduzioni / ipotesi)

### 2.1 Fatti osservati sull'hardware

| # | fatto | prova | ripetizioni |
| --- | --- | --- | --- |
| F1 | `verify-offsets` passa su 13.60 | `pass=17 fail=0`; 13/13 valori della tabella; `IDT[0]` gate valido (`selector=0x20 type=0xe present=1`); `IOMMU_SOFTC` puntatore kernel canonico; blob WiFi `header=0x00000001 size=500296` | **2** (due accensioni, `ktext` diverso) |
| F2 | i valori non dipendono da un singolo layout di boot | run 1 e run 2 con `ktext` diverso (`0xffffffffc30b0000` nel run registrato per ultimo; il run precedente è annotato nel diario del charter con un valore diverso) | 2 |
| F3 | il disarmo, da solo, è innocuo | `restore: pde=3264 pte=3264 \| ktext XOTEXT pte 1->1 \| marker 0 -> 0`, read-back `xotext=1 rw=0`; console sana (helper 200, elfldr 200, ping 3,9 ms) | 1 |
| F4 | su accensione fresca `.text` era **già** ripristinato (`XOTEXT 1->1`): il disarmo ha riscritto gli stessi valori | stesso run di F3 | 1 |
| F5 | `.text` non è leggibile via GPU (WS2b) | il gate del metodo passa su `.data`, ma i **sei** indirizzi in `.text` tornano **tutti `0xff`** | 1 |
| F6 | tre blocchi della console, stessa firma (accesa, schermo attivo, rete persa) | registrati nel diario del charter; ogni volta recuperati con spegnimento completo | 3 eventi |
| F7 | nessuna scrittura persistente: i blocchi non hanno brickato nulla | la console è tornata con helper+elfldr reiniettati; i payload girano in RAM | 3 |

### 2.2 Risultati registrati una volta sola

- **T4** — staging senza armo (`PL5_DIAG=16`, `ARM_HOOK=0`): **riuscito, senza standby**. Un solo run.
- **F3/F4** — il disarmo isolato: un solo run.
- **F5** — WS2b: un solo run, e in quella stessa accensione è avvenuto anche l'incidente #3.

### 2.3 Deduzioni statiche dal sorgente (non misure)

| # | deduzione | dove |
| --- | --- | --- |
| D1 | con `PL5_1360_ARM_HOOK=0` l'hook **non viene installato**: `install_resume_hook()` è dentro `#if PL5_1360_ARM_HOOK`, e nessun marker viene scritto | `source/hv/defeat/hv_defeat_1360.c` |
| D2 | con `PL5_DIAG` da 10 a 17 `main.c` **salta lo standby** (heartbeat di 20 s) — quindi `PL5_DIAG=16` non può servire a un test di resume | `source/main.c` |
| D3 | dopo il risveglio `main.c` chiama **sempre** `hv_defeat_1360_post_resume()`, cioè il percorso che (con `PL5_1360_TAKEOVER=1`) prosegue nel takeover | `source/main.c` |
| D4 | `PL5_DIAG=0` scriveva `STATE_ARMED` nella cave **mantenendo `g_armed=0`**, mentre `post_resume()` rifiutava il percorso quando `g_armed` è falso: il percorso si dichiarava armato e poi rifiutava se stesso | `hv_defeat_1360.c` (corretto, §4.2) |
| D5 | `PL5_1360_ACK_EXPERIMENTAL_ARMING` era in `CFLAGS` ma **non** nel configuration stamp: cambiarlo poteva riusare oggetti vecchi e non rivalutare la guardia `#error` | `Makefile` (corretto, §4.1) |
| D6 | la build ordinaria (default) non arma, non installa e non scrive il marker: è già "staging only" | `hv_defeat_1360.c`, ramo `#else` di `#if PL5_1360_ARM_HOOK` |

### 2.4 Ipotesi aperte

| # | ipotesi | stato |
| --- | --- | --- |
| H1 | al resume uccide lo **staging** o il **takeover/lavoro post-resume**? | **non deciso** — è esattamente ciò che T5 deve separare |
| H2 | l'incidente #3 è dovuto al **percorso GPU** (DMA + ritargettatura di foglie) | rafforzata: il disarmo è esonerato (F3/F4). Il percorso GPU non serve più (F5 negativo) → non va riprovato |
| H3 | `FUN_MP3_INITIALIZE` è `0xA14130` (nostro) o `0xA13740` (alternativo) | rinviata: nessun discriminatore read-only (F5; e il flag "mp3 pronto" è già 1 a console avviata) |
| H4 | i sei valori in `.text` sono corretti | non verificabili in modo diretto: `.text` non è leggibile (F5) |

### 2.5 Riconciliazione dei punti richiesti

- **T2 due volte, `pass=17 fail=0`, layout diversi** → §2.1 F1/F2. Ripetuto e riproducibile.
- **T3 riuscito, nessuna perdita di servizi in quella prova** → §2.1 F3.
- **disarmo dopo staging riuscito in precedenza; poi incidente in una sequenza GPU+disarmo con causa non
  isolata** → i due eventi restano **distinti** e non cancellati: il primo è nel diario come riuscito, il
  terzo blocco resta registrato come *causa non isolata*. T3 esonera il disarmo **come azione isolata**; non
  afferma che ogni sequenza di ripristino sia sicura.
- **T4 riuscito senza standby; il blocco dopo staging+risveglio è un evento distinto** → §2.2 e §2.4. Il
  blocco #2 (staging + risveglio) non è attribuito a T4.
- **WS2b negativo** → §2.1 F5.
- **boot Linux end-to-end non dimostrato** → §7.
- **fase B disabilitata di default, indirizzi HV irrisolti** → `PL5_1360_TAKEOVER ?= 0`; il registro tiene
  `HV_VMMCALL_HANDLER_PA` / `HV_CODE_CAVE_PA` / `HV_HANDLE_VMEXIT_PA` / `KERNEL_UART_OVERRIDE` come
  `NOT_REQUIRED_FOR_1360_PATH` (0), e il checker verifica che la fase B resti spenta finché
  `HV_VMMCALL_HANDLER_PA` è sconosciuto.

> Un risultato riuscito **non** dimostra la sicurezza di tutte le sequenze che lo contengono: T3 dice che il
> disarmo isolato è innocuo, non che una qualunque sequenza che finisce con un disarmo lo sia.

---

## 3. Il percorso `PL5_DIAG`, standby e post-resume

### 3.1 Cosa seleziona `PL5_DIAG` (dal sorgente)

| valore | effetto |
| --- | --- |
| `0` | **round-trip S3 puro**: nessun escape, nessuno staging, nessun hook. Nessun marker scritto |
| `1` | escape + installa l'hook di resume, **senza** redirigere RSI |
| `2` | come `1` + redirect RSI verso `break_hv` (fase A completa) |
| `3` | fase A + takeover post-resume (fase B, se compilata) |
| `5` | **escape soltanto**: nessun khook, niente armato attraverso il sonno |
| `10` | installazione con **tutte** le scritture |
| `11` | installazione **senza** la scrittura del gate `#DB` (`KH_SKIP_GATE`) |
| `12` | senza IST **e** senza gate |
| `13` | controllo: escape soltanto, `kh_install` **saltato** |
| `14` | solo il gate `#DB` (salta big/scratch/IST) |
| `15` | installazione completa ma **`DR7=0`** → l'hook non può scattare |
| `16` | installazione completa, **trigger saltato** (gate+IST scambiati, mai esercitati) |
| `17` | installazione completa e **ripristino immediato** dopo il trigger |
| `18` | **arm-late**: staging ora, armo solo subito prima dello standby |

Con `PL5_DIAG` da 10 a 17 `main.c` **non entra in standby**: stampa un heartbeat di 20 s ed esce. Questo è
il motivo per cui `PL5_DIAG=16` non può essere usato per un test di resume (§2.3 D2).

### 3.2 Il ciclo standby

Su firmware alto (`fw >= 0x0800`) lo standby è quello **reale**: `sceSystemStateMgrEnterStandby()`, non il
vecchio percorso a event-flag (`enter_rest_mode()`), perché serve l'invalidazione del TLB attraverso il
ciclo suspend/resume. Prima di entrare, `main.c` arma l'hook **solo** se `PL5_DIAG == 18` (e solo per
13.60), cioè nel caso arm-late.

### 3.3 Cosa succede al risveglio

`hv_defeat_1360_post_resume()`: attende il cookie di `break_hv` (solo se RSI è stato rediretto; il cookie è
la prova che la console è davvero tornata e che NPT è off), poi `log_reopen()`, poi cinque cicli di
`sleep(2)` + `log_reopen()` ("settling": rete e filesystem tornano un attimo dopo la CPU), infine — a
seconda di `PL5_DIAG` e `PL5_1360_TAKEOVER` — o si ferma dopo la fase A, o prosegue nel takeover.

Due cose che questo percorso **non** decide da solo:

1. **chi continua**: la scelta è esplicita e fail-closed (`pl5_continuation_choose`). Ma `post_resume()` la
   invoca con `userland_shown_alive = 0` fisso, quindi l'unico esito possibile è "catena in kernel" oppure
   "niente da continuare" — mai "userland". Va bene (è conservativo) ma va saputo.
2. **se il processo è vivo**: che questa funzione stia girando è la prova; che *non* giri non prova nulla
   sul kernel (`docs/1360-khook-death.md` ha misurato che userland, elfldr e helper possono non tornare).

---

## 4. Modifiche isolate su questo branch

Sei file di codice + test. Ogni modifica ha una motivazione, un controllo e — dove serve — un modo di
tornare indietro (sono tutte reversibili con `git revert` del commit relativo; nessuna tocca dati).

### 4.1 `Makefile` — il configuration stamp era incompleto

- **Motivo**: `PL5_1360_ACK_EXPERIMENTAL_ARMING` raggiungeva il compilatore (`CFLAGS`) ma **non** era nel
  `PL5_CONFIG_VALUE`. Uno switch di quel flag poteva riusare oggetti vecchi e quindi **non** rivalutare la
  guardia `#error` che impedisce un build armato senza acknowledgement.
- **Modifica**: aggiunto `PL5_1360_ACK_EXPERIMENTAL_ARMING` (e le due variabili nuove) al stamp; nuovi
  `PL5_1360_RESUME_REPORT_ONLY ?= 0` e `PL5_BUILD_COMMIT ?= unknown`; target `verify-resume`.
- **Controllo**: `tests/run_tests.py` ora estrae **tutti** i `-D` di `CFLAGS` dal Makefile e verifica che
  ognuno sia presente nel stamp (10 flag coperti). Il test esistente che prova il meccanismo del stamp (con
  la sub-make `shellcode/hv`) resta.
- **Nota di verità**: il test dice che *nessun flag può essere dimenticato*; il fatto che un flag cambi e
  ricompili è già dimostrato dal test esistente sul stamp.

### 4.2 `hv_defeat_1360.c` — il percorso di riferimento `PL5_DIAG=0`

- **Motivo** (§2.3 D4): il commento diceva "no escape, no hook" ma il codice scriveva `STATE_ARMED` con
  `g_armed=0`, e `post_resume()` rifiutava quel percorso.
- **Modifica**: `PL5_DIAG=0` **non scrive più** il marker (un marker è un'affermazione che un hook è
  installato: scriverlo lì era falso e poteva essere adottato da un run successivo), e `post_resume()` ha un
  ramo esplicito per `diag=0` che riporta il round-trip e termina. I quattro stati sono ora distinti e
  nominati nel codice: round-trip S3 / staging senza armo / hook armato / takeover post-resume.
- **Controllo**: lettura del diff + il fatto che la build ordinaria non cambi (§4.4).

### 4.3 `hv_defeat_1360.c` + `hv_defeat_1360.h` + `main.c` — il flag di T5

Nuovo `PL5_1360_RESUME_REPORT_ONLY` (default **0**), con:

- **guardia di compilazione fail-closed**: `#error` se è 1 insieme a `ARM_HOOK`, `ACK_EXPERIMENTAL_ARMING`,
  `TAKEOVER` o `STAGE_PRE_SLEEP`;
- **guardia di runtime**: in `main.c`, subito dopo `setup_env()`, rifiuta se `fw != 0x1360` **prima** di
  qualunque scrittura;
- **esenzione dal salto dello standby**: `PL5_DIAG` da 10 a 17 non esce più se il flag è attivo;
- **niente takeover**: dopo il risveglio chiama `hv_defeat_1360_report_resume()` e **non**
  `post_resume()` / `arm()`;
- `hv_defeat_1360_report_resume()`: **zero scritture** (nessuna elevazione di credenziali, nessuna page
  table, nessuna cave). Legge soltanto gli *entry* di page table che descrivono `.text` e il marker.

### 4.4 `utils.c` — intestazione di run nel log

- **Motivo** (Fase 3.3): un log deve permettere di risalire ad artefatto e configurazione.
- **Modifica**: una riga all'avvio con `version`, `commit` (`PL5_BUILD_COMMIT`), `fw` e **tutti** i flag
  semantici (`diag`, `stage`, `probe`, `hv_stop`, `takeover_fw`, `arm`, `ack`, `takeover`,
  `stage_pre_sleep`, `report_only`). Più i `#ifndef` di riserva, perché questo file resti compilabile da solo.
- **Limite dichiarato**: l'intestazione non può hasherare il binario in cui è compilata; l'SHA-256 lo
  registra chi costruisce l'artefatto (§5).

### 4.5 `tools/pl5-verify-offsets.c` — controllo di stato post-resume, sola lettura

- **Motivo** (Fase 5): serve un controllo eseguibile **separatamente**, dopo che la console torna
  raggiungibile, che non legga `.text` e non scriva nulla.
- **Modifica**: sezione gated da `-DPL5_VERIFY_RESUME=1` (target `make verify-resume`): legge gli *entry*
  PDE/PTE di `.text` (`XOTEXT`/`RW`), il marker nella data cave e — come già faceva — il gate `IDT[0]`.
  Nessuna scrittura, nessun ripristino, nessun armo, nessuno standby, nessuna elevazione.
- **Nota**: gli indirizzi usano `ktext + env_offset.<X>`, che è **letteralmente** ciò che restituisce
  `kdlsym()` (`ktext_addr(env_offset.X)`), quindi il controllo legge le stesse strutture che usa l'escape.

### 4.6 `tests/run_tests.py` — due controlli nuovi

1. *make: every CFLAGS -D flag is in the config stamp* — enumerazione dal Makefile, non da una lista scritta
   a mano (non può andare fuori sincrono).
2. *t5: report-only flag is fail-closed and off by default* — presenza della guardia `#error`, dei quattro
   flag nella condizione, e del default a 0.

---

## 5. Controlli automatici e verifica statica

Eseguiti su questo branch, con l'esito:

| controllo | esito |
| --- | --- |
| `python3 tools/check_offset_registry.py` | **0 failed / 0 warning**, 57 voci |
| `python3 tools/verify_off_1360.py --structure-only` | **PASS** (`64` campi, `57` valori, 13.60 e 13.20 sullo stesso insieme) |
| `python3 tests/run_tests.py` | **synthetic 39/41**; `real 0/2` e `package 0/4` **SKIP** (per progetto: cattura non vendored; payload non costruito senza `PL5_TEST_ELF=1`) |
| `git diff --check` | pulito |
| `make -n` (SDK stub) per l'intestazione dei flag | `-DPL5_BUILD_COMMIT='"unknown"'` → il compilatore la vede come `"unknown"` |

**Lane realmente eseguite vs non eseguite** (richiesto esplicitamente): *synthetic* eseguita e verde;
*real* non eseguita (serve `PL5_TEST_REAL_DUMP=1` e la cattura, non vendored); *package* non eseguita
(serve un payload costruito). Un `SKIP` **non** è un PASS.

**Perché non basta la CI**: `.github/workflows/verify.yml` gira su `master` e `feature/13.60-support` e su
`workflow_dispatch` — **non** su questo branch sperimentale. Le stesse tre verifiche sono state quindi
eseguite qui a mano (ed è ciò che la tabella sopra riporta).

### 5.1 La build (Fase 6)

Toolchain **documentata e pinnata** (`docs/TOOLCHAIN.md`): container `silkeh/clang:21-trixie`, SDK
ps5-payload **v0.44** e pLabs5-SDK al commit `eeae9d04…`, entrambi con verifica di checksum nella build.
Nessun SDK è installato sull'host: la build gira in **podman**. Albero pulito, commit del worktree
`3258296`, `PL5_BUILD_COMMIT=3258296`.

| artefatto | configurazione | SHA-256 | byte |
| --- | --- | --- | --- |
| `pl5-t5-report-only-3258296.elf` | `PL5_DIAG=4 PL5_1360_RESUME_REPORT_ONLY=1`, arm/ack/takeover/stage=0 | `70ad3081c5b8c49e67daed98fdf37da8984f35e7b29e6c903dfeac1cea935f29` | 241016 |
| `pl5-verify-resume-3258296.elf` | `-DPL5_VERIFY_MODE -DPL5_VERIFY_RESUME=1` | `2ae25e329c68412bb0bc808babe7f03930a17877644701ec7ecd4ef6c8037e1c` | 241184 |

Conservati **fuori dal repo** in `~/src/ps5-dumps/pl5-artifacts/` con `SHA256SUMS-t5-3258296.txt` e
`CONFIG-t5-3258296.txt` (comando + flag). Gli `.elf` non sono versionati nel repository, quindi un file
locale non prova da solo la sua provenienza: l'hash qui sopra è quello dell'artefatto **costruito a partire
da questo commit**.

**Sulla riproducibilità** — misurata, non assunta: due build dello *stesso* target dallo *stesso* albero
non sono identiche byte per byte. Differiscono in **16 byte contigui** che sono la nota
`NT_GNU_BUILD_ID` (verificato: `namesz=4 descsz=16 type=3 name='GNU'` a offset 154928); azzerando quei 16
byte nei due file, gli SHA-256 coincidono (`39927f9e…`), cioè il **contenuto del payload è riproducibile**
e varia solo la build-id. Conseguenza pratica: l'hash di un `.elf` identifica *quell'artefatto*, non la
configurazione in astratto — per questo gli hash sono registrati insieme al comando che li ha prodotti.

### 5.2 Le guardie, provate (non solo lette)

Costruite nel container, ognuna una prova reale:

| prova | esito atteso | esito osservato |
| --- | --- | --- |
| `RESUME_REPORT_ONLY=1` + `ARM_HOOK=1` + `ACK=1` | fallisce | `#error` (riga 167) — il report-only non accetta l'armo |
| `RESUME_REPORT_ONLY=1` + `TAKEOVER=1` | fallisce | `#error` — non accetta il takeover |
| `RESUME_REPORT_ONLY=1` + `STAGE_PRE_SLEEP=1` | fallisce | `#error` — non accetta lo staging pre-sonno |
| `make t5-report-only` senza il flag | fallisce | il target rifiuta (`exit 2`) con il comando corretto da usare |
| `ARM_HOOK=1` senza `ACK` (guardia **esistente**) | fallisce | `#error` (riga 132) |
| build ordinaria di default | riesce | `make -j4` ok; `make version` → `0.1.0` |
| warning introdotti dalle modifiche | nessuno | nessun warning su `main.c`, `utils.c`, `hv_defeat_1360.c`, `pl5-verify-offsets.c` attribuibile alle modifiche; quelli presenti (`install_resume_hook`/`khook_selftest` non usati con `ARM_HOOK=0`, `kh_diag_skip_mask` auto-assegnato) esistono **anche** nella build di default |

Una nota di metodo su quest'ultima riga: i conteggi totali di warning variano fra un run e l'altro perché
includono la ricostruzione dei blob shellcode in gcc. La riga sopra è ristretta ai file modificati.

---

## 6. Specifica di T5

Specifica operativa completa (pre-flight, comandi, criteri misurabili, arresto, recupero):
**`docs/T5-PROTOCOL-1360.md`**. In sintesi, il test misura **una** cosa:

> lo **staging dell'escape** (page table di `.text` rese scrivibili + NX chiaro sulla pagina payload)
> sopravvive a un ciclo reale di standby/resume, **senza** armo dell'hook e **senza** takeover?

Lettura del risultato, per non confondere tre cose diverse:

| osservazione | cosa prova | cosa **non** prova |
| --- | --- | --- |
| la riga `[R0]…[R4]` compare nel log | il processo è sopravvissuto al sonno e il log funziona ancora | che il kernel sia sano |
| `make verify-resume` gira e legge `xotext=0 rw=1`, `marker=0` | lo staging è **ancora in vigore** dopo il ciclo | che l'escape sia sicuro |
| la console non risponde e nessuna riga compare | niente: l'assenza non è una prova (§3.3) | che lo staging abbia corrotto il kernel |

### 6.1 Esito dell'esecuzione su console (2026-10-16, eseguita)

**T5 è stato eseguito e ha dato esito positivo.** Artefatto `pl5-t5-report-only-13cd264.elf`
(`sha256 4f13743feb2866f3149358e8a02a8edc10dd3cb7e0cbc54e8aead89502d8e528`, 241016 B), build
`PL5_DIAG=4 PL5_1360_RESUME_REPORT_ONLY=1 PL5_BUILD_COMMIT=13cd264`.

| passo | esito |
| --- | --- |
| sanity read-only prima (T2) | `pass=17 fail=0`, `ktext=0xffffffffc30b0000` |
| payload: header di run | `commit=13cd264 fw=0x1360 diag=4 arm=0 ack=0 takeover=0 stage_pre_sleep=0 report_only=1` |
| installazione Linux | **saltata** dal percorso report-only (`Linux install skipped (T5 never boots)`) |
| escape | eseguito: `NX BEFORE` registrato per kernel pmap e proc pmap |
| standby | `sceSystemStateMgrEnterStandby()`; console in rest mode a +12 s |
| risveglio (operatore) | console tornata, ping 3,9 ms, helper 200, elfldr 200 |
| report del payload | `[R0]` · `[R2] ktext pde/pte … xotext=0 rw=1` · `[R3] marker = 0` · `[R4] no hook armed, no takeover, no write` |
| conferma letta **da fuori** (`make verify-resume`) | `live resume stato .text/marker PASS  xotext=0 rw=1 marker=0`, `pass=18 fail=0` |
| integrità dopo (T2) | `pass=17 fail=0`; `IDT[0]` gate valido, `IOMMU_SOFT C` puntatore canonico, blob WiFi integro |

**Risposta a H1 (§2.4), nella parte che T5 copre**: lo **staging dell'escape** (page table di `.text` rese
scrivibili, NX chiaro sulla pagina payload) **sopravvive** a un ciclo standby/resume reale, e il processo
payload sopravvive con esso. Lo staging **non** è la causa dei blocchi al risveglio osservati in precedenza.

Il sospetto si restringe a ciò che in questo test **non** c'era: installazione dell'hook (catena nel cave),
armo (scritture del gate `#DB` e dello slot IST), redirect RSI, takeover post-resume. Da qui il nuovo test
**T5b** nel backlog del charter. Precisione necessaria: con `ARM_HOOK=0` `install_resume_hook()` **non viene
chiamata affatto**, quindi T5 non ha testato "install senza armo" — ha testato "nessun hook, solo staging".

**Primo tentativo, registrato perché è un dato**: l'artefatto al commit `3258296` usciva in `fetch_linux()`
con `File bzImage not found at default paths` **prima** dell'escape; nessuna scrittura, console mai
addormentata. La specifica iniziale (§3) dava per scontato che `fetch_linux()` non bloccasse il percorso: non
era vero. Corretto in `13cd264` e coperto da un controllo statico.

**Limite di ciò che l'esito dimostra**: T5 dice che *questo* staging con *questo* payload sopravvive; non
dice che qualunque combinazione che include lo staging sia sicura, né che il takeover post-resume sia
innocuo. E il risveglio è stato manuale: la console è stata svegliata dall'operatore, quindi nulla è detto
sul comportamento di un risveglio automatico o su tempistiche diverse.

---

## 7. Ciò che resta **non** dimostrato

1. **Che Linux avvii su 13.60**: mai raggiunto. Il takeover post-resume è incompleto (fase B spenta di
   default; indirizzi HV non risolti) e serve un media di boot ≥ 64 GB.
2. **Chi uccide al resume** (§2.4 H1): **ristretto**, non chiuso. T5 (§6.1) esclude lo staging; resta da
distinguere fra installazione dell'hook, armo (gate+IST), redirect RSI e takeover → **T5b**.
3. **Che lo staging sopravviva al ciclo S3**: **dimostrato per il caso senza hook** (§6.1). Resta aperto per
le varianti con l'hook installato e/o armato.
4. **La correttezza dei sei valori in `.text`** (§2.4 H4): `.text` non è leggibile — né via CPU né via GPU
   (F5). Restano statici, con le loro due fonti (cattura + loader di riferimento).
5. **Chi sia `FUN_MP3_INITIALIZE`** (§2.4 H3): divergenza documentata, misura rinviata.
6. **Che una qualunque sequenza che termina con un disarmo sia sicura**: T3 esonera il disarmo **isolato**.
7. **La liveness dell'userland dopo il resume**: misurata come "non torna" in un run precedente, ma non
   caratterizzata per ogni variante.
8. **Che il nuovo percorso report-only non aggiunga scritture**: verificato in esecuzione — il log mostra che
non tocca hook, marker, gate o IST, e le uniche scritture restano ucred + page table + NX (§4.3 e §6.1).

Un elenco di compilazione riuscita **non** è una prova di nessuno dei punti sopra: la build dice quali
simboli esistono, non cosa fa il kernel.
