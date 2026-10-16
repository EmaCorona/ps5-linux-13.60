# `testing` — charter del branch: conoscenze acquisite, criticità e piano

Questo documento è il **punto di ingresso** del branch `testing`. Consolida quello che sappiamo
(rimandando ai documenti esistenti invece di duplicarli), elenca le criticità misurate e definisce
il piano d'azione con criteri di successo verificabili.

Regola fondante: il branch `feature/13.60-support` (baseline) **non viene toccato**. Ogni modifica
qui è motivata, verificabile e accompagnata da un test; i risultati si confrontano con il baseline.

---

## Parte 1 — Regole del branch

1. **Baseline intatta.** `feature/13.60-support` resta il riferimento congelato. Nessun commit, nessun
   rebase, nessuna riscrittura su quel branch.
2. **Documentazione prima dell'implementazione.** Questo file precede le modifiche di codice.
3. **Ogni modifica**: (a) motivazione scritta, (b) evidenza riproducibile, (c) test automatico o
   procedura di verifica, (d) confronto con il baseline dove i numeri cambiano.
4. **Nessuna scrittura persistente sul sistema** (console o host) introdotta senza una sezione
   dedicata in questo file che ne descriva il rollback.
5. **Fail-closed**: se un valore o una condizione non è verificata, il payload deve rifiutare di
   proseguire, non indovinare.

---

## Parte 2 — Stato delle conoscenze

### 2.1 Cos'è il payload

`pLinux5-NG` è un payload PS5 che, partendo da un kernel 13.60 con jailbreak, prepara il sistema a
eseguire Linux al resume dallo standby: elude l'hypervisor, mappa memoria (IOMMU/TMR/GPU), richiama
alcuni servizi di sistema (MP3, transmitter display), scrive l'immagine di boot e la avvia.

Stadi di diagnostica (`PL5_DIAG`), dai test e dal codice:

| stadio | cosa fa | stato misurato |
| --- | --- | --- |
| `1` | probe build | non eseguito in questa sessione |
| `4` | *real post-resume flow* | **eseguito: perdita di servizi** (hook installato **e** scatenato) |
| `14` | solo il gate `#DB` | non eseguito |
| `15` | install completo con `DR7 = 0` | non eseguito |
| `16` | install completo, `kh_trigger()` **mai** chiamato | **eseguito: escape staged, hook NON installato, console sana** |

### 2.2 Offset: cosa è stato risolto e con quale prova

Tutti i campi tracciati hanno ora un valore con provenienza scritta in `tools/offset_registry.json`.
Gli ultimi risolti (con l'evidenza che li sostiene):

| campo | valore | prova |
| --- | --- | --- |
| `FUN_MP3_INITIALIZE` | `0xA14130` | tabella del loader 13.60 funzionante; **divergenza dichiarata** (una firma-stringa legava il nome a `0xA13740`, che *chiama* `0xA14130`) |
| `FUN_MP3_INVOKE` | `0xA12D30` | ABI a 3 argomenti (`cmd, req, rsp`) + distanza `0xA10` identica alla tabella 13.20 |
| `FUN_SMP_NO_RENDEVOUS_BARRIER` | `0xB03960` | corpo no-op (`push rbp; mov rbp,rsp; pop rbp; ret`); il valore alternativo `0x261E08` è uno stub che salta lì |
| `FUN_SMP_RENDEZVOUS` | `0xB03BA0` | il precedente `0xB04440` ha **0 chiamanti** (stampa solo la stringa); questo ne ha 6+ |
| `DATA_BASE_GVMSPACE` | `0x3BAA570` | misura indipendente ancorata all'IDT + `gvmspace = idt − 0x9D90`; i probe del repo usano `0x2EEA570` kdata-relativo (= stesso valore) |
| `FUN_TRANSMITTER_CONTROL` | `0xC0EAA0` | thunk `0x39B3B0` chiamato con `edi=0x4C` salta qui; **e** deriva cross-firmware `+0xCBD0` dalla coppia verificata `HV_MP_STARTUP_CALL` |
| `IOMMU_SOFTC` | `0x3543A70` | tabella del loader funzionante; `qword[0x3543A70]` nella cattura è un puntatore kernel canonico |
| `PS5_WIFI_FW_OFFSET` | `0x1518160` | tabella del loader funzionante; regione con header `01000000`, codice ARM e confini netti |
| `PS5_WIFI_FW_SIZE` | `500296` | chiude il trend monotono `492304 → 493000 → 493532 → 494536 → 497636 → 498108 → 500296` |
| `VMSPACE_VM_VMID` | `0x1EC` | il loader lo usa su 13.60 e 12.00; `0x1E4` esiste solo su 3.00-4.51 |
| `VMSPACE_VM_PMAP` | `0x1D8` | **disputa chiusa**: il loader usa il nostro valore, non l'`0x2E8` dell'SDK |

Dettaglio per campo, con limiti e incertezze: `docs/1360-unknown-offsets-hunt.md` e
`docs/1360-sonic-iso-loader-reference.md`. Strumenti: `tools/extract_elf_1360_table.py` (rilettura
riproducibile della tabella di riferimento), `tools/check_offset_registry.py` + `tools/offset_registry.json`.

### 2.3 Verifiche disponibili

* **Suite**: `tests/run_tests.py` — lane *synthetic* (fixture che verificano la logica dei
  verificatori), *real* (cattura reale), *package*.
* **Registry**: `tools/check_offset_registry.py` — classi, namespace, valori non ammessi, dedup.
* **Cattura 13.60**: `~/src/ps5-dumps/k1360.bin`, sha256 `c3f745e2…` — artefatto di riferimento per
  ogni verifica offline. Layout: `.text` = offset file 0..`0xCC0000`; `kernel_data` da `0xCC0000`.

### 2.4 Evidenza hardware raccolta

| run | build | effetto misurato |
| --- | --- | --- |
| 1 | default (`PL5_DIAG=4`), via elfldr | escape + install **e trigger** → **servizi userland morti** (helper 502, porta 9021 chiusa), console accesa ma degradata → richiesto power-cycle |
| 2 | `PL5_DIAG=16` (`diag16-nofire`), via ps5upload + elfldr | `arming disabled (staging only): hook NOT installed (arm=0 ack=0)` → **console sana** (helper 200, elfldr 200). Page-table walk, clear XOTEXT, diagnostica NX: tutti riusciti |

Lezione operativa: **il nome del target non implica il comportamento**. Il target `offsets` con
`PL5_DIAG=4` è un payload che arma e scatena; solo `PL5_DIAG=16` installa senza scatenare.

---

## Parte 3 — Criticità, vulnerabilità, casi limite, scenari d'errore

### 3.1 Criticità bloccanti / ad alto impatto

1. **Armare l'hook uccide i servizi (misurato).** Non è un rischio teorico: due run su due con
   `PL5_DIAG=4` hanno richiesto un power-cycle. Manca un modo per *disarmare* da caldo.
2. **Nessuna validazione runtime dei campi nuovi.** `diag16` salta lo standby, quindi la fase che
   legge e produce i valori non gira. I 10 campi sono validati *staticamente* (cattura + loader di
   riferimento) ma **non ancora letti dal kernel vivo**.
3. **`FUN_MP3_INITIALIZE`: divergenza aperta.** Due fonti serie, due valori, entrambi entry reali.
   Non è risolvibile per ragionamento: serve una misura a runtime.
4. **Il boot Linux non è mai stato completato su 13.60.** Il README upstream è esplicito: non
   trattare un build riuscito come prova di boot funzionante.

### 3.2 Vulnerabilità e punti deboli del payload

5. **Fail-open** in alcuni percorsi: un offset a zero può significare "non necessario" *oppure*
   "sconosciuto". Se il consumatore non distingue i due casi, legge a `0x0` e non fallisce subito.
6. **Doppia convenzione stub/entry**: alcune tabelle usano lo stub (`printf 0x25D410`), altre
   l'implementazione (`0x4ADD60`). Chi confronta valori senza decodificare può concludere male.
7. **Gate di versione**: il rifiuto su firmware non previsto esiste (`set_offsets` → `-1`), ma va
   verificato che *ogni* percorso lo rispetti prima di scrivere in kernel.
8. **Nessuna protezione dall'esecuzione doppia**: due run senza power-cycle in mezzo lasciano stato
   residuo (hook installato, `.text` scrivibile, marker ARMED nella data cave).
9. **Assenza di un percorso "solo lettura" per i nuovi campi**: l'unico dumper che stampa valori è
   pesante (dump completi) e non copre MP3/transmitter/WiFi/IOMMU.

### 3.3 Casi limite e scenari d'errore

10. **Media di boot assente o sbagliato**: il loader cerca `bzImage` e `initrd.img` in
    `/mnt/usb{0..3}[/PS5/Linux/]` e **aborta** se mancano — ma dopo aver già fatto escape e scritture.
    Un controllo *prima* delle scritture sarebbe più sicuro.
11. **Media troppo piccolo**: l'immagine richiede ≥64 GB; una chiavetta da 14,6 GiB fallisce a metà
    strada (e il flash cancellerebbe la PUP di recovery se fosse la stessa).
12. **Cattura non completa**: 21,8 MB della cattura sono zeri, incluso il range di pagine non mappate
    dichiarato. Qualsiasi verifica che ci cada dentro è falsa negativa.
13. **Dump che produce zeri**: il dumper `offsets` ha già prodotto un kit con `data_dump.bin` tutto a
    zero (artefatto inutile, 88 MB). Va reso evidente quando il dump è vuoto invece di consegnarlo.
14. **Perdita dell'helper**: i payload iniettati (helper, elfldr) muoiono col crash e vanno re-iniettati.
    Nessun watchdog li ripristina.

### 3.4 Rischio residuo dichiarato

15. **Recovery disponibile ma con costo**: recovery mode + PUP ufficiale 13.60 (1.404.953.088 B,
    verificata) ripristina la console; si perde il jailbreak. Il brick permanente non è contemplato
    dal percorso attuale (nessuna scrittura su flash/bootloader), ma non è dimostrato impossibile.

---

## Parte 4 — Piano d'azione (workstream, criteri di successo)

Ordine di priorità. Ogni WS ha: obiettivo, criteri **misurabili**, test, rischio.

### WS1 — Validazione offline continua (priorità massima, rischio nullo)
* Obiettivo: nessun valore entra nella tabella senza provenienza e verifica.
* Criteri: 100% dei campi con `provenance` non vuota; checker a 0 failed; suite verde su ogni commit;
  ogni nuovo valore accompagnato da un controllo sulla cattura quando possibile.
* Test: `tools/check_offset_registry.py`, `tests/run_tests.py` (lane real/package incluse).

### WS2 — Diagnostica sicura: leggere e stampare i 10 campi (priorità alta, rischio basso)
* Obiettivo: un payload che, **senza armare e senza standby**, dopo `set_offsets()` stampi i 10 campi
  e li confronti con i valori attesi dalla tabella.
* Criteri: i valori letti dal kernel vivo coincidono al 100% con la tabella; nessuna perdita di servizi
  in 3 run consecutivi; output salvato su file per il confronto.
* Test: run hardware (staging come `diag16`), confronto automatico output↔tabella.
* Dipendenze: WS3 (deve restare senza armo).

### WS3 — Robustezza dell'escape e sicurezza (priorità alta)
* Obiettivo: staging senza armo come *default*; arming solo con `ACK` esplicito; **comando di disarmo**.
* Criteri: `PL5_1360_ARM_HOOK=0` implica 0 installazioni (verificato da output); un disarmo riporta
  `.text` a XOTEXT=1 e rimuove il marker ARMED; nessuna perdita di servizi in N run di staging.
* Test: run di staging ripetuti + verifica del marker e di XOTEXT dopo il disarmo.

### WS4 — Chiudere la divergenza `FUN_MP3_INITIALIZE` (priorità media)
* Obiettivo: decidere fra `0xA14130` e `0xA13740` con una misura, non con un'opinione.
* Criteri: una prova runtime che produce un effetto distinguibile per i due valori (es. init del
  sottosistema MP3 osservabile) e il valore perdente documentato come alternativa.
* Test: run hardware controllato, output prima/dopo.

### WS5 — Boot Linux end-to-end su 13.60 (priorità media, dipende da WS2/WP3)
* Obiettivo: portare la console ad avviare Linux, con display/audio/WiFi (i campi G2).
* Criteri: boot completato con evidenza (log console, `uname`, stato rete/display); rollback provato
  almeno una volta; nessuna regressione sui campi già verificati.
* Test: media ≥64 GB preparata con `bzImage` + `initrd.img`; sequenza documentata; recovery pronta.

### WS6 — Prevedibilità e fail-closed (priorità media)
* Obiettivo: ogni percorso che scrive in kernel passa da un gate di versione + presenza valori.
* Criteri: un offset a 0 blocca con messaggio esplicito (niente letture a `0x0`); il controllo dei file
  di boot avviene **prima** delle scritture; su errore il payload non lascia stato residuo.
* Test: fixture che simulano offset mancanti e media assente.

### WS7 — Documentazione e tracciabilità (continua)
* Obiettivo: ogni decisione ha un documento; ogni numero ha una fonte.
* Criteri: i doc referenziati esistono e sono aggiornati; il registro cita la fonte di ogni valore.

---

## Parte 5 — Strategia di test

Tre livelli, in ordine di rischio crescente:

1. **Statico/offline** (nessuna console): checker del registro + suite + verifiche sulla cattura.
   È il livello dove vive la maggior parte del lavoro; costa zero e non rischia nulla.
2. **Hardware staged non distruttivo**: `PL5_DIAG=16` (install, no trigger) e i nuovi probe di WS2.
   Ogni run: salute console prima/dopo, output salvato, recovery pronta.
3. **Hardware completo** (boot Linux): solo dopo 1 e 2 puliti, con media ≥64 GB e rollback provato.

Regola di arresto: se un run al livello 2 o 3 peggiora la salute della console, si torna al livello 1,
si documenta la regressione e non si ripete il run finché non c'è una correzione verificata offline.

---

## Parte 6 — Definizione di "migliorato"

Confronto con il baseline `feature/13.60-support` (`3e35bd0`) su metriche oggettive:

| metrica | baseline | obiettivo su `testing` |
| --- | --- | --- |
| campi con provenienza scritta | 52 KNOWN_STATIC / 1 DISPUTED | 0 DISPUTED, 0 senza fonte |
| validazione runtime dei 10 campi nuovi | assente | 100% coincidenti |
| run di staging senza perdita di servizi | 0 su 1 tentativo pieno | ≥3 consecutivi |
| disarmo da caldo | assente | presente e verificato |
| boot Linux 13.60 | non raggiunto | raggiunto, con rollback provato |

---

## Backlog dei test, con rischio

Scala di rischio riferita a **questa console** (una PS5 13.60 con jailbreak, dove un blocco costa un
power-cycle completo + reiniezione di helper/elfldr, e la PUP di recovery e' pronta sulla chiavetta):

* **nullo** -- nessuna scrittura nel kernel;
* **basso** -- scritture note e reversibili, gia' eseguite senza danni;
* **medio** -- scritture che hanno gia' coinciso con un blocco, o percorso non ancora isolato;
* **alto** -- percorso che ha ucciso i servizi, o che chiama codice kernel non verificato;
* **molto alto** -- percorso dichiarato incompleto dal progetto stesso.

| # | test | cosa verifica | scritture nel kernel | reversibile | rischio | stato |
| --- | --- | --- | --- | --- | --- | --- |
| T1 | ripristino jailbreak (helper + elfldr) | la console e' di nuovo pilotabile | nessuna (payload standard dell'operatore) | n/d | **nullo** | **fatto** (operatore) |
| T2 | `make verify-offsets` (read-only) | i 13 valori della tabella + stato vivo (IDT, IOMMU_SOFTC, blob WiFi) | **nessuna** | n/d | **nullo** | **fatto 3 volte, sempre 17/0** |
| T3 | `make disarm` da solo | riporta XOTEXT/RW e azzera il marker ARMED | 3264 PDE + 3264 PTE (ripristino) | si' (e' gia' l'inverso) | **basso** | **fatto: sicuro**. Da solo non provoca il blocco |
| T4 | `PL5_DIAG=16` staging senza armo | l'escape si prepara **senza** installare l'hook | XOTEXT/RW + stage nel cave | si' (T3) | **medio** | provato sano una volta; **superato da T5**, che aggiunge il ciclo S3 vero |
| T5 | staging dell'escape + **ciclo S3 reale**, report-only (nessun armo, nessun takeover) | lo *staging* sopravvive al sonno? | ucred + XOTEXT/RW su 3264 PDE + 3264 PTE + NX sulla pagina payload. **Nessuna** scrittura di hook: con `ARM_HOOK=0` `install_resume_hook()` non e' nemmeno chiamata | parziale (il resume non e' annullabile) | **alto** (ma esito misurato benigno) | **FATTO — si': lo staging sopravvive.** Console sana, staging in vigore (`xotext=0 rw=1`), marker a 0. Il colpevole al resume non e' lo staging: passa a **install hook / armo gate+IST / redirect RSI / takeover** |
| T5b | staging + hook **installato ma NON armato** (catena scritta, gate/IST mai scritti) | le scritture di *install* bastano a rompere il resume, o serve l'armo? | come T5 **piu'** le scritture dell'install: `break_hv` nella cave, oracle, catena, immagine della scratch, `probe_write` | parziale | **medio-alto** | **preparato offline, NON eseguito** (in attesa di decisione). Separazione confermata dal motore: `kh_arm()` scrive *solo* gate+IST, e `kh_install()` puo' girare con `KH_SKIP_IST\|KH_SKIP_GATE`. Flag `PL5_1360_INSTALL_NO_ARM` fail-closed, artefatto `pl5-t5b-install-no-arm-74290bb.elf` (`3f0fd685…`), guardie provate a fallire, protocollo in `docs/T5B-PREP-1360.md` **ESEGUITO — positivo sulla sua domanda**: l'installazione non rompe il ciclo (console sana, staging in vigore, `[R0]` con `install_no_arm=1`). **Difetto trovato**: la coda di `install_resume_hook()` scriveva il marker `'KHOOKED.'` incondizionatamente, fuori da `kh_install()` → falso claim d'armo; corretto in `86b5231` (il marker non si scrive, nuovo test). Conferma su hardware con l'artefatto corretto `4e2bc20f…` **da fare**. Dettagli: `docs/T5B-PREP-1360.md` §7 |
| T6 | WS4: discriminare `0xA14130` vs `0xA13740` | quale dei due e' l'initializer MP3 | chiamata di funzione kernel + letture | no (crea un thread) | **alto** | **rinviato**: nessun discriminatore read-only disponibile (`.text` non leggibile; il flag e' gia' 1 a console avviata) |
| T7 | boot Linux end-to-end | il percorso completo fino a Linux | tutto quanto sopra | no | **molto alto** | **bloccato**: serve media >= 64 GB e il takeover e' incompleto (README: Linux non avvia su 13.60) |
| T8 | verifiche offline (cattura, registro, suite) | coerenza dei dati e dei gate | **nessuna** | n/d | **nullo** | attivo, gira a ogni commit |

Ordine consigliato: **T1 → T2** (nessun rischio, riporta la console a uno stato noto) → **T3** da sola → **T5**
(eseguito: positivo) → ora **T5b** (installare senza armare: stringere il sospetto) → poi **T6** (MP3) e **T7**
(boot), per ultimo.

Regole applicate a ogni riga: **un payload per accensione** -> controllo di salute -> spegnimento completo;
analisi offline di cio' che il test scrive *prima* di eseguirlo; criterio di **arresto** = se la console non
risponde piu' o peggiora, si torna a T2 e non si ripete il test finche' non c'e' una correzione verificata
offline.

## Appendice — Diario delle esecuzioni su questo branch

| data | WS | esito | prova |
| --- | --- | --- | --- |
| 2026-10-16 | WS1 | chiusa l'ultima DISPUTED (`G_VBIOS`) | registry 0 DISPUTED, checker 0 failed / 0 warning |
| 2026-10-16 | WS2 | **verifica runtime riuscita** | `pass=17 fail=0`: 13/13 tabella; IDT[0] gate valido; IOMMU_SOFTC puntatore canonico; blob WiFi header `01 00 00 00` + size 500296 |
| 2026-10-16 | WS2b | **metodo non valido, valori non smentiti** | i sei read via direct map restituiscono byte con la forma di una page-table entry (`07 00 00`) e identici fra indirizzi diversi: e' la finestra di lettura a essere sbagliata, non gli indirizzi. La traduzione VA->PA e' corretta (i delta dei PA seguono i delta degli offset). Via documentata per `.text`: percorso GPU (`pl5-gpu-read`). Il probe ora riporta INCONCLUSIVO invece di FAIL |
| 2026-10-16 | WS3 | **disarmo da caldo funzionante** | `restore: pde=3264 pte=3264 | ktext XOTEXT pte 0->1 | marker 0 -> 0`, read-back `xotext=1 rw=0`: il kernel era ancora escaped dal run diag16 ed e' stato ripristinato senza riavvio. Console sana |
| 2026-10-16 | WS2b (GPU) | **run eseguito: .text NON leggibile via GPU** | gate del metodo PASS (`cpu == gpu` su una pagina .data), ma i sei indirizzi restituiscono tutti `ff ff ff ff ff ff` (tutti-uno), la firma che `pl5-gpu-read` annota come "system RAM non leggibile dalla GPU". Poiche' il gate prova che la macchina di lettura funziona, il tutti-uno e' una proprieta' della piattaforma per le pagine di .text, non un errore del tool. I sei valori restano verificati *staticamente* (cattura + loader di riferimento) |
| 2026-10-16 | **T3** | **disarmo da solo: sicuro** | `restore: pde=3264 pte=3264 | ktext XOTEXT pte 1->1 | marker 0 -> 0`, read-back `xotext=1 rw=0`; console sana (helper 200, elfldr 200, ping 3,9 ms). Su una accensione fresca XOTEXT era gia' 1, quindi il disarmo ha scritto gli stessi valori: **non e' il disarmo, da solo, a provocare il blocco**. Il sospetto per l'incidente #3 si sposta sul **percorso GPU** (DMA + ritargettatura di foglie), l'altra azione di quella sequenza |
| 2026-10-16 | **T2** | **verifica read-only riuscita, su un secondo boot** | `pass=17 fail=0`: 13/13 valori della tabella; `IDT[0]` gate valido (selector 0x20, type 0xe, present); `IOMMU_SOFTC` puntatore kernel canonico; blob WiFi header `0x00000001` + size 500296. `ktext=0xffffffffc30b0000` (diverso dal run precedente `0xc6580000`): i valori reggono su un layout diverso. Zero scritture nel kernel, console sana |
| 2026-10-16 | WS2b (seguito) | **INCIDENTE: console bloccata (schermo acceso)** | subito dopo, il disarmo lanciato come controllo di stato. Console irraggiungibile, schermo acceso: stessa firma dei blocchi precedenti. Causa non isolata fra i due payload: il tool GPU scrive foglie di page table GPU (e le ripristina a ogni lettura, ma non e' esente da rischio) e il disarmo scrive ~6.5k entry CPU. **Regola violata: due payload di fila senza spegnere.** Da qui in avanti: un solo payload per accensione, controllo di salute, poi spegnimento completo |
| 2026-10-16 | **T5 (tentativo 1)** | **non raggiunge l'oggetto: si ferma prima dell'escape** | il payload esce in `fetch_linux()` con `File bzImage not found at default paths` perche' `main.c` installa le immagini Linux *prima* dell'escape e il flag report-only non lo condizionava. **Nessuna scrittura nel kernel, nessuno staging, la console non si e' mai addormentata**: costo zero. Corretto in `13cd264`: il percorso report-only salta l'installazione (T5 non avvia mai Linux, e `fetch_linux()` chiama anche `dump_device_firmwares()`, una scrittura su disco) |
| 2026-10-16 | **T5** | **RIUSCITO: lo staging sopravvive a un ciclo standby/resume reale** | `[R0]` report-only resume reached · `[R2] ktext pde/pte … xotext=0 rw=1` · `[R3] marker = 0` · `[R4] no hook armed, no takeover, no write`. Confermato **da fuori** dal payload con `make verify-resume`: `live resume stato .text/marker PASS  xotext=0 rw=1 marker=0`, `pass=18 fail=0`; poi `verify-offsets`: `pass=17 fail=0`. Console sana (ping 3,9 ms, helper 200, elfldr 200). **Conseguenza**: non e' lo staging delle page table a uccidere al resume; il sospetto si restringe a **installazione dell'hook / armo (gate+IST) / redirect RSI / takeover post-resume** |

| 2026-10-16 | **T5b** | **RIUSCITO: l'installazione non rompe il ciclo** — e un difetto trovato e corretto | Accensione nuova (`ktext=0xffffffff998f0000`, staging azzerato). Run: `mask=0xc` (`KH_SKIP_IST\|KH_SKIP_GATE`), `redirect=0`, catena installata (`rc=0`), trigger saltato. Al risveglio: `[R0]` con `install_no_arm=1`, `[R2] xotext=0 rw=1`, `[R4] no hook armed`. Console sana; `verify-offsets` `pass=17 fail=0`. **Difetto**: `[R3]` ha mostrato `marker=0x4b484f4f4b454401` (`'KHOOKED.'`) mentre il log diceva "this build never writes it": la coda di `install_resume_hook()` scrive il marker incondizionatamente, fuori da `kh_install()` dove nessuna skip mask arriva → falso claim d'armo in memoria condivisa (adozione disattivata, quindi contenuto). Corretto in `86b5231` + nuovo test. **Resta un run di conferma** con `4e2bc20f…` |

## Incidente WS2b/WS3 -- analisi e regole

* **Cosa e' certo**: il gate del metodo GPU e' passato, quindi la lettura .data funziona;
  i sei read .text danno tutti-uno, quindi .text non e' leggibile per quella via su questa console.
* **Cosa non e' certo**: quale dei due payload abbia provocato il blocco. Non lo affermo.
* **Cosa cambia**: i test live si fermano qui finche' non c'e' un piano a un-azione-per-accensione.
  In particolare, ogni run che scrive stato (escape, disarmo, DMA) va seguito da spegnimento completo,
  non da un secondo payload.
