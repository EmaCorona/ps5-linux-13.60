# Analisi funzionale dei prossimi test — PS5 13.60 (pLinux5-NG)

Documento inoltabile: contiene **cosa resta da testare, cosa serve per farlo, i rischi e le decisioni
che servono dall'analista**. È il seguito di `docs/ANALYST-BRIEFING-1360.md` (contesto completo).

---

## 1. Stato verificato (fatti misurati, non opinioni)

| test | esito | prova |
| --- | --- | --- |
| T1 jailbreak (helper + elfldr) | ✅ | console pilotabile via ps5upload + elfldr |
| T2 `verify-offsets` (read-only) | ✅ | `pass=17 fail=0` su **due** boot con layout diverso (`ktext=0xc30b0000` e `0xc6580000`) |
| T3 `disarm` da solo | ✅ | `pde=3264 pte=3264`, `XOTEXT 1->1`, marker a 0, console sana → **il disarmo è esonerato** |
| WS2b `.text` via GPU | ❌ negativo | gate del metodo PASS su `.data`, ma i sei indirizzi `.text` tornano tutti-uno → non leggibile per quella via |
| boot Linux end-to-end | 🚫 | mai raggiunto; il progetto dichiara il takeover post-resume incompleto |

**Tre blocchi** della console osservati in totale (stessa firma: accesa, schermo attivo, rete persa),
tutti recuperati con spegnimento completo, **nessuna scrittura persistente**:

1. `PL5_DIAG=4` (percorso completo, con trigger) → servizi userland morti;
2. staging (`PL5_DIAG=16`) seguito da un **risveglio** dal rest mode;
3. **due payload nella stessa accensione** (tool GPU + disarmo). Il disarmo è ora esonerato come
   azione isolata (T3) → il sospetto si sposta sul percorso GPU, che però non serve più.

**Regola operativa in vigore**: read-only ripetibile nella stessa accensione; ogni azione che
**scrive** nel kernel è **una per accensione**, seguita da controllo di salute e spegnimento completo.

---

## 2. I prossimi test

### T4 — staging senza armo (`PL5_DIAG=16`)

* **Obiettivo**: confermare che l'escape si prepara **senza installare** l'hook, e documentare
  esattamente cosa lascia dietro.
* **Cosa serve**: artefatto già pronto (`pLinux5-NG-offsets-diag16-nofire.elf`, sul branch
  `testing`). Nessun media, nessuna modifica di codice.
* **Cosa tocca**: XOTEXT/RW su `.text` (3264 PDE + 3264 PTE) + stage nel code cave. Nessun ciclo S3.
* **Rischio**: medio (è lo stato che ha preceduto il blocco #2, ma è già girato sano due volte).
* **Criterio di successo**: console viva dopo il run, con l'output che dichiara `hook NOT installed
  (arm=0 ack=0)`.
* **Criterio di arresto**: console non risponde → spegnimento, non si ripete.

### T5 — standby + resume **con staging non armato** ← *il test che conta*

* **Obiettivo**: decidere **cosa uccide al resume**: lo **staging** o il **lavoro di takeover
  post-resume**? Oggi non lo sappiamo: il blocco #1 aveva staging **e** takeover; il blocco #2 aveva
  staging **e** un risveglio, senza che sapessimo quale parte sia stata fatale.
* **Perché è la domanda**: se il problema è il takeover, allora il percorso verso il boot è
  affrontabile a pezzi (si isola e si corregge quella fase). Se è lo staging stesso che non
  sopravvive al ciclo S3, va ripensato il modo in cui prepariamo l'escape — e cambia l'intero piano.
* **Cosa serve — e qui c'è una lacuna**: nel codice attuale **non esiste uno stadio** che faccia
  "staging → standby → resume → *solo riferire*". I fatti dal codice (`source/main.c`):
  * `PL5_DIAG` da 10 a 17 → **salta lo standby** (loop di heartbeat) → non testa il resume;
  * `PL5_DIAG < 10` → prosegue e chiama `sceSystemStateMgrEnterStandby()`;
  * dopo il risveglio chiama **sempre** `hv_defeat_1360_post_resume()` → cioè il takeover incompleto;
  * l'armo dell'hook è governato da `PL5_1360_ARM_HOOK` (compile-time) e `PL5_DIAG == 18` (arm-late).
  Quindi servirebbe **una variante di build** che: (a) prepari lo staging, (b) entri in standby,
  (c) al risveglio **riporti lo stato e si fermi** senza fare il takeover. È una modifica piccola e
  reversibile, ma **è una modifica di codice**: per questo chiedo una decisione prima di farla.
* **Cosa tocca**: come T4 **più** un ciclo S3 reale.
* **Rischio**: **alto** (il resume è il punto fragile documentato).
* **Precondizioni**: jailbreak attivo; l'operatore deve poter **risvegliare** la console a mano;
  recovery pronta; nessun'altra azione nella stessa accensione.
* **Criterio di successo**: la console sopravvive al ciclo e l'output dichiara lo stato al risveglio.
* **Criterio di arresto**: non torna → spegnimento completo, si torna a T2, e **non si ripete** senza
  una correzione verificata offline.
* **Domande aperte**: quale stadio usare per lo staging (il default `PL5_DIAG=4` con
  `ARM_HOOK=0`?); serve misurare anche lo stato di XOTEXT **dopo** il risveglio?

### T6 — divergenza `FUN_MP3_INITIALIZE` (`0xA14130` vs `0xA13740`)

* **Obiettivo**: decidere quale dei due è l'initializer MP3.
* **Perché è rinviato**: non esiste un discriminatore **read-only**: `.text` non è leggibile (né CPU
  né GPU) e il flag "mp3 pronto" su cui `mp3_invoke` fa il gate è **già 1 su una console avviata**
  (il sistema inizializza l'MP3 da solo). Un test dovrebbe **chiamare** una funzione del kernel (che
  crea un thread) → rischio alto per un guadagno che si vedrebbe solo su audio/HDCP.
* **Opzioni**: (a) lasciarlo documentato e preferire il nostro `0xA13740` (due argomenti: possiede la
  stringa *"[MP3] failed to init message thread"* ed è il **chiamante** di `0xA14130`); (b) progettare
  l'esperimento a chiamata accettandone il rischio; (c) **deciderlo dal primo boot riuscito** (se
  sbagliato, l'audio/HDCP fallirebbe in modo rumoroso).
* **Domanda aperta**: quale delle tre?

### T7 — boot Linux end-to-end

* **Obiettivo**: portare la console ad avviare Linux.
* **Cosa serve**: supporto **≥ 64 GB** con `PS5/Linux/bzImage` + `PS5/Linux/initrd.img` (il loader
  cerca anche `vram.txt` e `cmdline.txt`); il percorso passa **obbligatoriamente** da rest mode +
  resume; il takeover post-resume è **incompleto** (dichiarato dal progetto).
* **Rischio**: **molto alto**. Non è da tentare prima di T5.
* **Domanda aperta**: ha senso preparare il media adesso, o solo dopo che T5 ha detto se il resume è
  affrontabile?

---

## 3. Lacune tecniche da colmare (cosa *manca*, non cosa è rotto)

| lacuna | impatto | costo |
| --- | --- | --- |
| non esiste uno stadio "staging + S3 + riferisci" senza takeover | **blocca T5**, che è la domanda centrale | piccola modifica di codice (nuovo flag, gated) |
| media di boot ≥ 64 GB non disponibile | blocca T7 | materiale |
| `.text` non leggibile (CPU e GPU) | impedisce la verifica live dei 6 valori in `.text` e un discriminatore MP3 read-only | nessuna soluzione nota oggi |
| il disarmo non è stato provato **dopo uno staging reale** nella stessa accensione | incertezza sul ripristino in sequenza | un test dedicato (T4 + T3 nella stessa accensione = 2 scritture, viola la regola attuale) |
| nessuna telemetria oltre `notify()` (l'output si perde se la console muore) | un blocco lascia poche tracce | log su file prima delle operazioni rischiose (da progettare) |

---

## 4. Decisioni che chiedo (sono il motivo di questo documento)

1. **T5**: autorizzi una **variante di build** "staging + standby + resume senza takeover"
   (nuovo flag gated, nessun effetto sui build attuali)? È la modifica che rende T5 possibile.
2. **Ordine**: T4 da solo in una accensione e T5 nella successiva, oppure T5 direttamente (T5
   contiene T4)? Ricordo che due azioni che scrivono nella stessa accensione violano la regola.
3. **Telemetria**: serve che le operazioni rischiose **scriversi il proprio stato su file** *prima*
   di eseguire (es. "sto per fare X, versione Y, stato Z"), così un blocco lascia una traccia?
4. **T6**: documentare-e-preferire (a), esperimento a chiamata (b), o decidere al primo boot (c)?
5. **Regola**: la regola "una scrittura per accensione" è troppo severa (rallenta molto) o giusta?
   Se serve una sequenza (staging → disarmo), come la rendiamo sicura invece di vietarla?

---

## 5. Cosa serve da me e dall'operatore, per eseguire

* **operatore**: jailbreak attivo (helper + elfldr); power-cycle tra le accensioni; poter risvegliare
  la console a mano per T5; recovery pronta sulla chiavetta.
* **me**: preparare le varianti di build richieste, eseguire **un'azione per accensione**, fare il
  controllo di salute prima/dopo, registrare ogni esito (inclusi i fallimenti) nel diario del charter.
* **artefatti già pronti**: `bin/pl5-verify-offsets.elf` (T2), `bin/pl5-disarm.elf` (T3),
  `pLinux5-NG-offsets-diag16-nofire.elf` (T4); mancano la variante per T5 e il media per T7.
