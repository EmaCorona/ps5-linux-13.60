# Briefing per l'analista — rendere il processo di boot PS5 13.60 più sicuro e affidabile

Documento **autosufficiente**: contiene tutto quello che è stato misurato. Se hai accesso al
repository `~/src/ps5-linux-13.60` (branch `feature/safe-reliable-process`), i documenti citati
sono lì; se non ce l'hai, questo file basta per lavorare.

## 1. Oggetto

Un payload (`pLinux5-NG`) gira in RAM su una **PS5 con jailbreak, firmware 13.60**, e prepara la
console a **avviare Linux**: elude l'hypervisor, prepara memoria (IOMMU, GPU, timer), richiama
alcuni servizi di sistema, legge l'immagine Linux da USB e la avvia **al risveglio dallo standby**.

Il progetto è un port del progetto pubblico `ps5-linux-loader` (stesse funzioni, stessi percorsi,
stesse stringhe). L'ELF di riferimento di terze parti (`1360linux.elf`, sha256
`e51a0298cb2c97b71be0ddad…`) è della stessa famiglia e gestisce il boot **allo stesso modo**.

**Obiettivo dell'analisi (tono: funzionale, non implementativa):** rendere questo processo
**più sicuro e più affidabile**. Il deliverable atteso è un documento di analisi + una proposta di
design, non codice.

## 2. Il percorso attuale, passo per passo (e dove scrive stato)

```
setup_env()            carica la tabella offset del firmware in corso
fetch_linux()          cerca bzImage + initrd.img (+ vram.txt, cmdline.txt) in
                       /mnt/usb{0..3}/ e /mnt/usb{0..3}/PS5/Linux/ ; ABORTA se mancano
prepare_resume()       prepara il vettore di resume
escape                 rende .text scrivibile: azzera il bit XOTEXT e setta RW su
                       3264 entry PDE e 3264 entry PTE  [SCRITTURA NEL KERNEL]
prepare / install      installa lo stage nel code cave; puo' arma un hook (#DB)
                       [SCRITTURA NEL KERNEL]
rest mode (S3)         la console va in standby
resume                 al risveglio: il vettore prende il controllo, completa il takeover,
                       avvia Linux (kexec-like)                              [PUNTO FRAGILE]
```

Punti che restano modificati se il passo si interrompe a metà: XOTEXT/RW su `.text`, lo stage nel
code cave, il marker di stato ("ARMED", valore `0x4B484F4F4B454401`), eventuali foglie di page table
della GPU (il tool GPU le ritargetta e le ripristina).

## 3. Evidenza sperimentale (tre blocchi della console)

Tutti e tre con la stessa firma: **console accesa, schermo attivo, rete persa** (porte chiuse,
helper assente). Tutti recuperati con **spegnimento completo** (togliere corrente ~30 s).
**Nessuna scrittura persistente**: il payload gira solo in RAM, non tocca flash/bootloader.

| # | condizione | esito |
| --- | --- | --- |
| 1 | build `PL5_DIAG=4`: arma **e** scatena l'hook | servizi userland morti, console degradata |
| 2 | run che aveva solo *preparato* l'escape (`PL5_DIAG=16`) + successivo **risveglio** dal rest mode | blocco |
| 3 | **due payload nella stessa accensione** (tool di verifica GPU, poi payload di disarmo) | blocco |

## 4. Percorsi provati SICURI (misurati)

| comando | cosa fa | esito |
| --- | --- | --- |
| `make verify-offsets` | legge/diagnostica dopo `setup_env()`, **nessun** escape/armo/standby | `pass=17 fail=0`, console sana |
| `make ... PL5_DIAG=16 offsets` | esegue l'escape **senza** armare (`arm=0 ack=0`), standby **saltato** | console sana |
| `make disarm` | inverso dell'escape: rimette XOTEXT, toglie RW, azzera il marker | `3264 pde + 3264 pte`, `XOTEXT 0->1`, read-back ok |

Nota importante: `PL5_DIAG=16` è la **variante non-armante**; `PL5_DIAG=4` è quella che ha ucciso i
servizi. Il nome del target non implica il comportamento: conta il valore di `PL5_DIAG` e i flag
(`PL5_1360_ARM_HOOK`, `PL5_1360_ACK_EXPERIMENTAL_ARMING`, `PL5_DIAG>=10 && <18` salta lo standby).

## 5. Limiti misurati e questioni aperte

* **`.text` non è leggibile via GPU**: su sei indirizzi di funzione i read tornano tutti-uno
  (`ff ff ff ff`), mentre il *gate di controllo* sulla stessa macchina legge correttamente una
  pagina `.data` (CPU == GPU). Quindi è una proprietà della piattaforma, non un difetto del tool.
  Gli indirizzi restano verificati *staticamente* (contro un dump del kernel e contro la tabella di
  un loader di riferimento che avvia).
* **Il takeover post-resume è incompleto** e Linux **non avvia** su 13.60 (dichiarato dal progetto).
* **Divergenza aperta** su un simbolo (`FUN_MP3_INITIALIZE`): due fonti serie indicano due valori
  diversi (`0xA14130` vs `0xA13740`), entrambi entry reali e in relazione chiamante/chiamato. Va
  decisa con una misura a runtime.
* Il kernel espone una protezione che rende rischiosa la lettura CPU di `.text`; esiste un percorso
  via GPU (usato per i test) e uno via direct-map (che in un test ha restituito byte con la forma di
  una page-table entry, quindi è stato scartato).

## 6. Regole operative già fissate (dopo gli incidenti)

1. **Un payload per accensione**: eseguire, controllare la salute della console, poi **spegnimento
   completo**. Mai due payload di fila (è la causa del blocco #3).
2. Dopo un run che fa **staging dell'escape**, non lasciare la console inattiva a dormire:
   disarmare e/o spegnere subito (è la causa del blocco #2).
3. Ogni nuovo passo live va prima **analizzato offline**: quali indirizzi scrive, quante entry,
   cosa può restare se si interrompe.
4. **Recovery pronta**: chiavetta con `PS5/UPDATE/PS5UPDATE.PUP` ufficiale 13.60 verificata.
   Il blocco non è un mattone: si recupera con lo spegnimento; se non basta, col recovery (si perde
   il jailbreak, non i dati).

## 7. Cosa ti chiedo (analisi funzionale, non codice)

1. **Analisi delle cause** dei tre blocchi, separando ciò che è dimostrato da ciò che è ipotesi:
   quali scritture possono corrompere lo stato e perché il resume è il punto fragile.
2. **Requisiti** di sicurezza/affidabilità: fail-closed, reversibilità, stato residuo zero,
   idempotenza, precondizioni verificate prima di ogni scrittura.
3. **Proposta di design** per rendere il percorso sicuro e affidabile, con alternative e trade-off:
   protocollo a stadi, verifica di stato prima/dopo, disarmo automatico, watchdog, limiti di
   "una azione per ciclo di vita", separazione tra staging e arming.
4. **Protocollo di test a stadi** con criteri di successo e **di arresto** misurabili, coerente con
   la regola "1 payload per accensione", inclusa la procedura di rollback.
5. **Domande aperte** per l'umano.

## 8. Artefatti utili

* Payload e tool: `bin/pLinux5-NG.elf` (principale), `bin/pl5-verify-offsets.elf` (diagnostica
  read-only), `bin/pl5-disarm.elf` (disarmo), `bin/pl5-gpu-textverify.elf` (lettura `.text` via GPU).
* Documenti nel repo: `docs/TESTING-BRANCH-CHARTER.md` (charter e diario delle esecuzioni),
  `docs/1360-khook-death.md` (perché l'hook armato uccide la console), `docs/1360-port-status.md`,
  `docs/BOOT-REQUIREMENTS-1360.md`, `docs/1360-sonic-iso-loader-reference.md`.
* Registro degli offset con provenienza: `tools/offset_registry.json` +
  `tools/check_offset_registry.py`.

## 9. Vincoli

* **Nessuna azione sull'hardware** durante l'analisi: nessun upload, nessuna esecuzione di payload,
  nessun contatto con la console. Solo analisi su codice e documenti.
* **Non toccare il branch baseline** `feature/13.60-support`
  (commit `3e35bd0b73ecdfefb69279055cd953cbc4472c6f`): è congelato.
* Lavora su un **branch dedicato** e committa lì solo documentazione/analisi.
* Distingui sempre **fatto misurato** da **ipotesi**, citando file e righe.
