# T5 — protocollo operativo (staging + standby + resume, report-only)

Specifica eseguibile di T5. **Nessuna prova hardware è stata eseguita**: questo documento è ciò che va
sottoposto all'operatore prima di eseguirla. Le regole generali restano quelle del charter
(`docs/TESTING-BRANCH-CHARTER.md`): una sola azione che **scrive** nel kernel per accensione, analisi
offline di ciò che il test scrive prima di eseguirlo, criterio di arresto con ritorno a T2.

Branch: `analysis/t5-resume-report-only`. Documento di riferimento: `docs/ANALYSIS-T5-REPORT.md`.

---

## 1. Domanda a cui T5 risponde

> lo **staging dell'escape** sopravvive a un ciclo reale di standby/resume, **senza** che l'hook sia armato
> e **senza** che giri il takeover post-resume?

Oggi non lo sappiamo: il blocco #1 aveva staging *e* takeover; il blocco #2 aveva staging *e* un risveglio,
senza sapere quale parte sia stata fatale.

---

## 2. Pre-flight (operatore)

| # | condizione | come si verifica |
| --- | --- | --- |
| P1 | jailbreak attivo | `curl -s "http://127.0.0.1:19113/api/ps5/status?addr=<IP>"` → 200; `curl -s -o /dev/null -w '%{http_code}' http://<IP>:9021/` → 200 |
| P2 | console sana, nessun payload in esecuzione | ping stabile; `list-dir /data` risponde |
| P3 | recovery ufficiale pronta | `PS5/UPDATE/PS5UPDATE.PUP` (13.60) sulla chiavetta |
| P4 | l'operatore può **risvegliare** la console a mano | — |
| P5 | log precedenti messi al sicuro | `tools/pl5-save-logs.sh <IP>` |
| P6 | `make verify-offsets` verde **prima** di iniziare | sanity check read-only (T2) |

---

## 3. Build

```bash
make clean-objs
make PL5_DIAG=4 PL5_1360_RESUME_REPORT_ONLY=1 \
     PL5_BUILD_COMMIT="$(git rev-parse --short HEAD)" t5-report-only
sha256sum bin/pl5-t5-report-only.elf
```

- L'artefatto è **`bin/pl5-t5-report-only.elf`** sotto quel nome e con quella configurazione: il target
  rifiuta di costruire se `PL5_1360_RESUME_REPORT_ONLY` non è `1`.
- `ARM_HOOK`, `ACK_EXPERIMENTAL_ARMING`, `TAKEOVER` e `STAGE_PRE_SLEEP` restano ai default **0**; se una
  qualsiasi di queste è `1`, la build **fallisce** con `#error` (guardia in `hv_defeat_1360.c`).
- `PL5_DIAG=4` è il valore consigliato: è il percorso che fa l'escape e registra lo stato NX prima/dopo.
- La configurazione effettiva va registrata insieme all'SHA-256: l'artefatto `.elf` non è versionato nel
  repository, quindi **un file locale non prova da solo a quale commit appartiene**.

---

## 4. Cosa scrive, esattamente

Solo il percorso di escape, e **prima** dello standby (dopo il risveglio: zero scritture):

1. `kernel_set_ucred_authid(getpid(), …)` — credenziali del processo payload;
2. `escape_kernel_text()` — per ogni pagina da `ktext` a `kdata`: `XOTEXT` azzerato e `RW` alzato su **PDE e
   PTE**, con riscrittura dell'entry (nell'ultimo run reale: `pde=3264 pte=3264`);
3. `map_payload_executable()` su **kernel pmap** e su **pmap del processo** — `EXECUTE_DISABLE` azzerato
   sulla pagina payload.

**Non** scrive: data cave, marker `STATE_ARMED`, gate `IDT[#DB]`, slot IST, `DR7`, blob di takeover. Con
`PL5_1360_ARM_HOOK=0` `install_resume_hook()` non è nemmeno chiamata (è dentro `#if PL5_1360_ARM_HOOK`).

Dopo il risveglio `hv_defeat_1360_report_resume()` **legge soltanto** (page table di `.text` + marker).
`hv_defeat_1360_arm()` e `hv_defeat_1360_post_resume()` non vengono chiamate.

---

## 5. Esecuzione (una azione scrivente per accensione)

1. sanity read-only: `bin/pl5-verify-offsets.elf` → atteso `pass=17 fail=0`;
2. copiare `bin/pl5-t5-report-only.elf` in `/data/` e lanciarlo con elfldr;
3. **non** eseguire altro in questa accensione;
4. la console entra in standby dopo ~5 s: **risvegliarla a mano**;
5. se torna raggiungibile: solo controlli **read-only** (`verify-offsets`, `verify-resume`). **Non** eseguire
   il disarmo "per comodità" nella stessa accensione;
6. spegnimento **completo** a fine prova.

---

## 6. Log e verifiche da raccogliere

- intestazione di run nel log: `pl5: run header version=… commit=… diag=4 … report_only=1` (nuova, §4.4 del
  report);
- righe di fase del payload: `[X] ktext pde/pte …`, `[W0] pre-suspend`, e — se il processo sopravvive —
  `[R0]…[R4]`;
- `make verify-offsets` e `make verify-resume` dopo il risveglio;
- `tools/pl5-save-logs.sh <IP>` **prima** della prova (il log si tronca all'avvio: se non lo copi prima, il
  run precedente sparisce).

Convenzione di fase (già in uso): ogni riga `[X]`/`[A]`..`[F]`/`[W0]`/`[P1]`..`[P7]`/`[R0]`..`[R4]` è un
marcatore; l'ultima riga presente nel log dice qual è stata **l'ultima fase completata**.

---

## 7. Criteri di successo (misurabili)

| # | criterio |
| --- | --- |
| S1 | `make verify-offsets` → `pass=17 fail=0` **dopo** il ciclo (tabella e stato vivo integri) |
| S2 | il log contiene l'intestazione di run con `report_only=1` |
| S3 | il log contiene `[R0]` → il processo payload è sopravvissuto al sonno |
| S4 | `make verify-resume` legge `xotext=0 rw=1` e `marker=0` → staging ancora in vigore, nessun armo dichiarato |
| S5 | la console resta raggiungibile e stabile ≥ 5 minuti (ping + helper + elfldr) |

**Nessun criterio è soddisfatto da una build riuscita.** S3 da solo non è la risposta: la riga prova che il
processo e il log sono vivi, non che il kernel sia sano. S4 è ciò che dice se lo **staging è sopravvissuto**,
e va letto da fuori (letto dal tool), non inferito dal fatto che manchi un errore.

---

## 8. Criteri di arresto

| # | condizione | azione |
| --- | --- | --- |
| A1 | la console non risponde dopo il risveglio | **non** ripetere il payload, **non** eseguire un altro intervento scrivente: registrare l'ultimo log persistente, spegnimento completo, tornare a T2 dopo il recupero |
| A2 | `verify-offsets` fallisce o dà valori diversi | stop immediato, nessuna azione scrivente, raccolta evidenze |
| A3 | blocco/riavvio durante lo staging (prima dello standby) | spegnimento completo; il test non si ripete senza una correzione verificata offline |
| A4 | un servizio manca dopo il resume (helper ≠ 200, elfldr ≠ 200) | stop; il risultato non è valido |

In tutti i casi: il fallimento va **registrato** (incluso l'esito negativo). Un test non riuscito è un dato.

---

## 9. Recupero

1. **spegnimento completo**: staccare la corrente ~30 s (non basta il tasto se la console resta in rest
   mode) → avvio a freddo → re-iniezione di helper ed elfldr;
2. se non torna a freddo: **recovery mode** con `PS5/UPDATE/PS5UPDATE.PUP` (recovery ufficiale 13.60) —
   perde il jailbreak, **non** i dati dell'utente;
3. il payload **non scrive su storage persistente** (gira in RAM): un brick da questa prova è improbabile.

---

## 10. Cosa **non** è una prova

- l'assenza di una riga `[R*]` nel log **non** dice che il kernel è stato danneggiato: è già misurato che
  userland, elfldr e helper possono semplicemente non tornare dal sonno;
- una compilazione riuscita non prova né la sopravvivenza del payload né la sicurezza del percorso;
- che il disarmo isolato sia innocuo (T3) non prova che questa sequenza lo sia.
