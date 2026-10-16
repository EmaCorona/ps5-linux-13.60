#!/usr/bin/env bash
# pl5-save-logs.sh -- mette al sicuro i log di una prova PRIMA di iniziarne una nuova.
#
# Perche' serve (analisi T5, fase 3.3): il payload scrive su piu' file di log
# (/mnt/usb0..3, /data, /tmp). Il primo open() di una nuova esecuzione tronca il
# file (O_TRUNC) finche' non e' avvenuto un log_reopen() (che passa a O_APPEND),
# quindi tutto cio' che sta sul dispositivo viene sovrascritto all'avvio della
# prova successiva. Il log e' l'unica traccia che resta se la console si blocca:
# va copiato fuori prima, non dopo.
#
# Uso:   tools/pl5-save-logs.sh <ip-console> [dir-locale]
# Default dir: ~/src/ps5-dumps/pl5-logs/<timestamp>/
#
# Richiede il motore locale di PS5Upload su 127.0.0.1:19113 (endpoint
# /api/transfer/download). Non scrive nulla sulla console: e' una lettura.
set -euo pipefail

IP="${1:?uso: $0 <ip-console> [dir-locale]}"
BASE="${2:-$HOME/src/ps5-dumps/pl5-logs}"
ENGINE="${PL5_ENGINE:-http://127.0.0.1:19113}"
STAMP="$(date +%Y%m%d-%H%M%S)"
DEST="$BASE/$STAMP"

command -v curl >/dev/null || { echo "serve curl" >&2; exit 1; }

if ! curl -sf -o /dev/null "$ENGINE/api/ps5/status?addr=$IP"; then
  echo "motore locale non raggiungibile su $ENGINE (o console $IP non risponde)" >&2
  exit 3
fi

mkdir -p "$DEST"
echo "salvataggio in: $DEST"

rc=0
for remote in /data/plinux5.log /tmp/plinux5.log; do
  job_json="$(curl -s -X POST "$ENGINE/api/transfer/download" \
      -H 'Content-Type: application/json' \
      -d "{\"addr\":\"$IP\",\"src_path\":\"$remote\",\"dest_dir\":\"$DEST\",\"kind\":\"file\"}")"
  job="$(printf '%s' "$job_json" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("job_id",""))' 2>/dev/null || true)"

  if [ -z "$job" ]; then
    # Il file puo' semplicemente non esistere su questa console: non e' un errore fatale.
    echo "  $remote: non scaricato ($job_json)"
    continue
  fi

  for _ in $(seq 1 30); do
    st="$(curl -s "$ENGINE/api/jobs/$job")"
    case "$st" in
      *'"status":"done"'*) echo "  $remote: OK"; break ;;
      *'"status":"failed"'*|*'"status":"error"'*)
        echo "  $remote: job fallito ($st)"; rc=1; break ;;
    esac
    sleep 1
  done
done

# Un file di log ricopiato senza guardarlo non e' una prova: mostriamo cosa c'e' dentro.
echo "--- riepilogo ---"
for f in "$DEST"/*.log; do
  [ -e "$f" ] || continue
  printf '  %8s B  %s  %s\n' "$(stat -c %s "$f")" "$(sha256sum "$f" | cut -c1-16)" "$(basename "$f")"
  echo "    ultima fase: $(tail -c 200 "$f" | tr '\n' '|' | tail -c 160)"
done
[ "$rc" = 0 ] && echo "log precedenti al sicuro: si puo' procedere" || echo "ATTENZIONE: qualche download e' fallito" >&2
exit "$rc"
