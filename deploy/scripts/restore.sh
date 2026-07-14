#!/usr/bin/env bash
# MobInspect — interactive SQLite restore from /var/backups/mobinspect.
#
# Usage:  sudo deploy/scripts/restore.sh
#
# What it does (in order):
#   1. Lists every db-*.sqlite3 snapshot under /var/backups/mobinspect, newest first.
#   2. Asks which one to restore (numeric index).
#   3. Stops mobinspect.service (gunicorn) AND mobinspect-worker.service.
#      (PartOf= propagates stop/restart but NOT start, so we have to bring the
#      worker back up explicitly in step 6 — otherwise async scans queue forever.)
#   4. Side-copies the *current* db to db.sqlite3.pre-restore-<ts> so we can roll
#      forward again if the chosen snapshot turns out to be wrong.
#   5. Copies the snapshot over ~/.MobInspect/db.sqlite3 and chowns to ubuntu:ubuntu.
#   6. Restarts mobinspect.service and tails the first ~20 lines of journal for
#      visual confirmation it came back healthy.
#
# RTO target: ≤ 15 minutes (manual confirm + restart).
# RPO target: ≤ 1 hour (driven by mobinspect-backup.timer cadence).

set -euo pipefail

BACKUP_DIR="/var/backups/mobinspect"
LIVE_DB="/home/ubuntu/.MobInspect/db.sqlite3"
SERVICE="mobinspect.service"
WORKER="mobinspect-worker.service"
OWNER="ubuntu:ubuntu"

if [[ $EUID -ne 0 ]]; then
  echo "ERROR: must run as root (need systemctl + chown). Re-run with sudo." >&2
  exit 1
fi

if [[ ! -d "$BACKUP_DIR" ]]; then
  echo "ERROR: $BACKUP_DIR does not exist — has mobinspect-backup.timer ever fired?" >&2
  exit 1
fi

# Newest first so the most-recent snapshot is index 1.
mapfile -t SNAPSHOTS < <(ls -1t "$BACKUP_DIR"/db-*.sqlite3 2>/dev/null || true)
if [[ ${#SNAPSHOTS[@]} -eq 0 ]]; then
  echo "ERROR: no db-*.sqlite3 files in $BACKUP_DIR." >&2
  exit 1
fi

echo "Available MobInspect SQLite snapshots in $BACKUP_DIR:"
echo
for i in "${!SNAPSHOTS[@]}"; do
  f="${SNAPSHOTS[$i]}"
  size=$(stat -c '%s' "$f" | numfmt --to=iec --suffix=B)
  mtime=$(stat -c '%y' "$f" | cut -d. -f1)
  printf "  [%3d] %s  %8s  %s\n" "$((i+1))" "$mtime" "$size" "$(basename "$f")"
done
echo

read -rp "Restore which snapshot? [1-${#SNAPSHOTS[@]}, or q to abort]: " choice
if [[ "$choice" == "q" || "$choice" == "Q" || -z "$choice" ]]; then
  echo "Aborted."
  exit 0
fi
if ! [[ "$choice" =~ ^[0-9]+$ ]] || (( choice < 1 || choice > ${#SNAPSHOTS[@]} )); then
  echo "ERROR: not a valid index." >&2
  exit 1
fi

CHOSEN="${SNAPSHOTS[$((choice-1))]}"
echo
echo "About to restore: $CHOSEN"
echo "         onto:   $LIVE_DB"
echo "This will stop $SERVICE + $WORKER, replace the live DB, and restart both."
read -rp "Proceed? [yes/NO]: " confirm
if [[ "$confirm" != "yes" ]]; then
  echo "Aborted."
  exit 0
fi

TS=$(date +%Y%m%d-%H%M%S)
PRE_RESTORE="${LIVE_DB}.pre-restore-${TS}"

echo
echo "[1/5] Stopping $SERVICE + $WORKER …"
systemctl stop "$SERVICE" "$WORKER"

echo "[2/5] Side-copying current DB to ${PRE_RESTORE} (rollback safety net) …"
if [[ -f "$LIVE_DB" ]]; then
  cp -a "$LIVE_DB" "$PRE_RESTORE"
else
  echo "      (no live DB present — fresh restore)"
fi

echo "[3/5] Copying snapshot into place …"
install -m 0640 -o ubuntu -g ubuntu "$CHOSEN" "$LIVE_DB"

echo "[4/5] Ensuring ownership on data dir …"
chown -R "$OWNER" /home/ubuntu/.MobInspect

echo "[5/5] Restarting $SERVICE + $WORKER …"
# PartOf= only propagates stop/restart, never start — start the worker explicitly
# or async scans (MOBINSPECT_ASYNC_ANALYSIS=1 is the prod default) will queue forever.
systemctl start "$SERVICE" "$WORKER"

echo
echo "Restore done. Recent journal:"
journalctl -u "$SERVICE" --no-pager -n 20 || true
echo
echo "If the service does not become healthy, roll back with:"
echo "  sudo systemctl stop $SERVICE $WORKER"
echo "  sudo install -m 0640 -o ubuntu -g ubuntu $PRE_RESTORE $LIVE_DB"
echo "  sudo systemctl start $SERVICE $WORKER"
