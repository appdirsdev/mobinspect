#!/usr/bin/env bash
# MobInspect — off-host backup stub (restic).
#
# This is intentionally a stub: the off-host repository, credentials, and
# bandwidth budget are deployment-specific and MUST be filled in per env.
# It exists so deploy/RUNBOOK.md has a single canonical place to point at
# for the off-host half of the DR plan (the on-host half is fully wired via
# mobinspect-backup.service + .timer).
#
# What it backs up:
#   - /var/backups/mobinspect/                  (hourly sqlite snapshots)
#   - /home/ubuntu/.MobInspect/secret           (Django SECRET_KEY)
#   - /home/ubuntu/.MobInspect/uploads/         (user-submitted APK/IPA originals)
#   - /home/ubuntu/.MobInspect/signatures/      (Yara/sig packs added in-place)
#
# To activate:
#   1. Install restic:                          sudo apt install restic
#   2. Create /etc/mobinspect/restic.env with at least:
#        RESTIC_REPOSITORY=s3:s3.amazonaws.com/<bucket>/mobinspect
#        RESTIC_PASSWORD_FILE=/etc/mobinspect/restic.password
#        AWS_ACCESS_KEY_ID=…
#        AWS_SECRET_ACCESS_KEY=…
#      chmod 0600 both files, owner root:root.
#   3. Initialize the repo once:                sudo restic init
#   4. Schedule daily (separate timer, not part of the hourly sqlite one):
#        sudo systemctl edit --force --full mobinspect-offsite.timer
#      pointing at this script.
#
# RPO target for the off-host copy: ≤ 24h (vs ≤ 1h for the local sqlite snapshots).

set -euo pipefail

ENV_FILE="/etc/mobinspect/restic.env"
if [[ ! -r "$ENV_FILE" ]]; then
  echo "ERROR: $ENV_FILE missing — see header comment for setup." >&2
  exit 1
fi
# shellcheck disable=SC1090
set -a; source "$ENV_FILE"; set +a

PATHS=(
  /var/backups/mobinspect
  /home/ubuntu/.MobInspect/secret
  /home/ubuntu/.MobInspect/uploads
  /home/ubuntu/.MobInspect/signatures
)

restic backup --tag mobinspect --tag "$(hostname -s)" "${PATHS[@]}"
restic forget --prune \
  --keep-hourly 24 --keep-daily 14 --keep-weekly 8 --keep-monthly 12
restic check --read-data-subset=5%
