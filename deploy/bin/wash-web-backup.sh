#!/bin/bash
# Nightly wash-web backup: a sqlite dump (VACUUM INTO, consistent with a live WAL),
# never a file copy, plus the TLS key pair that enrolled washd's have pinned.
set -euo pipefail
DEST=/data/backups/wash
STAMP=$(date +%Y%m%d-%H%M%S)
KEEP=14

# /backup in the container is $DEST on the host
podman exec wash-web /wash-web backup "/backup/wash-$STAMP.db"
# losing tls/ means every user must re-run `wash enroll` (new fingerprint)
tar -C /data-active/wash -czf "$DEST/wash-tls-$STAMP.tar.gz" tls

find "$DEST" -name 'wash-*.db'         -mtime +$KEEP -delete
find "$DEST" -name 'wash-tls-*.tar.gz' -mtime +$KEEP -delete
