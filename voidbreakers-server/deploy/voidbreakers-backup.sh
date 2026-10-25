#!/bin/sh
# Daily SQLite backup. Install with:  0 4 * * * /opt/voidbreakers-server/deploy/voidbreakers-backup.sh
set -eu
DB=/var/lib/voidbreakers/voidbreakers.db
DEST=/var/lib/voidbreakers/backups
mkdir -p "$DEST"
python3 - "$DB" "$DEST/voidbreakers-$(date +%F-%H%M).db" <<'PY'
import sqlite3, sys
src, dst = sys.argv[1], sys.argv[2]
con = sqlite3.connect(src)
bck = sqlite3.connect(dst)
con.backup(bck)
bck.close()
con.close()
print("backup written:", dst)
PY
find "$DEST" -name 'voidbreakers-*.db' -mtime +14 -delete
