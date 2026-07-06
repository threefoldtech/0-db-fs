#!/bin/bash
# Remount / restore tests for 'autons': zdbfs must attach to namespaces that
# already exist instead of failing to create them.
#
# Scenarios:
#   1. remount   - mount, write, unmount, remount the same zdb: data intact
#   2. custom-ns - same cycle with mn=/dn=/tn= custom namespace names; also
#                  asserts the custom names actually exist on the zdb side
#                  (a fallback to default names would silently pass a pure
#                  data roundtrip)
#   3. transplant - stop zdb, copy index+data directories to a new location
#                  (a restore from backup), start a fresh zdb over the copy,
#                  mount: data intact
#
# Usage: ZDB=/path/to/zdb ZDBFS=/path/to/zdbfs tests/reattach.sh
set -e

ZDB=${ZDB:-zdb}
ZDBFS=${ZDBFS:-$(dirname "$0")/../zdbfs}
PORT=${PORT:-19800}

work=$(mktemp -d /tmp/zdbfs-reattach.XXXXXX)
zdbpid=""

cleanup() {
    set +e
    mountpoint -q "$work/mnt" && fusermount3 -u "$work/mnt"
    [ -n "$zdbpid" ] && kill "$zdbpid" 2> /dev/null && wait "$zdbpid" 2> /dev/null
    rm -rf "$work"
}
trap cleanup EXIT

zdb_start() {
    datadir="$1"
    indexdir="$2"

    "$ZDB" --port "$PORT" --data "$datadir" --index "$indexdir" \
           --logfile "$work/zdb.log" --mode seq &
    zdbpid=$!
    sleep 1
    kill -0 "$zdbpid"
}

zdb_stop() {
    kill "$zdbpid"
    wait "$zdbpid" 2> /dev/null || true
    zdbpid=""
}

zdbfs_mount() {
    nsopts="$1"

    "$ZDBFS" -o "autons,background,mh=localhost,mp=$PORT,dp=$PORT,tp=$PORT$nsopts" "$work/mnt"
    mountpoint -q "$work/mnt"
}

populate() {
    tag="$1"

    mkdir -p "$work/mnt/dir/sub"
    echo "hello reattach" > "$work/mnt/dir/file-a"
    dd if=/dev/urandom of="$work/mnt/dir/sub/file-b" bs=64k count=8 status=none
    ln -s file-a "$work/mnt/dir/link"
    (cd "$work/mnt" && find . -type f -exec md5sum {} \; | sort) > "$work/sums-$tag"
}

verify() {
    tag="$1"

    (cd "$work/mnt" && find . -type f -exec md5sum {} \; | sort) > "$work/sums.now"
    diff "$work/sums-$tag" "$work/sums.now"
    [ "$(readlink "$work/mnt/dir/link")" = "file-a" ]
}

mkdir -p "$work/mnt" "$work/zdb-data" "$work/zdb-index"

echo "[+] scenario 1: unmount / remount over existing namespaces"
zdb_start "$work/zdb-data" "$work/zdb-index"
zdbfs_mount ""
populate default
fusermount3 -u "$work/mnt"

zdbfs_mount ""
verify default
fusermount3 -u "$work/mnt"
echo "[+] scenario 1: OK"

echo "[+] scenario 2: custom namespace names survive the same cycle"
custom=",mn=custom-meta,dn=custom-data,tn=custom-temp"
zdbfs_mount "$custom"

# fresh namespaces: the mount must be empty; seeing scenario 1's tree here
# means the custom names were ignored and the default namespaces reused
[ -z "$(ls -A "$work/mnt")" ] || (echo "custom namespace mount is not empty" && false)

populate custom
fusermount3 -u "$work/mnt"

# the custom namespaces must exist server-side: zdb keeps one index
# directory per namespace
for ns in custom-meta custom-data custom-temp; do
    [ -d "$work/zdb-index/$ns" ] || (echo "namespace $ns was never created" && false)
done

zdbfs_mount "$custom"
verify custom
fusermount3 -u "$work/mnt"
echo "[+] scenario 2: OK"

echo "[+] scenario 3: restore transplanted index+data onto a fresh zdb"
zdb_stop
cp -r "$work/zdb-data" "$work/restored-data"
cp -r "$work/zdb-index" "$work/restored-index"
PORT=$((PORT + 1))
zdb_start "$work/restored-data" "$work/restored-index"

zdbfs_mount ""
verify default
fusermount3 -u "$work/mnt"
echo "[+] scenario 3: OK"

echo "[+] all reattach scenarios passed"
