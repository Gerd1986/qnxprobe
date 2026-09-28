#!/bin/bash
# Build the APFS image whose volume was encrypted after files were already on
# it, which qnxprobe's self-test unlocks with a password, and record what the
# volume holds.
#
# Runs on macOS as an ordinary user. hdiutil creates a sparse image with one
# plain volume; files are written to it; diskutil encrypts it in place with a
# passphrase (background encryption, waited for until it finishes), sets a
# passphrase hint, and one more file is written once it is encrypted. So the
# volume holds data encrypted by the conversion and data written encrypted.
#
# The passphrase and the hint are test values made for this fixture.
#
#     bash tools/make_apfs_converted_fixture.sh tests/fixtures
set -euo pipefail
OUT=${1:-tests/fixtures}
PASS='qnxprobe-apfs-convert'
HINT='the qnxprobe conversion test'
WORK=$(mktemp -d)
DISK=""
cleanup() {
  [ -n "$DISK" ] && hdiutil detach -quiet "$DISK" 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT
hdiutil create -quiet -size 600m -type SPARSE -fs APFS -volname CONVVOL \
  -layout GPTSPUD "$WORK/apfs-converted"
ATT=$(hdiutil attach -nomount "$WORK/apfs-converted.sparseimage")
DISK=$(echo "$ATT" | awk 'NR==1 {print $1}')
CONT=$(echo "$ATT" | awk '/EF57347C/ {print $1}' | head -1)
[ -n "$CONT" ] || { echo "no APFS container attached"; exit 1; }
VOLDEV="${CONT}s1"
diskutil mount "$VOLDEV" >/dev/null
V=/Volumes/CONVVOL
[ -d "$V" ] || { echo "$V is not mounted"; exit 1; }
mkdir -p "$V/docs"
printf 'known APFS test file in CONVVOL, written before encryption\n' > "$V/docs/readme.txt"
python3 -c 'import sys; open(sys.argv[1], "wb").write(bytes((i * 131 + 17) % 253 for i in range(262144)))' \
  "$V/docs/pattern.bin"
sync
printf '%s' "$PASS" | diskutil apfs encryptVolume "$VOLDEV" -user disk -stdinpassphrase >/dev/null
# background encryption: wait until diskutil stops reporting progress
for _ in $(seq 1 120); do
  diskutil apfs list "$CONT" | grep -q "Encryption Progress" || break
  sleep 1
done
diskutil apfs list "$CONT" | grep -q "Encryption Progress" && { echo "encryption did not finish"; exit 1; }
diskutil apfs list "$CONT" | grep -q "FileVault:.*Yes" || { echo "CONVVOL is not encrypted"; exit 1; }
diskutil apfs setPassphraseHint "$VOLDEV" -user disk -hint "$HINT" >/dev/null
printf 'written after the volume was encrypted\n' > "$V/docs/after.txt"
sync
(cd "$V" && shasum -a 256 docs/*) > "$OUT/apfs-converted.sha256"
diskutil unmount "$V" >/dev/null
hdiutil detach -quiet "$DISK"
DISK=""
gzip -9 -n -c "$WORK/apfs-converted.sparseimage" > "$OUT/apfs-converted.sparseimage.gz"
ls -l "$OUT/apfs-converted.sparseimage.gz" "$OUT/apfs-converted.sha256"
