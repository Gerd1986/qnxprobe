#!/bin/bash
# Build the APFS image with one plain and one encrypted volume that qnxprobe's
# self-test reads, and record what went into the plain one.
#
# Runs on macOS as an ordinary user. hdiutil creates a sparse image, and diskutil
# adds a volume encrypted with a passphrase, which APFS encrypts in software, so
# the encrypted volume's blocks are ciphertext on the image. The container is
# 1,100 MB because APFS allows one volume per 512 MiB of container; the sparse
# image holds only what was written.
#
# The passphrase is a test value made for this fixture, and the self-test opens the
# encrypted volume with it as well as reading it locked without it.
#
#     bash tools/make_apfs_encrypted_fixture.sh tests/fixtures
set -euo pipefail
OUT=${1:-tests/fixtures}
WORK=$(mktemp -d)
DISK=""
cleanup() {
  [ -n "$DISK" ] && hdiutil detach -quiet "$DISK" 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT
hdiutil create -quiet -size 1100m -type SPARSE -fs APFS -volname PLAINVOL \
  -layout GPTSPUD "$WORK/apfs-encrypted"
ATT=$(hdiutil attach -nomount "$WORK/apfs-encrypted.sparseimage")
DISK=$(echo "$ATT" | awk 'NR==1 {print $1}')
CONT=$(echo "$ATT" | awk '/EF57347C/ {print $1}' | head -1)
[ -n "$CONT" ] || { echo "no APFS container attached"; exit 1; }
printf 'qnxprobe-apfs-test' | diskutil apfs addVolume "$CONT" APFS SECRETVOL -stdinpassphrase >/dev/null
diskutil mount "${CONT}s1" >/dev/null
[ -d /Volumes/SECRETVOL ] || printf 'qnxprobe-apfs-test' | \
  diskutil apfs unlockVolume "${CONT}s2" -stdinpassphrase >/dev/null
for V in /Volumes/PLAINVOL /Volumes/SECRETVOL; do
  [ -d "$V" ] || { echo "$V is not mounted"; exit 1; }
  mkdir -p "$V/docs"
  printf 'known APFS test file in %s\n' "$(basename "$V")" > "$V/docs/readme.txt"
  python3 -c 'import sys; open(sys.argv[1], "wb").write(bytes((i * 131 + 17) % 253 for i in range(262144)))' \
    "$V/docs/pattern.bin"
done
# What the plain volume holds, which the self-test must read back; nothing is
# recorded for the encrypted one, whose blocks it must not read.
(cd /Volumes/PLAINVOL && shasum -a 256 docs/*) > "$OUT/apfs-encrypted.sha256"
diskutil apfs list | grep -A9 "Name:.*SECRETVOL" | grep -q "FileVault:.*Yes" || {
  echo "SECRETVOL is not encrypted"; exit 1; }
diskutil unmount /Volumes/SECRETVOL >/dev/null
diskutil unmount /Volumes/PLAINVOL >/dev/null
hdiutil detach -quiet "$DISK"
DISK=""
gzip -9 -n -c "$WORK/apfs-encrypted.sparseimage" > "$OUT/apfs-encrypted.sparseimage.gz"
ls -l "$OUT/apfs-encrypted.sparseimage.gz" "$OUT/apfs-encrypted.sha256"
