#!/usr/bin/env bash
# Build tests/fixtures/jffs2-le-lzma.img.gz with OpenWrt's LZMA-patched
# mkfs.jffs2, the writer of JFFS2 compression 0x08.
#
# Mainline mkfs.jffs2 has no LZMA compressor. OpenWrt adds one in
# tools/mtd-utils/patches/130-lzma_jffs2.patch, which also carries the LZMA SDK
# encoder, so the writer builds from mtd-utils 2.3.1 and OpenWrt's patches alone.
# Everything is fetched at a pinned commit and hash-checked. The build needs only
# gcc (no autotools, no zlib, no LZO): the compressors compiled in are LZMA and
# rtime, and rtime is switched off for the image.
#
# The image is written from make_jffs2_fixtures.sh's own source tree
# (ONLY=le-lzma), so it is checked against the same jffs2.src.sha256 and
# jffs2.src.stat as every other JFFS2 fixture.
#
# Runs on Linux with gcc, curl, bzip2 and patch.
set -euo pipefail

OPENWRT=d9f8ecc394dd30537d7136963fa4f6891b59c1ee
MTD=mtd-utils-2.3.1
MTD_SHA256=03d9dc58ad10ea3549d9528f6b17a44d8944e18e96c0f31474f9f977078b83dc  # OpenWrt's PKG_HASH
here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cd "$work"

curl -sfL -o "$MTD.tar.bz2" "https://infraroot.at/pub/mtd/$MTD.tar.bz2"
echo "$MTD_SHA256  $MTD.tar.bz2" | sha256sum -c -
tar xjf "$MTD.tar.bz2"
for p in 110-portability.patch 130-lzma_jffs2.patch 320-mkfs.jffs2-SOURCE_DATE_EPOCH.patch; do
    curl -sfL -o "$p" \
        "https://raw.githubusercontent.com/openwrt/openwrt/$OPENWRT/tools/mtd-utils/patches/$p"
    patch -d "$MTD" -p1 -s < "$p"
done

cd "$MTD"
printf '#define PACKAGE_VERSION "2.3.1-openwrt-lzma"\n#define VERSION PACKAGE_VERSION\n' > config.h
gcc -O2 -w -D_GNU_SOURCE -include config.h -DWITH_LZMA -Iinclude -Iinclude/linux/lzma -I. \
    -o "$work/mkfs.jffs2-lzma" \
    jffsX-utils/mkfs.jffs2.c jffsX-utils/compr.c jffsX-utils/compr_rtime.c \
    jffsX-utils/compr_lzma.c jffsX-utils/lzma/LzFind.c jffsX-utils/lzma/LzmaEnc.c \
    jffsX-utils/lzma/LzmaDec.c lib/libcrc32.c lib/common.c lib/rbtree.c \
    lib/libmtd.c lib/libmtd_legacy.c
compressors=$("$work/mkfs.jffs2-lzma" -L 2>&1 || true)   # -L lists them, then exits non-zero
[[ $compressors == *"lzma priority"* ]] || { echo "no lzma compressor built"; exit 1; }

MKFS_JFFS2_LZMA="$work/mkfs.jffs2-lzma" ONLY=le-lzma bash "$here/make_jffs2_fixtures.sh" "${1:-$here/../tests/fixtures}"
