#!/usr/bin/env python3
"""Turn what tools/make_ntfs_windows_fixture.cmd wrote into the committed fixture.

    python3 tools/finish_ntfs_windows_fixture.py <folder holding ntfs-known.vhd and results.txt>

Windows writes the volume and says what is in it; this only repackages both:

* the fixed VHD's 512-byte footer is dropped, which leaves the raw disk;
* the security descriptors Windows wrote name the writing machine's own
  security identifier (S-1-5-21-a-b-c-513, the primary group). Its three
  machine-specific numbers are replaced with 1-2-3 wherever that identifier
  occurs. Nothing the reader uses is touched: no file record, run list,
  reparse point or stream changes, and the count replaced is printed;
* results.txt becomes tests/fixtures/ntfs-windows.known.tsv: for each file, the
  length, attributes, size on disk and SHA-256 Windows reported, and whether
  Windows itself could read it. None of those values comes from qnxprobe.
"""
import gzip
import hashlib
import os
import re
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURES = os.path.join(os.path.dirname(HERE), "tests", "fixtures")
SID_HEAD = bytes.fromhex("010500000000000515000000")   # revision 1, five parts, S-1-5-21


def main(folder):
    with open(os.path.join(folder, "ntfs-known.vhd"), "rb") as fh:
        vhd = fh.read()
    if vhd[-512:-504] != b"conectix":
        raise SystemExit("not a fixed VHD: no footer in its last sector")
    print(f"VHD as Windows wrote it: sha256 {hashlib.sha256(vhd).hexdigest()}")
    raw = bytearray(vhd[:-512])
    machines, swapped = set(), 0
    for found in re.finditer(re.escape(SID_HEAD), bytes(raw)):
        at = found.start() + len(SID_HEAD)
        machines.add(bytes(raw[at:at + 12]))
        struct.pack_into("<III", raw, at, 1, 2, 3)
        swapped += 1
    if len(machines) > 1:
        raise SystemExit("more than one machine identifier in the image; look before publishing")
    print(f"machine identifier replaced in {swapped} security identifiers")

    with open(os.path.join(folder, "results.txt"), encoding="utf-8-sig") as fh:
        lines = fh.read().replace("\r", "").split("\n")
    system = next((x for x in lines if x.startswith("Microsoft Windows")), "Windows")
    # A file under the sync root is listed twice: once in the listing of the whole
    # volume, which does not read it, and once by name with a read attempted. The
    # second says more and is the one kept.
    known = {}
    for line in lines:
        part = line.split("\t")
        if len(part) < 5 or not part[1].isdigit() or not part[2].startswith("0x"):
            continue
        if part[0] in known and len(part) < 6:
            continue
        refused = len(part) > 5 and part[5].startswith("read refused")
        digest = part[4] if re.fullmatch(r"[0-9a-f]{64}", part[4]) else "-"
        known[part[0]] = (part[0], part[1], part[2], part[3], digest,
                          "refused" if refused else "read")
    rows = sorted(known.values())
    out = os.path.join(FIXTURES, "ntfs-windows.known.tsv")
    with open(out, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("# What Windows itself reported for each file of ntfs-windows.img, written by\n"
                 "# tools/make_ntfs_windows_fixture.cmd on " + system + ".\n"
                 "# length and attributes as the file API gives them, size on disk from\n"
                 "# GetCompressedFileSizeW, sha256 from Get-FileHash, and whether Windows could\n"
                 "# read the file with no cloud provider running. '-' is a file it could not hash.\n"
                 "# path\tlength\tattributes\tsize_on_disk\tsha256\twindows\n")
        for row in rows:
            fh.write("\t".join(row) + "\n")
    image = os.path.join(FIXTURES, "ntfs-windows.img.gz")
    with open(image, "wb") as fh:
        with gzip.GzipFile(fileobj=fh, mode="wb", compresslevel=9, mtime=0, filename="") as gz:
            gz.write(bytes(raw))
    print(f"{out}: {len(rows)} files")
    print(f"{image}: {os.path.getsize(image):,} bytes, raw sha256 "
          f"{hashlib.sha256(bytes(raw)).hexdigest()}")


if __name__ == "__main__":
    main(sys.argv[1])
