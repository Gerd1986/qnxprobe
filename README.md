# qnxprobe

Read QNX6, QNX4, ETFS, EFS, ext2/3/4, F2FS, FAT32, exFAT, NTFS, HFS+ and APFS filesystems,
the Linux flash filesystems SquashFS, JFFS2, UBI/UBIFS and YAFFS1/YAFFS2, and QNX IFS boot
images, out of raw disk images and flash dumps: identify each by its own on-disk structure
rather than trusting a partition type byte, list, and extract to a zip with a
provenance manifest. No mounting, no admin rights, standard library only.

QNX is what a lot of vehicle infotainment runs on, and it is the reason this tool
exists and keeps its name. When a head unit image lands on your desk, the first
question is what filesystems are in it, and the usual tools do not answer it:
`blkid`, `file` and The Sleuth Kit have no QNX6 support, and the partition table
will happily call a qnx6 volume `0x83 Linux`. This reads the superblock and tells
you what is actually there, then lists and extracts what it found. It reads
ext2/3/4 the same way, so a mixed vehicle landscape (Ford runs QNX, BMW runs
Linux) is one tool rather than two.

It also reads QNX's two flash filesystems, ETFS and EFS, the kind a head unit
keeps its manufacturing and configuration data on. Both are typically imaged bare
with no partition table, so they arrive as the whole image and are read at LBA 0.
ETFS has no superblock at all, so it is rebuilt by replaying the transaction
records in each page's spare area; EFS is found by its `QSSL_F3S` boot record.
Their byte layouts are transcribed from the Kaitai specs in
[NetherlandsForensicInstitute/qnxmount](https://github.com/NetherlandsForensicInstitute/qnxmount)
(Apache-2.0), whose ETFS spec is itself sourced to QNX's `fs/etfs.h` and whose EFS
spec to `fs/f3s_spec.h`, and both readers are validated by round-trip against
qnxmount's own committed test images.

It also reads QNX4, the filesystem of QNX 4 systems, still met on older embedded
and industrial gear. The MBR type bytes `0x4d/0x4e/0x4f` announce a QNX4
partition but never prove one; this reads the actual structure, the `/` root
inode that doubles as the `0x002f` magic, and walks it the way the Linux
kernel's own read-only `fs/qnx4` driver does, inline 64-byte inode entries,
long names resolved through `.inodes` links, and multi-extent files through
their `IamXblk` chains. The reader is validated by round-trip against that
kernel driver on a populated fixture; see
[Where the constants come from](#where-the-constants-come-from).

It also reads QNX IFS boot images, the compressed boot filesystem behind a head
unit's `ifs_*` partitions, holding the kernel, the boot drivers and the startup
scripts. The image filesystem is UCL-compressed, which is not in the standard
library, so a small pure-Python UCL NRV2B decoder is carried in the file rather
than taken as a dependency: the tool still installs nothing. The format and the
decompression are sourced from QNX's own `dumpifs` and `sys/image.h`, and the
decoder is proven byte for byte against the three Ford Sync G4 IFS volumes (each
decompresses to exactly the size its header records and the image checksum
balances). See [What it does not do](#what-it-does-not-do) for the compression
methods it recognises but does not yet read.

It also opens BitLocker volumes with their password, recovery password or startup key
(`.BEK`) file, and reads the NTFS, FAT32 or exFAT inside them; without a key it names
the volume, its protectors and what would open it. See [BitLocker](#bitlocker).

It also opens an APFS volume macOS encrypted in software (an external drive, or a Mac
without a T2 chip or Apple silicon) with its password or personal recovery key; without
one it names the volume, says what would open it and gives the passphrase hint the volume
stores. See [Opening an encrypted APFS volume](#opening-an-encrypted-apfs-volume).

It also reads the filesystems embedded Linux keeps on flash: SquashFS, JFFS2, UBI and the
UBIFS inside it, and YAFFS1 and YAFFS2. They are what routers, cameras, drones and Linux
head units tend to carry, often as a chip dump with no partition table and sometimes with
the NAND spare bytes still between the pages. Each is found by its own headers inside such
a dump and read the way the Linux kernel (for YAFFS, Aleph One's own code) reads it. LZO
and LZ4, which the standard library lacks, are carried as small pure-Python decoders. See
[Linux flash filesystems](#linux-flash-filesystems). A U-Boot environment or a Belkin
libnvram store found on the chip is handed over as a one-file volume holding its bytes (see
[Raw flash dumps and NAND spare bytes](#raw-flash-dumps-and-nand-spare-bytes)).

One file, Python 3 standard library only. Nothing to install, no admin rights, and
it never writes to the image. A second, optional file, `qnxprobe_gui.py`, puts a
window over it (see [The window](#the-window)); it is standard library too.

## Requirements

Python 3, and nothing else. No packages, no install step.

Reading zstd-compressed SquashFS or UBIFS needs Python 3.14 or later, whose standard
library adds `compression.zstd`. On an older Python those files are named and reported as
not read (see [What it does not do](#what-it-does-not-do)). The
[executables](#executables) carry their own Python 3.14, so they read zstd wherever they
run; those published with v1.31 and v1.32 were built on 3.12 and do not.

Run and self-tested on 3.10, 3.12 and 3.14. It uses no syntax newer than 3.8 and
parses cleanly under 3.8 and 3.9, but it has not been run there.

## Quick start

```
python3 qnxprobe.py mmcblk0.img            # one image
python3 qnxprobe.py *.img *.bin            # several at once
python3 qnxprobe.py partition2.dd          # a partition already carved out
python3 qnxprobe.py --self-test            # prove it reports both ways
python3 qnxprobe.py --help                 # every option, with sourcing
```

## The window

`qnxprobe_gui.py` is a tkinter front end for people who would rather not use a
terminal. It needs the same Python and nothing else; tkinter ships with the
standard Python installers on macOS and Windows and with the `python3-tk` package
on most Linux distributions.

```
python3 qnxprobe_gui.py                 # open the window
python3 qnxprobe_gui.py mmcblk0.img     # open it with an image already added
```

Add one or more images, set the same options the command line takes, and press
**Run report** or **Extract to zip**. Both run `qnxprobe.py` as a subprocess and
stream its output into the Report pane as it is printed, so the report in the
window is byte for byte the report the command line prints. During an extraction
the progress bar is driven by the tool's own `--progress` stream, with exact file
and byte counts per volume. Cancel stops the subprocess; a zip left behind by a
cancelled run is not a complete extraction and the window says so.

The **Contents** pane browses an image without extracting it. It opens the image
read-only, finds each volume with the same partition-table and superblock code
the report uses, and walks it with the same reader classes the extractor uses.
Directories load when you expand them, and a selected file can be saved out on
its own. The Kind column tells regular files from directories, symlinks and
special entries; only regular files can be saved. Created and Accessed are filled
for NTFS, which stores all three times as instants; the other readers carry only
Modified, so those two columns stay blank for them. A FAT32 or exFAT file has no
instant at all: its (UTC) columns stay blank and its readings appear in **Recorded
(as stored)**.

The two halves are kept honest against each other by a check you can run on any
image, with no window:

```
python3 qnxprobe_gui.py --check-discovery mmcblk0.img
```

It runs the report, reads back which volumes it named and what it called each
one, and requires the Contents pane's own discovery to name exactly the same
set. It was run on the 12 synthetic self-test images, qnxmount's four reference
images, a Ford Sync G4 eMMC image (9 volumes) and a BMW MGU image (11 volumes)
before this was published, and all agreed. A qnx6 found only by the brute scan
is reported but has no partition to walk, so it appears in the report and not in
the Contents pane, in the window exactly as on the command line.

## Executables

For a machine with no Python, the repository's GitHub Actions workflow
(`.github/workflows/build-executables.yml`) builds both files into standalone
executables with PyInstaller on Python 3.14, `qnxprobe` for the command line and
`qnxprobe_gui` for the window, on six targets: Windows x64 and arm64, macOS on Apple
silicon and Intel, and Linux x64 and arm64. Each build runs the self-test, the discovery
check, a check that the command line executable extracts every file of the zstd SquashFS
fixture with the bytes it was built from, and a window liveness check on its own runner
before it is packaged with
`SHA256SUMS.txt` and a README. The executables are not code signed; the README
inside each archive says what Windows SmartScreen and macOS Gatekeeper will ask.
They are published on the release for a `v*` tag and are otherwise available as
workflow artifacts.

## What a run looks like

```
==============================================================================
synthetic.img
  7,340,032 bytes (7.0 MiB)
==============================================================================
  MBR      valid, 1 entries
    1  type 0xb1  LBA 2,048           4.0 MiB

  2 magic match(es): 2 CONFIRMED, 0 rejected as coincidence

  CONFIRMED qnx6 filesystem on MBR part 1  [little endian]
      2 superblock copies, 2 generations

      ACTIVE   serial 41   at 0x102000
        sb_ctime   2018-03-19 15:00:25 UTC
        sb_atime   2024-04-04 09:27:48 UTC
        version    4.3   blocksize 4,096   flags 0x00000000
        volume     4.0 MiB  (1,020 blocks, 966 free)   <- 99.6% of the 4.0 MiB partition
        inodes     20,000 total, 15,000 free, 5,000 used

      PREVIOUS serial 40   at 0x102e00   (still on disk)
        sb_ctime   2018-03-19 15:00:25 UTC
        sb_atime   2024-04-04 09:27:46 UTC

      WHAT CHANGED between the two generations
        serial       +1   (one commit)
        sb_atime     +2 s   (forward 2 seconds)
        free_blocks  -1  (1 block allocated)
        free_inodes  -1  (1 inode allocated)

  VERDICT: QNX6 filesystem present.
```

That output is from a synthetic image built by the self-test code, so nothing in it
came off a real device.

## Reading the timestamps

This is the part worth getting right, because it is easy to report the wrong thing.

- **`sb_ctime`** is written once, when the filesystem is created. It does not move.
- **`sb_atime`** moves when the filesystem is **committed**, not when a file is read.
  Do not read it as when the device was last used by a person.
- **`serial`** counts commits. It is the better measure of how much a volume has
  been written.

A qnx6 volume carries four superblock copies, and the tool groups them into
generations. The highest serial is the active one; the one below it is the previous
committed state, still on disk. The `WHAT CHANGED` block diffs the two, so you can
see what a single commit did.

## Deciding what to pull first

A head unit runs to tens of gigabytes and most of it is not evidence.

```
python3 qnxprobe.py --triage mmcblk0.img
```

## What an extraction is named, and how to check it

Every volume extracts under a directory named from the partition table, not from
the filesystem:

```
p2_lba65536                MBR primary 2
p6_lba13168672             second logical volume (logicals number from 5, as OSes do)
p3_lba16384_dps_mfg        GPT partition 3, carrying its name
lba0                       no partition table: a whole-disk filesystem or bare region
```

The LBA is the identity. It is a physical fact about the image that any partition
tool reproduces, and two volumes cannot share one, so names cannot collide. A
label is only ever a suffix. An LBA counts the disk's own logical sectors: 512
bytes on most disks, and 4096 on a disk whose GPT header sits at byte 4096, as on
4Kn drives and UFS LUN images, so `p1_lba300` on such a disk begins at byte
1,228,800.

The zip also carries `volumes.json`: per volume, the LBA and the sector size it
counts in (`sector_bytes`), byte offset, partition size, filesystem type, the recorded volume id or UUID, and what was extracted,
including `short` (files whose blocks reach past the end of the image), `failed`
(files that could not be read, which are not in the zip) and, on a
volume that does, `extends_past_image_by_bytes`. On a split image `image` names the
first segment and `image_segments` lists every segment joined, with its byte count;
on a virtual disk read over a parent, `image_parents` lists each parent's files, nearest
first, with theirs.
For a bare image with no vendor export alongside it, that file is the record
tying every extracted path back to a place on the disk, checkable against
`mmls` or `fdisk` without trusting the directory names.

`--triage` ranks the volumes by how much each has been written, using only what the
probe already read: the qnx6 superblock serial is a commit counter, and ext exposes
mount count and lifetime kilobytes written. It also samples filenames and says so
when they are encrypted, because a volume whose names are encrypted will not yield
to any parser without the keys.

Read the fill percentage alongside the ranking rather than sorting on size. Two
results from real vehicles, both counter-intuitive:

- On a 2024 BMW MGU the busiest volume on the disk was 36% encrypted filenames in a
  sample, so the ranking's top entry was the one least worth extracting.
- On a Ford Sync G4 the 4 MiB manufacturing volume ranked last with 16 commits, and
  it is the one holding the unit's Bluetooth and WiFi addresses, serials and TLS
  keys.

Activity finds the user data. It does not measure value per byte.

## Listing and extracting, without mounting

You do not need to mount anything. macOS ships 18 filesystems and qnx6 is not one of
them, the WSL2 kernel is built with `CONFIG_QNX6FS_FS` unset, and the free FUSE
options are Linux only. So the tool reads the filesystem directly instead.

```
python3 qnxprobe.py --list mmcblk0.img                      # walk and print the tree
python3 qnxprobe.py --list --depth 4 --list-max 3000 img    # deeper, higher cap
python3 qnxprobe.py --extract case.zip mmcblk0.img          # everything, into one zip
python3 qnxprobe.py --extract storage.zip --only storage img   # one volume by name
python3 qnxprobe.py --extract case.zip --exclude ECRYPTFS img  # leave out what will not parse
python3 qnxprobe.py --extract case.zip mmcblk0.img.001        # any segment of a split image; the set is joined
```

`--list` walks qnx6 through the same block resolution the kernel uses in
`qnx6_block_map()`, including multi-level indirect trees and long filenames held out
of line in the Longfile tree, and walks ext through its extent trees, or through the
classic block map of ext2 and ext3 (twelve direct pointers, then single, double and
triple indirect blocks). Both read-only.

A file is read by logical block, so a sparse file comes out at its declared size
with zeros where its holes are, and an extent the kernel wrote as uninitialized
reads as zeros too. That matters on an Android image: SQLite's `-shm` files and
MMKV stores are sparse, and a reader that concatenates the allocated blocks hands
back a shorter file with its pages in the wrong order. The two ext fixtures under
`tests/fixtures/` hold a hole first, a hole in the middle, a trailing hole past the
last block, a file that is nothing but hole and a 3 MiB file with data at both ends,
built with `mke2fs -d` from one tree (`tools/make_ext_fixtures.sh`); the self-test
requires every one to hash to what `sha256sum` recorded over that tree. A file whose
data is inline in its inode is read when it fits the inode's 60 bytes and refused,
by name, when the rest lives in an extended attribute this does not read.

The zip `--extract` produces is what a LEAPP tool ingests, so this replaces the mount
and the manual zip in one step. `--exclude` is repeatable.

Each file is read in full before anything of it is written to the zip, because a zip
member cannot be taken back once written. A file whose read raises partway (in the
self-test, a UBIFS data node that reads as erased flash) is left out of the zip
entirely: the report counts it as `FAILED` and prints
`could not extract <path>: <reason>` for the first five on each volume, and
`volumes.json` counts it under `failed`.
There is no member for it, under its own name or a marker. Before 1.53 such a file
could reach the zip holding only the bytes read before the error, under its real
name, where it looked like an ordinary, shorter file. A file whose blocks reach past
the end of the image is still stored, under a name ending
`.SHORT-<here>-of-<size>-bytes` (see "What it does not do"), and since 1.53 that name
is given on every volume, not only on one the partition table already shows is cut.
A file larger than 32 MiB is held in a temporary file while it is read, so extraction
needs that file's size free in the system's temporary folder.

## Reading an image from Python

Everything the command line does is reachable by importing the file, and the
entry point is `volumes()`, the callable form of the discovery the report does
while it prints. The window's Contents pane and the LEAPP tools read images
through it, and `qnxprobe_gui.py --check-discovery IMAGE` proves that it names
the same volumes the report does, on any image you give it.

```python
import qnxprobe as q

segments = q.split_segments(path)          # the .001/.002 set beside a segment, or None
image = q.open_image(path, segments)       # a plain file, a joined set, or an acquisition
for vol in q.volumes(image):
    print(vol["name"], vol["kind"], vol["label"], vol["missing_past_end"])
    walker = vol.get("walker")            # None when the kind is not one this reads
    if walker is None:
        print("   ", vol["note"])
        continue
    for path, ino, size, mtime in q.collect(walker, walker.root):
        if size is None:                   # a symlink or special file
            continue
        for chunk in walker.read_file(ino, size):
            ...                            # the file's bytes, streamed
image.close()
```

Each dict names the region as the report does (`label`), gives its byte offset and
length (`base`, `size`) and its sector (`lba`, in the disk's logical sectors), the
directory an extraction uses
(`name`, see [What an extraction is named](#what-an-extraction-is-named-and-how-to-check-it)),
the filesystem (`kind`, or `not recognised`, or `extended container` for the MBR
entry that holds logical volumes) and, when the image holds only part of the
volume, `missing_past_end`, the bytes of it that lie past the end of the file. That
last field is how a lone first segment of a split image shows itself. FAT32 and
exFAT walkers hand back readings rather than instants for their times, as
described under [FAT32 and exFAT times](#fat32-and-exfat-times-are-readings-and-are-listed-as-such);
pass a dict as `times` to `collect()` to receive them.

`allocation(walker, ino)` (since 1.56) says what the volume stores for one file beside
the size it records, and whether it is a cloud placeholder with no content to read; see
[What a file stores](#what-a-file-stores-cloud-placeholders-and-overlay-compression).

`volumes()` reads only what identification needs. The walk and the reads happen
when you ask for them, so a consumer that wants a few files out of a 250 GiB disk
never touches the rest.

### Listing a whole volume

`collect()` returns the regular files in tree order, which is what an extraction
needs. Something that wants **everything**, directories included, should ask
`walk_all()` instead, because it takes a faster route where one exists.

```python
for path, node, mode, size, mtime, recorded in q.walk_all(walker):
    ...                                    # every file, directory, link and node
```

On NTFS it builds the listing from one sequential pass over `$MFT` rather than
from the directory indexes, and on APFS it reads the file-system tree's leaves
once rather than searching it per lookup. Measured on this Mac:

| | tree walk | `walk_all()` |
| --- | ---: | ---: |
| 7.4 GB Windows E01, 156,894 entries | 6.9 s | 2.0 s |
| 32 GB macOS E01, 625,543 entries | 147.0 s | 8.0 s |

The APFS route trades memory for it, roughly 900 MB on that 625,543-entry
volume, and a volume larger than `APFS_PRIME_MAX_RECORDS` is walked the
ordinary way instead of held.

Since 1.30. `walk_all()` **does not promise an order**, and on NTFS it answers a slightly
different question: it reads what each record says about itself rather than what
each directory says is in it. The two agree on every consistent volume measured
and differ on 4 entries of 313,652 on one acquisition where the volume's own
index and records disagree, and on 3 on another. `NtfsWalker.listing` says which
and what is known about why. `collect()` is unchanged.

## QNX6 free space

Since 1.58 `Qnx6Walker.free_extents()` reports the space a qnx6 volume says is free, as
`(byte offset into the image, length)` runs. It is the call the F2FS, FAT32, exFAT, NTFS,
HFS+ and APFS walkers already answer, so a carve can be scoped to free space on a qnx6
volume the same way.

```python
import qnxprobe as q

image = q.open_image(path)
for vol in q.volumes(image):
    if vol["kind"] != "qnx6" or vol.get("walker") is None:
        continue
    for offset, length in vol["walker"].free_extents(min_bytes=1 << 20):
        data = q.read_at(image, offset, min(length, 1 << 20))   # the run's first bytes
image.close()
```

The bitmap is a tree under the Bitmap root node of the superblock, the second root node
of `struct qnx6_super_block`
([qnx6_fs.h line 111](https://github.com/torvalds/linux/blob/d56b699d76d1b352f7a3d3a0a3e91c79b8612d94/include/linux/qnx6_fs.h#L111)). The kernel's description of
it ([qnx6.rst lines 156 to 165](https://github.com/torvalds/linux/blob/d56b699d76d1b352f7a3d3a0a3e91c79b8612d94/Documentation/filesystems/qnx6.rst#L156-L165))
gives one bit per block, block 0 where file blocks start, and the bits past the last
block set. It does not say which bit value means in use or which end of a byte is counted
first, and the Linux driver, which has no write path, never reads the bitmap. Both were
measured, on the four qnx6 volumes at hand: qnxmount's reference image and the three qnx6
partitions of a Ford Sync G4 image. Live blocks below are every block named by the
superblock's root nodes and by every inode whose status is directory or normal file.

| volume | blocks | block size | free runs | free blocks | `sb_free_blocks` | live blocks | live blocks inside a free run | the same, most significant bit first |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| qnxmount `test_image.bin` | 384 | 1,024 | 2 | 339 | 339 | 38 | 0 | 5 |
| Sync G4 `dps_mfg` | 1,020 | 4,096 | 2 | 965 | 965 | 50 | 0 | 4 |
| Sync G4 `dps_os` | 6,140 | 4,096 | 3 | 6,055 | 6,055 | 59 | 0 | 2 |
| Sync G4 `storage` | 7,541,755 | 4,096 | 5,422 | 3,716,776 | 3,716,776 | 3,822,697 | 0 | 10,445 |

A set bit is a block in use, and bit 0 is the least significant bit of byte 0. Read that
way the clear bits equal the superblock's own `sb_free_blocks` on all four volumes and no
live block is clear. The count cannot settle the bit order (on the reference image both
orders give 339); position does, and read from the top of each byte live blocks fall in
free space on every volume. A second qnx6 reader, written independently of this one,
names the same set of free blocks on the three volumes it opens, and its dump of them is
byte-identical by SHA-256 on the two small ones.

Live and free blocks do not add up to the volume. 7, 5, 26 and 2,282 blocks are marked in
use and named by no live inode or root node. qnx6.rst describes a preallocated system
area in the bitmap; whether that accounts for them was not established. They are not
reported as free.

The bitmap read is the one of the superblock the walker was opened on, the newest
generation. Blocks that only the previous generation's trees name can be clear in it (1,
1 and 7 blocks on the three volumes that hold two generations), so a reported run can
hold what the last commit replaced.

Nothing is reported unless the whole bitmap can be read and its clear bits equal
`sb_free_blocks`. A bitmap that is cut short by a partial image, shorter than the volume
needs, not mapped, or at odds with its superblock returns an empty list, which is "no
answer" and not "nothing free". The walker reads little-endian volumes; all four
measured are little endian.

## Writing free space to files

Since 1.58 `--unallocated DIR` copies out the free space of every volume whose filesystem
says what is free: qnx6, F2FS, FAT32, exFAT, NTFS, HFS+ and APFS.

```
python3 qnxprobe.py --unallocated free_space --only dps_mfg mmcblk0.img
```

For each such volume it writes `<image>.<volume>.unallocated.bin`, the free runs one after
another, and a `.tsv` beside it with one line per run: where the run starts in that file,
where it came from in the image, and its length. A carve hit at an offset in the `.bin`
maps back to the disk through that table. `unallocated.json` lists every volume looked at,
what was done with it, and the SHA-256 of each file written. Offsets are into the image
as qnxprobe reads it, so for an E01, an AFF, a disk image or a split set they are offsets
into the disk and not into the container file.

What it writes and what it leaves out:

- **A filesystem that does not report free space gets no file.** ext2/3/4, QNX4, ETFS,
  EFS, SquashFS, JFFS2, UBI/UBIFS, YAFFS and QNX IFS readers have no free-space call. The
  volume is listed as `not written: the ext4 reader does not report free space`.
- **An empty answer gets no file, and is not called "nothing free".** A reader returns
  the same empty list when it cannot read its allocation map and when the volume is full,
  so the status is `no free space reported (the allocation map could not be read, or
  nothing is free)`.
- **A run past the end of a partial image is cut there.** The FAT32 reader, on an image
  cut short, reports clusters past the end of the file as free. On the committed FAT32
  fixture cut to 3,000,000 bytes, 1.8 MiB was written and 61.1 MiB was counted as lying
  past the end and not written.
- **An APFS container's free space is the container's**, not one volume's, so it is one
  file per container. It is copied as stored: blocks an encrypted volume wrote there stay
  encrypted, with or without its password, and the output says when the container holds
  an encrypted volume.
- **A BitLocker volume that was opened is read through its decryption**, the same handle
  file reads use. No test image here pairs BitLocker with a filesystem that reports free
  space, so that path has not been run.
- **Space outside every recognised volume is not written.** Gaps between partitions,
  reserved partitions and an unpartitioned tail are no filesystem's free space.
- **Nothing is overwritten.** DIR must be new or empty, and a volume whose output would
  not fit in the room DIR has is listed and skipped.

`--only` applies, as it does to `--extract`. The output can be nearly as large as the
disk: the Ford Sync G4 `storage` volume has 3,716,776 free blocks, about 14.2 GiB.

On the two small qnx6 volumes measured above (qnxmount's reference image and Sync G4
`dps_mfg`) the `.bin` is byte-identical, by SHA-256, to the dump the second qnx6 reader
writes. One committed fixture per other filesystem was run through it: F2FS, FAT32, exFAT,
NTFS, HFS+ and APFS each wrote a file, and the ext4 and SquashFS ones were listed as not
reporting free space.

From Python the same writer is `write_unallocated(fh, size, volumes(fh, size), out_dir,
image_name)`.

## APFS

Every Mac since 2017 is APFS, so `--list` and `--extract` read a container. It is
claimed by the `NXSB` magic in the first block's object header together with a block
size that is a power of two, and only reported once its newest checkpoint and object
map have been read far enough to name the volumes inside it.

A container holds several volumes, and on a Mac the user's data is not the first of
them, so the container is listed as a **directory whose children are its volumes**.
One walk reaches all of them and each file lands under its volume's name.

What it reads: the checkpoint with the highest transaction id whose Fletcher-64
checksum is right, the container and volume object maps, the file-system B-tree,
directory records, inodes and their extended fields, file extents including sparse
ones, symbolic links, and files compressed with the `decmpfs` attribute in its zlib
forms.

What it does not do: an encrypted volume whose blocks are ciphertext in the image, and
which no password given opens (see below), is named, marked `encrypted and locked, not
read`, and not walked, and a file compressed with LZVN or LZFSE is listed with its size
and refuses to be read. Nothing here reads a snapshot: what is walked is the volume as
the newest checkpoint leaves it.

An encrypted volume is one whose flags lack `APFS_FS_UNENCRYPTED` (Apple File System
Reference, 2020-06-22, `apfs_superblock_t` and "Volume Flags"). Whether its blocks are
ciphertext in a given image is a separate question, and the volume's own blocks answer
it: when the root node of its file-system tree passes its Fletcher-64 checksum, the
image holds the volume decrypted, and it is read and marked `encrypted, read in the
clear`; when it does not, the volume is locked. An acquisition made through the Mac's
own decryption stores a volume that way: on Digital Collector 3.7's AFF4 of an Apple
silicon MacBook Pro, whose log says it enabled "crypto I/O" for the encrypted Data
volume, that volume reads in the clear, and 198 of 200 property lists read from it
parse (one is LZVN-compressed, one holds a date Python cannot represent). Before 1.44
both kinds were walked as though they were plain: the one in the clear happened to
read, and a locked one was missing from listings with nothing saying why. A report
and `volumes()` now say which is which, in a `note` beside the volume list.

The self-test reads an image `tools/make_apfs_encrypted_fixture.sh` builds on any Mac:
a plain volume, and a volume `diskutil` encrypted with a test passphrase, which APFS
encrypts in software. The plain volume's files must match what macOS wrote and the
encrypted one must be named locked with its tree never parsed. The in-the-clear case is
built from the plain fixture by clearing the flag and sealing the superblock's
checksum again, and must read every entry; with the tree's root node replaced by noise,
the same volume must read as locked.

### Opening an encrypted APFS volume

Since 1.50 an encrypted APFS volume whose blocks are ciphertext in the image opens with
its password or its personal recovery key, given the way any password is
(`--password-file FILE` or `--password-env NAME`, repeatable, each tried against every
such volume), and is then listed and extracted like any other. The report marks it
`encrypted, opened with a password`, and the note says so. Without a key that …30950 tokens truncated…t=mono)
    ys = ttk.Scrollbar(rep, orient="vertical", command=text.yview)
    xs = ttk.Scrollbar(rep, orient="horizontal", command=text.xview)
    text.configure(yscrollcommand=ys.set, xscrollcommand=xs.set, state="disabled")
    text.grid(row=0, column=0, sticky="nsew")
    ys.grid(row=0, column=1, sticky="ns")
    xs.grid(row=1, column=0, sticky="ew")
    rep.rowconfigure(0, weight=1)
    rep.columnconfigure(0, weight=1)

    con = ttk.Frame(nb)
    nb.add(con, text="Contents")
    cbar = ttk.Frame(con, padding=(0, 6))
    cbar.pack(fill="x")
    ttk.Label(cbar, text="Image").pack(side="left")
    combo = ttk.Combobox(cbar, state="readonly", width=60)
    combo.pack(side="left", padx=6, fill="x", expand=True)
    b_load = ttk.Button(cbar, text="Load contents")
    b_load.pack(side="left")
    b_save = ttk.Button(cbar, text="Save selected file...", state="disabled")
    b_save.pack(side="left", padx=(6, 0))

    # Created and Accessed fill where the walker keeps instants for them, which
    # is NTFS through stamps(); every other reader carries only the modified
    # time, so those two stay blank there rather than show a date nothing read.
    # A FAT32 or exFAT walker keeps readings rather than instants, so for it
    # the three (UTC) columns stay blank and the readings go in the last column
    # as stored, the way GLEAPP's gallery shows the same file.
    tree = ttk.Treeview(con, columns=("kind", "size", "mtime", "created", "accessed", "recorded"),
                        selectmode="browse")
    tree.heading("#0", text="Name")
    tree.heading("kind", text="Kind")
    tree.heading("size", text="Size")
    tree.heading("mtime", text="Modified (UTC)")
    tree.heading("created", text="Created (UTC)")
    tree.heading("accessed", text="Accessed (UTC)")
    tree.heading("recorded", text="Recorded (as stored)")
    tree.column("#0", width=520, stretch=True)
    tree.column("kind", width=110, stretch=False)
    tree.column("size", width=110, anchor="e", stretch=False)
    tree.column("mtime", width=170, stretch=False)
    tree.column("created", width=110, stretch=False)
    tree.column("accessed", width=110, stretch=False)
    tree.column("recorded", width=420, stretch=False)
    tys = ttk.Scrollbar(con, orient="vertical", command=tree.yview)
    tree.configure(yscrollcommand=tys.set)
    tree.pack(side="left", fill="both", expand=True)
    tys.pack(side="right", fill="y")

    # ---- signature carving (independent read-only handle) -----------------
    import qnxprobe_carving as carving
    car = ttk.Frame(nb)
    nb.add(car, text="Carving")
    cb = ttk.Frame(car, padding=6)
    cb.pack(fill="x")
    ttk.Label(cb, text="Uses image selected in Contents; scans entire logical image.").pack(anchor="w")
    ttk.Label(cb, text="Contiguous candidates only; hits may belong to live files. No original names/timestamps.").pack(anchor="w")
    controls = ttk.Frame(cb)
    controls.pack(fill="x")
    types = {k: tk.BooleanVar(value=True) for k in carving.SIGNATURES}
    for kind, var in types.items():
        ttk.Checkbutton(controls, text=kind.upper(), variable=var).pack(side="left")
    ttk.Label(controls, text="Max MiB/file").pack(side="left")
    max_mib = tk.StringVar(value="64")
    ttk.Entry(controls, textvariable=max_mib, width=7).pack(side="left")
    cs = dict(hits={}, path=None, busy=False)
    cq = queue.Queue()
    stop_carving = threading.Event()
    carve_status = tk.StringVar(value="Ready")
    ttk.Label(cb, textvariable=carve_status).pack(anchor="w")
    ct = ttk.Treeview(car, columns=("offset", "size", "type", "validation"), show="headings")
    for col in ("offset", "size", "type", "validation"):
        ct.heading(col, text=col.title())
    ct.pack(fill="both", expand=True)

    def poll_carving():
        for _ in range(200):
            try:
                tag, value = cq.get_nowait()
            except queue.Empty:
                break
            if tag == "hit":
                iid = ct.insert("", "end", values=(hex(value["offset"]), value["size"], value["type"], value["validation"]))
                cs["hits"][iid] = value
            elif tag == "progress":
                carve_status.set(f"Scanning {value:.1%}; {len(cs['hits'])} candidates")
            else:
                cs["busy"] = False
                carve_start["state"] = "normal"
                carve_export["state"] = "normal"
                carve_status.set(str(value))
        if cs["busy"] or not cq.empty():
            root.after(50, poll_carving)

    def start_carving():
        path = combo.get()
        try:
            limit = int(max_mib.get()) * 1024 * 1024
            selected = [k for k, var in types.items() if var.get()]
            if not path or limit <= 0 or not selected:
                raise ValueError("Select an image, file types and a positive maximum size.")
        except ValueError as exc:
            messagebox.showerror("Carving", str(exc))
            return
        if not unlock(path):
            return
        cs.update(path=path, hits={}, busy=True)
        ct.delete(*ct.get_children())
        stop_carving.clear()
        carve_start["state"] = carve_export["state"] = "disabled"
        password = state["passwords"].get(path)
        key = state["aff_keys"].get(path)
        def work():
            try:
                with q.open_image(path, password=password, private_key=key) as fh:
                    for hit in carving.scan(fh, q.image_size(fh), selected, limit,
                                            stop_carving.is_set,
                                            lambda v: cq.put(("progress", v))):
                        cq.put(("hit", hit))
                cq.put(("done", "Cancelled (partial results)" if stop_carving.is_set() else "Scan complete"))
            except Exception as exc:
                cq.put(("error", str(exc)))
        threading.Thread(target=work, daemon=True).start()
        root.after(50, poll_carving)

    def export_carving():
        hits = [cs["hits"][i] for i in ct.selection()]
        if not hits:
            messagebox.showinfo("Carving", "Select one or more candidates first.")
            return
        folder = filedialog.askdirectory(title="Parent folder for a new carving export directory")
        if not folder:
            return
        import tempfile
        output = tempfile.mkdtemp(prefix="qnxprobe-carving-", dir=folder)
        path = cs["path"]
        password = state["passwords"].get(path)
        key = state["aff_keys"].get(path)
        cs["busy"] = True
        carve_start["state"] = carve_export["state"] = "disabled"
        def work():
            records = []
            error = None
            try:
                with q.open_image(path, password=password, private_key=key) as fh:
                    for hit in hits:
                        if stop_carving.is_set():
                            break
                        records.append(carving.export_hit(fh, hit, output))
            except Exception as exc:
                error = str(exc)
            try:
                with open(os.path.join(output, "carving.json"), "x", encoding="utf-8") as out:
                    json.dump(dict(image=os.path.abspath(path), hits=records,
                                   cancelled=stop_carving.is_set(), error=error), out, indent=2)
                cq.put(("done", f"Exported {len(records)} files to {output}" + (f"; {error}" if error else "")))
            except Exception as exc:
                cq.put(("error", str(exc)))
        stop_carving.clear()
        threading.Thread(target=work, daemon=True).start()
        root.after(50, poll_carving)

    carve_start = ttk.Button(controls, text="Scan", command=start_carving)
    carve_start.pack(side="left", padx=6)
    ttk.Button(controls, text="Stop", command=stop_carving.set).pack(side="left")
    carve_export = ttk.Button(controls, text="Export selected...", command=export_carving)
    carve_export.pack(side="left", padx=6)

    def refresh_image_combo():
        vals = list(images.get(0, "end"))
        combo["values"] = vals
        if vals and combo.get() not in vals:
            combo.set(vals[0])
        if not vals:
            combo.set("")

    def append_text(s):
        text.configure(state="normal")
        text.insert("end", s)
        text.see("end")
        text.configure(state="disabled")

    def clear_text():
        text.configure(state="normal")
        text.delete("1.0", "end")
        text.configure(state="disabled")

    # ---- subprocess driver ------------------------------------------------
    q_out = queue.Queue()
    q_con = queue.Queue()

    def build_args(extract):
        paths = list(images.get(0, "end"))
        if not paths:
            messagebox.showinfo("qnxprobe", "Add at least one image first.")
            return None
        args = probe_command() + ["--progress"]
        try:
            args += ["--scan-limit", str(int(v_scan.get()))]
            if v_list.get():
                args += ["--list", "--depth", str(int(v_depth.get())),
                         "--list-max", str(int(v_max.get()))]
        except ValueError:
            messagebox.showerror("qnxprobe", "depth, list-max and scan-limit must be whole numbers.")
            return None
        if v_triage.get():
            args.append("--triage")
        if v_only.get().strip():
            args += ["--only", v_only.get().strip()]
        for x in v_exclude.get().split(","):
            if x.strip():
                args += ["--exclude", x.strip()]
        if extract:
            zp = v_zip.get().strip()
            if not zp:
                messagebox.showinfo("qnxprobe", "Choose where the extraction zip goes.")
                return None
            if os.path.exists(zp):
                messagebox.showerror("qnxprobe", f"Refusing to overwrite an existing file:\n{zp}")
                return None
            args += ["--extract", zp]
        # An encrypted image's password goes to the subprocess in its environment,
        # never on its command line, where the process list would show it.
        for path in paths:
            if not unlock(path) or not unlock_volumes(path):
                return None
        env = dict(os.environ)
        given = [state["passwords"][p] for p in paths if p in state["passwords"]]
        given += [x for p in paths for x in state["bl_secrets"].get(p, [])]
        for n, secret in enumerate(given):
            env[f"QNXPROBE_PASSWORD_{n}"] = secret
            args += ["--password-env", f"QNXPROBE_PASSWORD_{n}"]
        for key in sorted({k for p in paths for k in state["bl_keys"].get(p, [])}):
            args += ["--bitlocker-key", key]
        for key in sorted({state["aff_keys"][p] for p in paths if p in state["aff_keys"]}):
            args += ["--private-key", key]
        state["child_env"] = env
        return args + paths

    def pump(stream, tag):
        for line in iter(stream.readline, b""):
            q_out.put((tag, line.decode("utf-8", "replace")))
        q_out.put((tag, None))

    def start(extract):
        args = build_args(extract)
        if args is None:
            return
        clear_text()
        shown = ["qnxprobe.py"] + args[args.index("--cli") + 1:]
        append_text("$ " + " ".join(a if " " not in a else f'"{a}"' for a in shown) + "\n\n")
        progress["value"] = 0
        status["text"] = "running..."
        for b in (b_report, b_extract):
            b["state"] = "disabled"
        b_cancel["state"] = "normal"
        try:
            state["proc"] = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                             env=state.pop("child_env", None))
        except OSError as exc:
            messagebox.showerror("qnxprobe", f"could not start qnxprobe.py: {exc}")
            finish()
            return
        state["open_streams"] = 2
        threading.Thread(target=pump, args=(state["proc"].stdout, "out"), daemon=True).start()
        threading.Thread(target=pump, args=(state["proc"].stderr, "err"), daemon=True).start()
        root.after(50, poll)

    def poll():
        try:
            while True:
                tag, line = q_out.get_nowait()
                if line is None:
                    state["open_streams"] -= 1
                    continue
                if tag == "out":
                    append_text(line)
                else:
                    try:
                        j = json.loads(line)
                        tb = j.get("total_bytes") or 0
                        if tb:
                            progress["value"] = 100.0 * j.get("bytes", 0) / tb
                        status["text"] = (f"{j.get('volume', '')}: {j.get('files', 0):,} of "
                                          f"{j.get('total_files', 0):,} files, "
                                          f"{q.human(j.get('bytes', 0))} of {q.human(tb)}")
                    except ValueError:
                        append_text(line)                # stderr that is not progress
        except queue.Empty:
            pass
        p = state["proc"]
        if p is not None and (p.poll() is None or state["open_streams"] > 0):
            root.after(50, poll)
            return
        rc = p.returncode if p is not None else None
        finish(rc)

    def finish(rc=None):
        for b in (b_report, b_extract):
            b["state"] = "normal"
        b_cancel["state"] = "disabled"
        if rc == 0:
            progress["value"] = 100
            status["text"] = "done"
        elif rc is None:
            status["text"] = "not started"
        elif rc < 0:
            status["text"] = "cancelled"
        else:
            status["text"] = f"qnxprobe.py exited {rc}"
        state["proc"] = None

    def cancel():
        p = state["proc"]
        if p is not None and p.poll() is None:
            p.terminate()
            append_text("\n[cancelled; a partial zip, if any, is not a complete extraction]\n")

    b_report.configure(command=lambda: start(False))
    b_extract.configure(command=lambda: start(True))
    b_cancel.configure(command=cancel)

    # ---- contents pane ----------------------------------------------------
    def close_image():
        if state["fh"] is not None:
            try:
                state["fh"].close()
            except OSError:
                pass
        state.update(fh=None, volumes=[], nodes={}, image_path=None)
        tree.delete(*tree.get_children())
        b_save["state"] = "disabled"

    def load_contents():
        path = combo.get()
        if not path:
            messagebox.showinfo("qnxprobe", "Add an image and pick it in the list.")
            return
        close_image()
        b_load["state"] = "disabled"
        status["text"] = f"reading {os.path.basename(path)} ..."

        if not unlock(path):                 # an encrypted image, its password refused
            done_loading()
            return
        if not unlock_volumes(path):         # a BitLocker or APFS volume's key asked for
            done_loading()
            return

        def work():
            # Tk is not thread safe, so the worker only reads; the result is
            # picked up by poll_contents() on the main thread.
            try:
                fh = q.open_image(path, password=state["passwords"].get(path),
                                  private_key=state["aff_keys"].get(path))
                fh, _found = q.unlock_bitlocker(fh, q.image_size(fh),
                                                state["bl_secrets"].get(path, []),
                                                state["bl_keys"].get(path, []))
                fh, _afound = q.unlock_apfs(fh, q.image_size(fh),
                                            state["bl_secrets"].get(path, []))
                q_con.put(("ok", path, fh, q.volumes(fh, q.image_size(fh))))
            except Exception as exc:
                q_con.put(("err", path, None, str(exc)))
        threading.Thread(target=work, daemon=True).start()
        root.after(50, poll_contents)

    def poll_contents():
        try:
            kind, path, fh, payload = q_con.get_nowait()
        except queue.Empty:
            root.after(50, poll_contents)
            return
        if kind == "ok":
            show_volumes(path, fh, payload)
        else:
            messagebox.showerror("qnxprobe", f"could not read {path}:\n{payload}")
            done_loading()

    def done_loading():
        b_load["state"] = "normal"
        status["text"] = "ready"

    def show_volumes(path, fh, vols):
        state.update(fh=fh, volumes=vols, image_path=path)
        for i, v in enumerate(vols):
            label = f"{v['label']}   {v['kind']}   ({v['name']})" if v["name"] else f"{v['label']}   {v['kind']}"
            if v.get("walker") is not None and v.get("note"):
                label += f"   [{v['note']}]"     # a walked volume that cannot be read here
            iid = tree.insert("", "end", text=label,
                              values=("volume", q.human(v["size"]), v.get("detail", "")[:60], "", "", ""),
                              open=False)
            w = v.get("walker")
            if w is not None:
                state["nodes"][iid] = (i, w.root, True, None)
                tree.insert(iid, "end", text="loading...", values=("", "", "", "", "", ""))
            else:
                tree.insert(iid, "end", text=v.get("note", "no contents"), values=("", "", "", "", "", ""))
        done_loading()
        if not vols:
            status["text"] = "no partition or volume found in this image"

    def expand(_event=None):
        iid = tree.focus()
        node = state["nodes"].get(iid)
        if node is None or not node[2]:
            return
        kids = tree.get_children(iid)
        if not (len(kids) == 1 and tree.item(kids[0], "text") == "loading..."):
            return
        tree.delete(*kids)
        vi, ino, _isdir, _ = node
        w = state["volumes"][vi]["walker"]
        try:
            readings = hasattr(w, "listdir_records")
            entries = list(w.listdir_records(ino)) if readings \
                else [(name, cino, None) for name, cino in w.listdir(ino)]
        except Exception as exc:
            tree.insert(iid, "end", text=f"could not list: {exc}", values=("", "", "", "", "", ""))
            return
        for name, cino, recorded in entries:
            ent = w.entry(cino)
            if not ent:
                continue
            mode, size, mtime = ent
            isdir = (mode & 0o170000) == q.S_IFDIR     # a block device shares the S_IFDIR bit
            islink = (mode & q.S_IFLNK) == q.S_IFLNK
            isreg = (mode & 0o170000) == 0o100000
            kind = "dir" if isdir else "link" if islink else "file" if isreg else "special"
            created = accessed = 0
            if hasattr(w, "stamps"):
                created, _modified, accessed = w.stamps(cino)
            cid = tree.insert(iid, "end", text=name,
                              values=(kind, "" if isdir else q.human(size),
                                      "" if readings else q._fmt_time(mtime),
                                      q._fmt_time(created) if created else "",
                                      q._fmt_time(accessed) if accessed else "",
                                      "; ".join(f"{k} {v}" for k, v in (recorded or {}).items() if v)))
            state["nodes"][cid] = (vi, cino, isdir, size if isreg else None)
            if isdir:
                tree.insert(cid, "end", text="loading...", values=("", "", "", "", "", ""))

    def selected(_event=None):
        node = state["nodes"].get(tree.focus())
        b_save["state"] = "normal" if node and not node[2] and node[3] is not None else "disabled"

    def save_file():
        iid = tree.focus()
        node = state["nodes"].get(iid)
        if not node or node[2] or node[3] is None:
            return
        vi, ino, _d, size = node
        w = state["volumes"][vi]["walker"]
        out = filedialog.asksaveasfilename(title="Save file as", initialfile=tree.item(iid, "text"))
        if not out:
            return
        try:
            n = 0
            with open(out, "wb") as f:
                for chunk in w.read_file(ino, size):
                    f.write(chunk)
                    n += len(chunk)
            status["text"] = f"saved {n:,} bytes to {out}"
            if n != size:
                messagebox.showwarning("qnxprobe", f"wrote {n:,} bytes but the entry records {size:,}")
        except Exception as exc:
            messagebox.showerror("qnxprobe", f"could not save: {exc}")

    tree.bind("<<TreeviewOpen>>", expand)
    tree.bind("<<TreeviewSelect>>", selected)
    tree.bind("<Double-1>", lambda e: save_file() if b_save["state"] == "normal" else None)
    b_load.configure(command=load_contents)
    b_save.configure(command=save_file)

    def on_close():
        stop_carving.set()
        cancel()
        close_image()
        root.destroy()

    root.protocol("WM_DELETE_WINDOW", on_close)

    # Absolute from the start: the subprocess and the frozen build's re-entry
    # must not depend on whatever the working directory happens to be.
    for p in initial_paths:
        if os.path.exists(p):
            images.insert("end", os.path.abspath(p))
    refresh_image_combo()
    root.mainloop()


if __name__ == "__main__":
    argv = sys.argv[1:]
    if argv and argv[0] == "--cli":
        run_cli(argv[1:])
        sys.exit(0)
    if argv and argv[0] == "--check-discovery":
        paths = argv[1:]
        missing = [p for p in paths if not os.path.exists(p)]
        if not paths or missing:
            sys.exit("usage: qnxprobe_gui.py --check-discovery IMAGE [IMAGE ...]"
                     + (f"\nnot found: {', '.join(missing)}" if missing else ""))
        sys.exit(check_discovery(paths))
    run_window(argv)
