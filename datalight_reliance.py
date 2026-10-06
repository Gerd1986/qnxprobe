#!/usr/bin/env python3
"""
Datalight FlashFX/VBF + Reliance Nitro end-to-end directory-tree reconstructor
for the supplied raw NAND geometry.

INPUT (observed in the supplied chip.dmp)
-----------------------------------------
Raw NAND page: 4320 bytes
  10 bytes FlashFX/OOB metadata
  8 x:
      512 bytes main data
       26 bytes interleaved ECC
   6 bytes trailing spare
= 4096 bytes logical main data + 224 bytes redundant data

Erase unit: 128 raw pages.

PIPELINE
--------
raw NAND
  -> deinterleave 4096-byte main pages
  -> parse DL_FS4.00 FlashFX unit headers
  -> rebuild current FlashFX/VBF logical-page mapping
  -> optionally write standalone FlashFX/VBF logical images
  -> find Reliance Nitro MAST volumes
  -> optionally write each Reliance Nitro volume as its own logical image
  -> choose newest META
  -> META -> IDIR
  -> current IDIR/LDIR directory tree
  -> decode parent object IDs + filename fragments
  -> create recovered directory trees + CSV/tree reports

IMPORTANT
---------
This version reconstructs the current directory tree and recovers file payloads
from the current IALC/LALC allocation metadata where the observed Nitro 2.7.1
layout can be decoded. --placeholders can create zero-byte placeholders only for
files whose payload cannot currently be reconstructed.

Use --write-flashfx to keep the reconstructed FlashFX/VBF logical devices and
--write-reliance (alias --write-logical-volumes) to additionally write each
detected Reliance Nitro volume as a standalone .bin image.

Tested against the supplied chip.dmp / Reliance Nitro 2.7.1 image.
"""

import argparse
import collections
import csv
import mmap
import os
import re
import struct
from pathlib import Path

RAW_PAGE = 4320
DATA_PAGE = 4096
PAGES_PER_UNIT = 128

# Reliance Nitro directory layout observed in this image.
BS = 4096
IDIR_PTR_ARRAY_OFF = 0xAB0
LDIR_NAME_ARRAY_OFF = 0x4A0


def u16(b, o):
    return struct.unpack_from("<H", b, o)[0]


def u32(b, o):
    return struct.unpack_from("<I", b, o)[0]


# ---------------------------------------------------------------------------
# Raw NAND -> FlashFX
# ---------------------------------------------------------------------------

def extract_main(raw_page: bytes) -> bytes:
    """Remove the observed interleaved OOB/ECC and return 4096 main bytes."""
    if len(raw_page) != RAW_PAGE:
        raise ValueError(f"Expected {RAW_PAGE} raw bytes, got {len(raw_page)}")

    out = bytearray()
    pos = 10
    for _ in range(8):
        out += raw_page[pos:pos + 512]
        pos += 512 + 26

    if len(out) != DATA_PAGE:
        raise AssertionError(f"Deinterleave produced {len(out)} bytes")
    return bytes(out)


def parse_flashfx_header(main: bytes):
    """Parse DL_FS4.00 erase-unit header from unit page 0."""
    if len(main) < 0x38 or main[:11] != b"\xCC\xDDDL_FS4.00":
        return None

    return {
        "clientAddress": u32(main, 0x10),
        "eraseCount": u32(main, 0x14),
        "serialNumber": u32(main, 0x18),
        "sequence": u32(main, 0x1C),
        "lnuTotal": u32(main, 0x20),
        "lnuTag": u32(main, 0x24),
        "numSpareUnits": u16(main, 0x28),
        "blockSize": u16(main, 0x2A),
        "lnuPerRegion": u16(main, 0x2C),
        "partitionStartUnit": u16(main, 0x2E),
        "unitTotalBlocks": u16(main, 0x30),
        "unitClientBlocks": u16(main, 0x32),
        "unitDataBlocks": u16(main, 0x34),
        "checksum": u16(main, 0x36),
    }


def flashfx_header_checksum_ok(main: bytes) -> bool:
    if len(main) < 0x38:
        return False
    return (sum(main[:0x36]) & 0xFFFF) == u16(main, 0x36)


def scan_flashfx_units(mm):
    if len(mm) % RAW_PAGE:
        raise RuntimeError(
            f"Input size {len(mm)} is not divisible by raw page size {RAW_PAGE}"
        )

    total_pages = len(mm) // RAW_PAGE
    total_units = total_pages // PAGES_PER_UNIT

    headers = []
    invalid = []

    for unit in range(total_units):
        pp = unit * PAGES_PER_UNIT
        raw_off = pp * RAW_PAGE
        raw = mm[raw_off:raw_off + RAW_PAGE]
        main = extract_main(raw)
        h = parse_flashfx_header(main)

        if h is None:
            invalid.append(unit)
            continue

        h["physicalUnit"] = unit
        h["headerChecksumOK"] = flashfx_header_checksum_ok(main)
        h["unitAllocWord"] = u16(raw, 2)
        headers.append(h)

    return total_pages, total_units, headers, invalid


def choose_flashfx_groups(headers):
    groups = collections.defaultdict(list)

    for h in headers:
        key = (
            h["serialNumber"],
            h["lnuTotal"],
            h["blockSize"],
            h["unitClientBlocks"],
            h["unitTotalBlocks"],
            h["lnuPerRegion"],
        )
        groups[key].append(h)

    # Ignore isolated false/corrupt headers.
    result = [g for g in groups.values() if len(g) >= 2]
    result.sort(key=lambda g: min(x["physicalUnit"] for x in g))
    return result


def build_flashfx_map(mm, units):
    """
    Map each FlashFX logical 4096-byte page to its newest physical NAND page.

    Observed allocation word:
      high nibble 0x4 = allocated/current candidate
      low 12 bits    = logical allocation address within the unit/region
    """
    p = units[0]
    logical_pages = p["unitClientBlocks"] * p["lnuTotal"]
    mapping = [None] * logical_pages
    status_counts = collections.Counter()

    for h in units:
        base_lp = h["clientAddress"] // h["blockSize"]
        sequence = h["sequence"]
        unit = h["physicalUnit"]

        # Page 0 is the FlashFX erase-unit header.
        max_pages = min(h["unitTotalBlocks"], PAGES_PER_UNIT)
        for page_in_unit in range(1, max_pages):
            physical_page = unit * PAGES_PER_UNIT + page_in_unit
            raw_off = physical_page * RAW_PAGE

            aw = u16(mm, raw_off + 2)
            status = (aw >> 12) & 0xF
            logical_allocation = aw & 0x0FFF
            status_counts[status] += 1

            if status != 0x4:
                continue

            logical_page = base_lp + logical_allocation
            if not (0 <= logical_page < logical_pages):
                status_counts["out_of_range"] += 1
                continue

            candidate = (sequence, physical_page)
            old = mapping[logical_page]

            # Newer unit sequence wins. Physical page is deterministic tie-break.
            if old is None or candidate[0] > old[0] or (
                candidate[0] == old[0] and candidate[1] > old[1]
            ):
                mapping[logical_page] = candidate

    return mapping, status_counts


class FlashFXLogical:
    """Random-access view of a reconstructed FlashFX logical device."""

    def __init__(self, raw_mm, mapping):
        self.mm = raw_mm
        self.mapping = mapping
        self.size = len(mapping) * DATA_PAGE
        self._cache_lp = None
        self._cache_data = None

    def page(self, logical_page):
        if logical_page < 0 or logical_page >= len(self.mapping):
            return b"\xFF" * DATA_PAGE

        if self._cache_lp == logical_page:
            return self._cache_data

        entry = self.mapping[logical_page]
        if entry is None:
            data = b"\xFF" * DATA_PAGE
        else:
            _, physical_page = entry
            off = physical_page * RAW_PAGE
            data = extract_main(self.mm[off:off + RAW_PAGE])

        self._cache_lp = logical_page
        self._cache_data = data
        return data

    def read(self, offset, size):
        if size <= 0:
            return b""
        if offset < 0 or offset >= self.size:
            return b""

        end = min(self.size, offset + size)
        out = bytearray()

        while offset < end:
            lp = offset // DATA_PAGE
            po = offset % DATA_PAGE
            n = min(DATA_PAGE - po, end - offset)
            out += self.page(lp)[po:po + n]
            offset += n

        return bytes(out)

    def write_image(self, path: Path):
        blank = b"\xFF" * DATA_PAGE
        with path.open("wb", buffering=1024 * 1024) as out:
            for entry in self.mapping:
                if entry is None:
                    out.write(blank)
                else:
                    _, pp = entry
                    ro = pp * RAW_PAGE
                    out.write(extract_main(self.mm[ro:ro + RAW_PAGE]))


# ---------------------------------------------------------------------------
# FlashFX logical device -> Reliance Nitro
# ---------------------------------------------------------------------------

def find_reliance_volumes(dev: FlashFXLogical):
    """
    Find MAST at volume_start + 0x40 and validate block size/count.
    We scan mapped logical pages only, avoiding creation of a huge intermediate.
    """
    candidates = {}

    for lp, entry in enumerate(dev.mapping):
        if entry is None:
            continue

        data = dev.page(lp)
        pos = 0
        while True:
            q = data.find(b"MAST", pos)
            if q < 0:
                break

            mast_abs = lp * DATA_PAGE + q
            if mast_abs >= 0x40:
                start = mast_abs - 0x40
                h = dev.read(mast_abs, 0x80)

                if len(h) >= 0x38 and h[:4] == b"MAST":
                    block_size = u32(h, 0x08)
                    block_count = u32(h, 0x0C)

                    if (
                        block_size == BS
                        and block_count > 0
                        and start % BS == 0
                        and start + block_size * block_count <= dev.size
                    ):
                        candidates[start] = {
                            "start": start,
                            "mast": mast_abs,
                            "header": h,
                            "blockSize": block_size,
                            "blockCount": block_count,
                            "size": block_size * block_count,
                        }

            pos = q + 4

    return [candidates[k] for k in sorted(candidates)]


class RelianceVolume:
    def __init__(self, dev, info):
        self.dev = dev
        self.info = info
        self.start = info["start"]
        self.block_size = info["blockSize"]
        self.block_count = info["blockCount"]
        self.header = info["header"]

    def block(self, block_no):
        if block_no < 0 or block_no >= self.block_count:
            return b""
        return self.dev.read(
            self.start + block_no * self.block_size,
            self.block_size
        )

    def write_image(self, path: Path, chunk_size=16 * 1024 * 1024):
        """Write this Reliance volume as a standalone logical image."""
        path.parent.mkdir(parents=True, exist_ok=True)
        remaining = self.info["size"]
        offset = 0
        with path.open("wb", buffering=1024 * 1024) as out:
            while remaining > 0:
                n = min(chunk_size, remaining)
                data = self.dev.read(self.start + offset, n)
                if not data:
                    raise RuntimeError(
                        f"Short read while writing Reliance image at volume offset 0x{offset:X}"
                    )
                out.write(data)
                offset += len(data)
                remaining -= len(data)

    def newest_meta(self):
        a = u32(self.header, 0x28)
        b = u32(self.header, 0x2C)

        ba = self.block(a)
        bb = self.block(b)

        ca = u32(ba, 8) if ba[:4] == b"META" else -1
        cb = u32(bb, 8) if bb[:4] == b"META" else -1

        return (a, ba, ca) if ca >= cb else (b, bb, cb)


# ---------------------------------------------------------------------------
# Reliance Nitro current directory tree
# ---------------------------------------------------------------------------

def idir_child_ptrs(b):
    count = u32(b, 0x10) & 0x7FFFFFFF
    max_count = max(0, (len(b) - IDIR_PTR_ARRAY_OFF) // 4)
    count = min(count, max_count)
    return [u32(b, IDIR_PTR_ARRAY_OFF + 4 * i) for i in range(count)]


def collect_current_ldir_leaves(vol: RelianceVolume, root_bn):
    """
    Traverse current IDIR tree. The supplied volume's root points directly to
    LDIR leaves, but recursion is supported in case another level appears.
    """
    leaves = []
    visited = set()
    stack = [root_bn]

    while stack:
        bn = stack.pop()

        if bn in visited or bn < 0 or bn >= vol.block_count:
            continue
        visited.add(bn)

        b = vol.block(bn)
        magic = b[:4]

        if magic == b"LDIR":
            leaves.append(bn)
            continue

        if magic == b"IDIR":
            children = idir_child_ptrs(b)
            # Reverse so traversal remains in original pointer order.
            stack.extend(reversed(children))

    return leaves


def parse_ldir_records(b, leaf_bn):
    count = u32(b, 0x10) & 0x7FFFFFFF

    # The key array begins at 0x18 and consists of 8-byte keys.
    max_key_count = max(0, (LDIR_NAME_ARRAY_OFF - 0x18) // 8)
    count = min(count, max_key_count)

    fragments = []

    for i in range(count):
        key = b[0x18 + i * 8:0x20 + i * 8]
        slot_off = LDIR_NAME_ARRAY_OFF + i * 20
        slot = b[slot_off:slot_off + 20]

        if len(key) != 8 or len(slot) != 20:
            break

        frag_raw = slot[:16]
        frag = frag_raw.split(b"\x00", 1)[0].decode("utf-8", "replace")
        oid = u32(slot, 16)

        frag_index = key[7]
        base_key = key[:7]

        # Crucial observation validated on this image:
        # first 32 bits of the directory key are big-endian (parent_id << 2).
        parent_id = int.from_bytes(key[:4], "big") >> 2

        fragments.append({
            "leaf_block": leaf_bn,
            "entry_index": i,
            "key_raw": key,
            "base_key": base_key,
            "fragment_index": frag_index,
            "fragment": frag,
            "object_id": oid,
            "parent_id": parent_id,
        })

    # Join 16-byte filename fragments with same 7-byte base key and indices 1..N.
    joined = []
    i = 0

    while i < len(fragments):
        r = fragments[i]

        if r["fragment_index"] != 1:
            i += 1
            continue

        name = r["fragment"]
        j = i + 1
        expected = 2

        while (
            j < len(fragments)
            and fragments[j]["base_key"] == r["base_key"]
            and fragments[j]["fragment_index"] == expected
        ):
            name += fragments[j]["fragment"]
            j += 1
            expected += 1

        joined.append({
            "leaf_block": leaf_bn,
            "entry_index": r["entry_index"],
            "key": r["base_key"].hex(),
            "parent_id": r["parent_id"],
            "object_id": r["object_id"],
            "name": name,
            "fragments": expected - 1,
        })

        i = j

    return joined


def recover_directory_records(vol: RelianceVolume):
    meta_bn, meta, transaction = vol.newest_meta()
    if meta[:4] != b"META":
        raise RuntimeError("Could not locate a valid current META block")

    idir_root = u32(meta, 0x10)
    idir = vol.block(idir_root)

    if idir[:4] not in (b"IDIR", b"LDIR"):
        raise RuntimeError(
            f"META points to 0x{idir_root:X}, magic={idir[:4]!r}, expected IDIR/LDIR"
        )

    leaves = collect_current_ldir_leaves(vol, idir_root)

    rows = []
    for bn in leaves:
        rows.extend(parse_ldir_records(vol.block(bn), bn))

    # Deduplicate exact object/name/parent duplicates while retaining tree order.
    seen = set()
    clean = []
    for r in rows:
        k = (r["parent_id"], r["object_id"], r["name"])
        if k not in seen:
            seen.add(k)
            clean.append(r)

    return {
        "meta_block": meta_bn,
        "transaction": transaction,
        "idir_root": idir_root,
        "leaves": leaves,
        "records": clean,
    }



# ---------------------------------------------------------------------------
# Reliance Nitro current allocation tree (IALC/LALC)
# ---------------------------------------------------------------------------

LALC_VALUE_ARRAY_OFF = 0x808


def collect_current_lalc_leaves(vol: RelianceVolume, root_bn):
    """Traverse current IALC tree and return active LALC leaves."""
    leaves = []
    visited = set()
    stack = [root_bn]

    while stack:
        bn = stack.pop()
        if bn in visited or bn < 0 or bn >= vol.block_count:
            continue
        visited.add(bn)

        b = vol.block(bn)
        magic = b[:4]
        if magic == b"LALC":
            leaves.append(bn)
            continue
        if magic != b"IALC":
            # A non-allocation pointer can occur in damaged/stale metadata.
            continue

        count = u32(b, 0x10) & 0x7FFFFFFF
        max_count = max(0, (len(b) - IDIR_PTR_ARRAY_OFF) // 4)
        count = min(count, max_count)
        children = [u32(b, IDIR_PTR_ARRAY_OFF + 4*i) for i in range(count)]
        stack.extend(reversed(children))

    return leaves


def recover_allocation_records(vol: RelianceVolume):
    """
    Parse the current allocation tree.

    Observed Nitro 2.7.1 LALC layout in this image:
      0x18: 8-byte big-endian keys
      0x808: parallel 8-byte values

    The 0x808 value-array offset is derived from the Reliance Nitro driver:
      value_off = 24 + key_size * floor((block_size - 24) / (key_size + value_size))
                = 24 + 8 * floor((4096 - 24) / 16)
                = 0x808

    Key first dword:
      object_id = first_be32 >> 2
      record_class = first_be32 & 3
    Key second dword:
      record index/type-specific index

    For normal file objects, class=1,index=2 contains the packed file size (value >> 16). Values that decode as (valid_block, count>0)
    are data extents. This is validated by recovered SQLite/text/ELF content.
    """
    meta_bn, meta, transaction = vol.newest_meta()
    if meta[:4] != b"META":
        raise RuntimeError("Could not locate current META")

    ialc_root = u32(meta, 0x14)
    leaves = collect_current_lalc_leaves(vol, ialc_root)
    by_object = collections.defaultdict(list)

    for leaf_bn in leaves:
        b = vol.block(leaf_bn)
        if b[:4] != b"LALC":
            continue

        count = u32(b, 0x10) & 0x7FFFFFFF
        # 0x808 is the driver-derived value-array base. Limit keys to what fits
        # before/at that boundary; current image commonly has <=254 records.
        count = min(count, 254)

        for i in range(count):
            ko = 0x18 + i*8
            vo = LALC_VALUE_ARRAY_OFF + i*8
            key = b[ko:ko+8]
            value = b[vo:vo+8]
            if len(key) != 8 or len(value) != 8:
                break

            first = int.from_bytes(key[:4], "big")
            oid = first >> 2
            rec_class = first & 3
            rec_index = int.from_bytes(key[4:], "big")

            by_object[oid].append({
                "leaf_block": leaf_bn,
                "entry_index": i,
                "first": first,
                "record_class": rec_class,
                "record_index": rec_index,
                "key": key,
                "value": value,
            })

    for oid in by_object:
        by_object[oid].sort(key=lambda r: (r["first"], r["record_index"], r["leaf_block"], r["entry_index"]))

    return {
        "ialc_root": ialc_root,
        "leaves": leaves,
        "by_object": by_object,
    }


def object_size_from_lalc(records):
    """
    Driver-derived Nitro 2.7.1 file-size decoder.

    class=1,index=2 is the stat/size record.  The on-disk 8-byte value is a
    packed field; for normal files the 64-bit file size is value >> 16.
    Bit 0x10 in the low flags byte denotes the no-size/special case.
    """
    for r in records:
        if r["record_class"] == 1 and r["record_index"] == 2:
            raw = int.from_bytes(r["value"], "little")
            flags = raw & 0xFF
            if flags & 0x10:
                return 0
            return raw >> 16
    return None


def object_timestamps_from_lalc(records):
    """
    Return the three Nitro stat timestamps (milliseconds) from class=1:
      index 3 -> atime
      index 4 -> mtime
      index 5 -> ctime

    This mapping is confirmed by the device's relfs.ko/reliance.ko:
    TfsCoreStat copies these records into the stat structure and relfs_inode_get
    maps them to Linux i_atime/i_mtime/i_ctime after division by 1000.
    """
    out = {"atime_ms": None, "mtime_ms": None, "ctime_ms": None}
    names = {3: "atime_ms", 4: "mtime_ms", 5: "ctime_ms"}
    for r in records:
        if r["record_class"] == 1 and r["record_index"] in names:
            out[names[r["record_index"]]] = int.from_bytes(r["value"], "little")
    return out

def object_extents_from_lalc(vol: RelianceVolume, records):
    """
    Return plausible current data extents in LALC key order.

    Data extent value = <u32 physical Reliance block, u32 block count>.
    Metadata values in this build normally have count==0, which separates them
    cleanly from file extents for the overwhelming majority of objects.
    """
    extents = []
    for r in records:
        # class 0 records are the file-data allocation extents.
        if r["record_class"] != 0:
            continue
        start, count = struct.unpack("<II", r["value"])
        if (
            0 < start < vol.block_count
            and 0 < count <= vol.block_count - start
            and count <= 4096
        ):
            extents.append({
                "start_block": start,
                "block_count": count,
                "record_class": r["record_class"],
                "record_index": r["record_index"],
                "leaf_block": r["leaf_block"],
            })
    return extents


def write_recovered_file(vol: RelianceVolume, path: Path, size, extents):
    """Write extent payload in current LALC key order and trim to logical size."""
    path.parent.mkdir(parents=True, exist_ok=True)
    remaining = size
    written = 0

    with path.open("wb") as out:
        for e in extents:
            for bn in range(e["start_block"], e["start_block"] + e["block_count"]):
                if remaining <= 0:
                    break
                data = vol.block(bn)
                if not data:
                    break
                chunk = data[:remaining]
                out.write(chunk)
                written += len(chunk)
                remaining -= len(chunk)
            if remaining <= 0:
                break

    return written, remaining


# ---------------------------------------------------------------------------
# Directory tree materialization
# ---------------------------------------------------------------------------

_WINDOWS_BAD = re.compile(r'[<>:"/\\|?*\x00-\x1F]')


def safe_component(name):
    # Keep the original name in CSV; this is only for host filesystem output.
    s = _WINDOWS_BAD.sub("_", name)
    s = s.rstrip(" .")
    if not s:
        s = "_unnamed"
    if s in (".", ".."):
        s = "_" + s.replace(".", "dot")
    # Avoid common Windows device names.
    stem = s.split(".", 1)[0].upper()
    if stem in {
        "CON", "PRN", "AUX", "NUL",
        *(f"COM{i}" for i in range(1, 10)),
        *(f"LPT{i}" for i in range(1, 10)),
    }:
        s = "_" + s
    return s


def select_root_id(records):
    """
    Reliance Nitro image supplied here uses object ID 2 as root.
    Prefer 2 when it has children; otherwise derive a likely root.
    """
    parent_counts = collections.Counter(r["parent_id"] for r in records)
    object_ids = {r["object_id"] for r in records}

    if parent_counts.get(2, 0):
        return 2

    missing = [(count, pid) for pid, count in parent_counts.items() if pid not in object_ids]
    if missing:
        return max(missing)[1]

    return parent_counts.most_common(1)[0][0]


def build_namespace(records):
    by_oid = {}
    children = collections.defaultdict(list)

    for r in records:
        # Current directory tree should normally contain one current record/object.
        # Keep first deterministic occurrence if duplicates remain.
        by_oid.setdefault(r["object_id"], r)
        children[r["parent_id"]].append(r)

    directory_ids = set(children.keys())
    root_id = select_root_id(records)

    return root_id, by_oid, children, directory_ids


def logical_path_for_record(rec, by_oid, root_id):
    parts = [rec["name"]]
    seen = {rec["object_id"]}
    pid = rec["parent_id"]

    while pid != root_id:
        if pid in seen:
            parts.append(f"_cycle_{pid}")
            break
        seen.add(pid)

        parent = by_oid.get(pid)
        if parent is None:
            parts.append(f"_orphan_parent_{pid}")
            break

        parts.append(parent["name"])
        pid = parent["parent_id"]

    return "/" + "/".join(reversed(parts))


def materialize_namespace(base: Path, records, vol=None, allocation=None, placeholders=False):
    root_id, by_oid, children, directory_ids = build_namespace(records)
    tree_root = base / "directory_tree"
    tree_root.mkdir(parents=True, exist_ok=True)

    path_cache = {root_id: tree_root}
    host_paths_by_oid = {}

    def host_dir_for_oid(oid, recursion=None):
        if oid == root_id:
            return tree_root
        if oid in path_cache:
            return path_cache[oid]
        if recursion is None:
            recursion = set()
        if oid in recursion:
            p = tree_root / "_cycles" / str(oid)
            p.mkdir(parents=True, exist_ok=True)
            path_cache[oid] = p
            return p

        recursion.add(oid)
        rec = by_oid.get(oid)
        if rec is None:
            p = tree_root / "_orphans" / f"parent_{oid}"
            p.mkdir(parents=True, exist_ok=True)
            path_cache[oid] = p
            return p

        parent_dir = host_dir_for_oid(rec["parent_id"], recursion)
        name = safe_component(rec["name"])
        p = parent_dir / name
        if p.exists() and host_paths_by_oid.get(oid) != p:
            p = parent_dir / f"{name}__oid_{oid}"
        p.mkdir(parents=True, exist_ok=True)
        path_cache[oid] = p
        host_paths_by_oid[oid] = p
        recursion.remove(oid)
        return p

    for oid in sorted(directory_ids):
        if oid != root_id:
            host_dir_for_oid(oid)

    manifest_rows = []
    by_alloc = allocation["by_object"] if allocation else {}

    for r in records:
        oid = r["object_id"]
        is_dir = oid in directory_ids
        logical = logical_path_for_record(r, by_oid, root_id)

        size = None
        recovered_bytes = None
        extent_count = 0
        atime_ms = None
        mtime_ms = None
        ctime_ms = None
        recovery_status = "directory" if is_dir else "not_attempted"

        if is_dir:
            host = host_dir_for_oid(oid)
        else:
            parent = host_dir_for_oid(r["parent_id"])
            name = safe_component(r["name"])
            host = parent / name
            if host.exists():
                host = parent / f"{name}__oid_{oid}"

            alloc_records = by_alloc.get(oid, [])
            if vol is not None and allocation is not None and alloc_records:
                size = object_size_from_lalc(alloc_records)
                ts = object_timestamps_from_lalc(alloc_records)
                atime_ms = ts["atime_ms"]
                mtime_ms = ts["mtime_ms"]
                ctime_ms = ts["ctime_ms"]
                extents = object_extents_from_lalc(vol, alloc_records)
                extent_count = len(extents)

                if size is not None:
                    if size == 0:
                        host.touch(exist_ok=True)
                        recovered_bytes = 0
                        recovery_status = "complete"
                    elif extents:
                        recovered_bytes, remaining = write_recovered_file(vol, host, size, extents)
                        recovery_status = "complete" if remaining == 0 else "partial"
                    else:
                        recovered_bytes = 0
                        recovery_status = "no_extent"
                else:
                    recovery_status = "no_size"
            elif placeholders:
                host.touch(exist_ok=True)
                recovery_status = "placeholder"

        manifest_rows.append({
            **r,
            "type": "directory" if is_dir else "file",
            "logical_path": logical,
            "host_path": str(host),
            "size": size,
            "recovered_bytes": recovered_bytes,
            "extent_count": extent_count,
            "atime_ms": atime_ms,
            "mtime_ms": mtime_ms,
            "ctime_ms": ctime_ms,
            "recovery_status": recovery_status,
        })

    return root_id, manifest_rows

def write_tree_txt(path: Path, manifest_rows, max_entries=None):
    dirs = collections.defaultdict(list)

    for r in manifest_rows:
        logical = r["logical_path"]
        parent = str(Path(logical).parent).replace("\\", "/")
        if parent == ".":
            parent = "/"
        dirs[parent].append(r)

    lines = []

    def walk(parent, prefix=""):
        entries = sorted(
            dirs.get(parent, []),
            key=lambda r: (r["type"] != "directory", r["name"].lower())
        )
        for idx, r in enumerate(entries):
            if max_entries is not None and len(lines) >= max_entries:
                return
            last = idx == len(entries) - 1
            connector = "└── " if last else "├── "
            suffix = "/" if r["type"] == "directory" else ""
            lines.append(prefix + connector + r["name"] + suffix)
            if r["type"] == "directory":
                child_prefix = prefix + ("    " if last else "│   ")
                walk(r["logical_path"], child_prefix)

    lines.append("/")
    walk("/")
    path.write_text("\n".join(lines), encoding="utf-8")


def write_csv(path: Path, rows):
    fields = [
        "type", "logical_path", "parent_id", "object_id", "name",
        "leaf_block", "entry_index", "key", "fragments", "host_path",
        "size", "recovered_bytes", "extent_count", "atime_ms", "mtime_ms", "ctime_ms", "recovery_status"
    ]
    with path.open("w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)


# ---------------------------------------------------------------------------
# End-to-end
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(
        description="Raw Datalight NAND -> FlashFX -> Reliance Nitro directory + file recovery"
    )
    ap.add_argument("dump", help="Raw chip.dmp (4320-byte physical page geometry)")
    ap.add_argument(
        "-o", "--output-dir", default="datalight_recovered",
        help="Output directory"
    )
    ap.add_argument(
        "--write-flashfx", action="store_true",
        help="Also write reconstructed FlashFX/VBF logical images (large)"
    )
    ap.add_argument(
        "--write-reliance", "--write-logical-volumes",
        dest="write_reliance", action="store_true",
        help=(
            "Also write each detected Reliance Nitro volume as a standalone "
            "logical .bin image"
        )
    )    ap.add_argument(
        "--placeholders", action="store_true",
        help="Create zero-byte placeholders only where payload recovery is unavailable"
    )
    args = ap.parse_args()

    dump = Path(args.dump)
    out = Path(args.output_dir)
    out.mkdir(parents=True, exist_ok=True)

    print("=" * 72)
    print("Datalight FlashFX / Reliance Nitro end-to-end directory recovery")
    print("=" * 72)
    print("Input:", dump)

    with dump.open("rb") as f:
        mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)

        total_pages, total_units, headers, invalid = scan_flashfx_units(mm)
        groups = choose_flashfx_groups(headers)

        print(f"Raw size             : {len(mm):,}")
        print(f"Raw pages            : {total_pages:,} x {RAW_PAGE}")
        print(f"Physical erase units : {total_units:,} x {PAGES_PER_UNIT} pages")
        print(f"Valid DL_FS headers  : {len(headers):,}")
        print(f"FlashFX groups       : {len(groups)}")

        summary_rows = []

        for gi, units in enumerate(groups, 1):
            h = units[0]
            mapping, statuses = build_flashfx_map(mm, units)
            dev = FlashFXLogical(mm, mapping)
            mapped = sum(x is not None for x in mapping)

            print()
            print("-" * 72)
            print(f"FlashFX #{gi}")
            print(f"Serial               : 0x{h['serialNumber']:08X}")
            print(f"Physical headers     : {len(units)}")
            print(f"Logical size         : {dev.size:,}")
            print(f"Mapped pages         : {mapped:,}/{len(mapping):,}")
            print(f"Allocation statuses  : {dict(statuses)}")

            fxdir = out / f"flashfx_{gi}"
            fxdir.mkdir(parents=True, exist_ok=True)

            if args.write_flashfx:
                img = fxdir / f"flashfx_{gi}.bin"
                print("Writing FlashFX image :", img)
                dev.write_image(img)

            volumes = find_reliance_volumes(dev)
            print(f"Reliance volumes     : {len(volumes)}")

            if not volumes:
                continue

            for vi, info in enumerate(volumes, 1):
                vol = RelianceVolume(dev, info)

                vdir = fxdir / f"reliance_volume_{vi}"
                vdir.mkdir(parents=True, exist_ok=True)

                if args.write_reliance:
                    rimg = vdir / f"reliance_volume_{vi}.bin"
                    print(f"  Writing Reliance volume {vi}: {rimg}")
                    vol.write_image(rimg)

                result = recover_directory_records(vol)
                allocation = recover_allocation_records(vol)

                root_id, manifest = materialize_namespace(
                    vdir,
                    result["records"],
                    vol=vol,
                    allocation=allocation,
                    placeholders=args.placeholders
                )

                csv_path = vdir / "directory_and_file_manifest.csv"
                tree_path = vdir / "tree.txt"
                write_csv(csv_path, manifest)
                write_tree_txt(tree_path, manifest)

                # Extra raw directory-record CSV, useful for reverse engineering.
                raw_csv = vdir / "raw_directory_records.csv"
                raw_fields = [
                    "leaf_block", "entry_index", "key", "parent_id",
                    "object_id", "name", "fragments"
                ]
                with raw_csv.open("w", newline="", encoding="utf-8-sig") as cf:
                    w = csv.DictWriter(cf, fieldnames=raw_fields)
                    w.writeheader()
                    w.writerows(result["records"])

                dirs_count = sum(1 for r in manifest if r["type"] == "directory")
                files_count = sum(1 for r in manifest if r["type"] == "file")
                complete_count = sum(1 for r in manifest if r.get("recovery_status") == "complete")
                partial_count = sum(1 for r in manifest if r.get("recovery_status") == "partial")

                print()
                print(f"  Reliance volume {vi}")
                print(f"    Start            : 0x{info['start']:X}")
                print(f"    Size             : {info['size']:,}")
                print(f"    Blocks           : {info['blockCount']:,} x {info['blockSize']}")
                print(f"    META             : 0x{result['meta_block']:X}")
                print(f"    Transaction      : {result['transaction']}")
                print(f"    IDIR root        : 0x{result['idir_root']:X}")
                print(f"    Current LDIRs    : {len(result['leaves'])}")
                print(f"    Root object ID   : {root_id}")
                print(f"    Directories      : {dirs_count:,}")
                print(f"    File records     : {files_count:,}")
                print(f"    Files complete   : {complete_count:,}")
                print(f"    Files partial    : {partial_count:,}")
                print(f"    IALC root        : 0x{allocation['ialc_root']:X}")
                print(f"    Current LALCs    : {len(allocation['leaves'])}")
                print(f"    Folder tree      : {vdir / 'directory_tree'}")
                print(f"    Tree listing     : {tree_path}")

                summary_rows.append({
                    "flashfx": gi,
                    "reliance_volume": vi,
                    "flashfx_serial": f"0x{h['serialNumber']:08X}",
                    "volume_start": f"0x{info['start']:X}",
                    "volume_size": info["size"],
                    "meta_block": f"0x{result['meta_block']:X}",
                    "transaction": result["transaction"],
                    "idir_root": f"0x{result['idir_root']:X}",
                    "root_object_id": root_id,
                    "directories": dirs_count,
                    "files": files_count,
                    "files_complete": complete_count,
                    "files_partial": partial_count,
                    "output": str(vdir),
                })

        mm.close()

    summary = out / "summary.csv"
    if summary_rows:
        with summary.open("w", newline="", encoding="utf-8-sig") as sf:
            w = csv.DictWriter(sf, fieldnames=list(summary_rows[0].keys()))
            w.writeheader()
            w.writerows(summary_rows)

    print()
    print("=" * 72)
    print("Finished.")
    print("Output:", out)
    print()
    print("NOTE: directory records come from current IDIR/LDIR; payloads come from current IALC/LALC.")
    print("The raw dump's interleaved ECC bytes are not corrected by this script, so individual NAND bit errors may remain in recovered file contents.")


if __name__ == "__main__":
    main()