#!/usr/bin/env python3
"""Build the BitLocker self-test fixtures: small volumes laid out as BitLocker lays
them out, around the 48 KiB SquashFS fixture, so every key protector, both sector
ciphers, the moved first sectors, the Encrypt-on-Write map and the layouts this does
not read are exercised from bytes the reader did not write.

    python3 tools/make_bitlocker_fixtures.py        (needs pycryptodome)

This program shares no code with qnxprobe's reader: every layout value below is
written out again from Joachim Metz, "BitLocker Drive Encryption (BDE) format
specification" (libyal/libbde at 96e3c5dce6143c2702c90f3903018fb8c12a8956), and it
encrypts where the reader decrypts. BitLocker encrypts whatever volume it is given;
SquashFS is inside only because it is the smallest filesystem with a known file
list here, and ciphertext does not compress. qnxprobe's BitLocker reader was
checked separately against volumes Windows 11 wrote (see the README).

Every password, recovery password and key here is a test value made for these
fixtures, and the self-test states them again rather than reading this file.
"""
import gzip
import hashlib
import os
import struct

from Crypto.Cipher import AES

HERE = os.path.dirname(os.path.abspath(__file__))
FIX = os.path.join(HERE, "..", "tests", "fixtures")

PASSWORD = "qnxprobe-bde-test"
RECOVERY_A = "111111-222222-333333-444444-555555-666666-000011-000022"
RECOVERY_B = "000011-000022-000033-000044-000055-000066-000077-000088"
GUID = bytes.fromhex("3bd66749292ed84a8399f6a339e3d001")       # 4967d63b-2e29-4ad8-8399-f6a339e3d001
EOW_GUID = bytes.fromhex("3b4da89280dd0e4d9e4eb1e3284eaed8")   # 92a84d3b-dd80-4d0e-9e4e-b1e3284eaed8
FILETIME = (1758931200 + 11644473600) * 10**7   # 2025-09-27 00:00:00 UTC, 100 ns ticks from 1601

SECTOR = 512
INNER = 65536                          # the SquashFS fixture, padded
META = (65536, 131072, 196608)         # three 64 KiB FVE metadata blocks
VH_OFFSET, VH_SIZE = 262144, 8192      # where the first 8 KiB are kept, encrypted
EOW_DESC, EOW_MAP = 270336, 274432     # Encrypt-on-Write descriptor and block map
SIZE = 278528
EOW_BLOCK = 8192


def rng(tag):
    """Deterministic bytes, so rebuilding gives the same fixtures."""
    state = hashlib.sha256(tag.encode()).digest()
    while True:
        state = hashlib.sha256(state).digest()
        yield from state


def take(gen, n):
    return bytes(next(gen) for _ in range(n))


def entry(etype, vtype, data, version=1):
    return struct.pack("<HHHH", 8 + len(data), etype, vtype, version) + data


def ccm(key, payload_key, method, gen):
    """An AES-CCM encrypted key value: nonce (FILETIME, counter), tag, then the
    encrypted size, version, method and key."""
    nonce = struct.pack("<QI", FILETIME, 1 + next(gen))
    payload = struct.pack("<IHHI", 12 + len(payload_key), 1, 0, method) + payload_key
    ct, tag = AES.new(key, AES.MODE_CCM, nonce=nonce, mac_len=16).encrypt_and_digest(payload)
    return nonce + tag + ct


def stretch(initial, salt):
    last = bytes(32)
    for count in range(0x100000):
        last = hashlib.sha256(last + initial + salt + struct.pack("<Q", count)).digest()
    return last


def recovery_initial(text):
    groups = [int(g) for g in text.split("-")]
    assert all(g % 11 == 0 and g // 11 < 65536 for g in groups), text
    return hashlib.sha256(b"".join(struct.pack("<H", g // 11) for g in groups)).digest()


def password_initial(text):
    return hashlib.sha256(hashlib.sha256(text.encode("utf-16-le")).digest()).digest()


def vmk_entry(kid, protection, props):
    return entry(2, 8, kid + struct.pack("<QHH", FILETIME, 0, protection) + props)


def encrypt_sectors(method, fvek, phys, data):
    out = bytearray()
    for i in range(0, len(data), SECTOR):
        off = phys + i
        block = data[i:i + SECTOR]
        if method in (0x8004, 0x8005):
            half = 16 if method == 0x8004 else 32
            k1, k2 = AES.new(fvek[:half], AES.MODE_ECB), AES.new(fvek[half:2 * half], AES.MODE_ECB)
            t = int.from_bytes(k2.encrypt((off // SECTOR).to_bytes(16, "little")), "little")
            for j in range(0, SECTOR, 16):
                tb = t.to_bytes(16, "little")
                x = bytes(a ^ b for a, b in zip(block[j:j + 16], tb))
                out += bytes(a ^ b for a, b in zip(k1.encrypt(x), tb))
                t <<= 1
                if t >> 128:
                    t = (t & ((1 << 128) - 1)) ^ 0x87
        else:
            key = fvek[:16 if method == 0x8002 else 32]
            iv = AES.new(key, AES.MODE_ECB).encrypt(off.to_bytes(16, "little"))
            out += AES.new(key, AES.MODE_CBC, iv).encrypt(block)
    return bytes(out)


def build(name, method, protectors, layout="7", eow_plain=(), readable=True):
    """protectors: list of ("password"|"recovery"|"startup"|"clear"|"tpm", secret)."""
    gen = rng(name)
    vol = bytearray(SIZE)
    inner = bytearray(INNER)
    with gzip.open(os.path.join(FIX, "squashfs-small.img.gz"), "rb") as g:
        sq = g.read()
    inner[:len(sq)] = sq
    fvek = take(gen, {0x8002: 16, 0x8003: 32, 0x8004: 32, 0x8005: 64}.get(method, 64))
    vmk = take(gen, 32)
    volume_id = take(gen, 16)
    entries, bek = b"", None
    for kind, secret in protectors:
        kid = take(gen, 16)
        if kind in ("password", "recovery"):
            salt = take(gen, 16)
            initial = password_initial(secret) if kind == "password" else recovery_initial(secret)
            key = stretch(initial, salt)
            props = entry(0, 3, struct.pack("<I", 0x1000) + salt) + entry(0, 5, ccm(key, vmk, 0x2000, gen))
            entries += vmk_entry(kid, 0x2000 if kind == "password" else 0x0800, props)
        elif kind == "startup":
            ext = take(gen, 32)
            entries += vmk_entry(kid, 0x0200, entry(0, 5, ccm(ext, vmk, 0x2000, gen)))
            key_entry = entry(0, 1, struct.pack("<I", 0x2002) + ext)
            ext_value = kid + struct.pack("<Q", FILETIME) + key_entry
            body = entry(6, 9, ext_value)
            bek = struct.pack("<IIII", 48 + len(body), 1, 48, 48 + len(body)) + volume_id + \
                struct.pack("<IIQ", 1, 0, FILETIME) + body
        elif kind == "clear":
            clear = take(gen, 32)
            props = entry(0, 1, struct.pack("<I", 0x2003) + clear) + entry(0, 5, ccm(clear, vmk, 0x2000, gen))
            entries += vmk_entry(kid, 0x0000, props, )
        elif kind == "tpm":
            entries += vmk_entry(kid, 0x0100, entry(0, 6, take(gen, 64)))
    entries += entry(3, 5, ccm(vmk, fvek, method, gen))
    entries += entry(7, 2, "QNXPROBE-TEST F: 2025-09-27\x00".encode("utf-16-le"))
    entries += entry(15, 15, struct.pack("<QQ", VH_OFFSET, VH_SIZE))
    mheader = struct.pack("<IIII", 48 + len(entries), 1, 48, 48 + len(entries)) + volume_id + \
        struct.pack("<IIQ", 1, method, FILETIME)
    enc_size = SIZE
    if layout == "vista":
        block = b"-FVE-FS-" + struct.pack("<HHHH", 64, 1, 4, 4) + bytes(16) + \
            struct.pack("<QQQQ", *META, 0) + mheader + entries
    else:
        block = b"-FVE-FS-" + struct.pack("<HHHHQII", 64, 2, 4, 4, enc_size, 0, VH_SIZE // SECTOR) + \
            struct.pack("<QQQQ", *META, VH_OFFSET) + mheader + entries
    for off in META:
        vol[off:off + len(block)] = block

    # The volume header: a FAT32 boot sector in all but BitLocker's own fields.
    hdr = bytearray(SECTOR)
    hdr[0:3] = b"\xeb\x52\x90" if layout == "vista" else b"\xeb\x58\x90"
    hdr[3:11] = b"MSWIN4.1" if layout == "togo" else b"-FVE-FS-"
    struct.pack_into("<HB", hdr, 11, SECTOR, 8)
    hdr[21] = 0xF8
    struct.pack_into("<HH", hdr, 24, 0x3F, 0xFF)
    if layout == "vista":
        # Windows Vista's header is an NTFS boot sector but for its signature and the
        # FVE metadata block's cluster number at 56; it carries no FAT32 fields.
        struct.pack_into("<BBBBQQQ", hdr, 36, 0x80, 0, 0x80, 0, SIZE // SECTOR, 4, META[0] // 4096)
    else:
        struct.pack_into("<I", hdr, 36, 0x1FE0)
        hdr[66] = 0x29
        hdr[71:82] = b"NO NAME    "
        hdr[82:90] = b"FAT32   "
    if layout == "togo":
        hdr[424:440] = GUID
        struct.pack_into("<QQQ", hdr, 440, *META)
    elif layout != "vista":
        hdr[160:176] = EOW_GUID if layout == "eow" else GUID
        struct.pack_into("<QQQ", hdr, 176, *META)
        if layout == "eow":
            struct.pack_into("<QQ", hdr, 200, EOW_DESC, 0)
    hdr[510:512] = b"\x55\xaa"
    vol[0:SECTOR] = hdr

    if layout == "eow":
        nbits = SIZE // EOW_BLOCK
        bitmap = bytearray(-(-nbits // 8))
        for i in range(nbits):
            start = i * EOW_BLOCK
            if not any(s <= start < e for s, e in eow_plain):
                bitmap[i // 8] |= 1 << (i % 8)
        desc = bytearray(4096)
        desc[0:8] = b"FVE-EOW\x00"
        struct.pack_into("<HHIIIIIII", desc, 8, 56, 64, SECTOR, SECTOR, EOW_BLOCK, 0, 0, 1, 0)
        struct.pack_into("<QQQ", desc, 40, EOW_DESC, 0, EOW_MAP)
        vol[EOW_DESC:EOW_DESC + 4096] = desc
        bm = bytearray(4096)
        bm[0:10] = b"FVE-EOWBM\x00"
        struct.pack_into("<HIIQQQIII", bm, 10, 60, 4096, 0, 0, SIZE, 0, 512, 0, 512)
        rec = bytearray(512)
        rec[0:10] = b"FVE-EOWBR\x00"
        struct.pack_into("<HIIQ", rec, 10, 36, 512, nbits, 1)
        rec[36:36 + len(bitmap)] = bitmap
        bm[512:1024] = rec
        vol[EOW_MAP:EOW_MAP + 4096] = bm

    if readable:
        # The volume's own first 8 KiB go to VH_OFFSET, encrypted with that
        # location's sector numbers; the rest is encrypted where it stands, or
        # left as stored where an unfinished conversion has not reached.
        vol[VH_OFFSET:VH_OFFSET + VH_SIZE] = encrypt_sectors(method, fvek, VH_OFFSET, bytes(inner[:VH_SIZE]))
        for off in range(VH_SIZE, INNER, SECTOR):
            plain = bytes(inner[off:off + SECTOR])
            if any(s <= off < e for s, e in eow_plain):
                vol[off:off + SECTOR] = plain
            else:
                vol[off:off + SECTOR] = encrypt_sectors(method, fvek, off, plain)

    with gzip.GzipFile(os.path.join(FIX, f"bitlocker-{name}.img.gz"), "wb", mtime=0) as g:
        g.write(bytes(vol))
    if bek is not None:
        with open(os.path.join(FIX, f"bitlocker-{name}.BEK"), "wb") as f:
            f.write(bek)
    print(f"bitlocker-{name}.img.gz" + (f" and bitlocker-{name}.BEK" if bek else ""))


if __name__ == "__main__":
    build("xts128", 0x8004, [("password", PASSWORD), ("recovery", RECOVERY_A), ("startup", None)])
    build("cbc256", 0x8003, [("recovery", RECOVERY_B)])
    build("clearkey", 0x8005, [("password", PASSWORD), ("clear", None)])
    build("eow", 0x8004, [("password", PASSWORD)], layout="eow", eow_plain=((32768, 65536),))
    build("togo", 0x8002, [("password", PASSWORD)], layout="togo")
    build("tpm", 0x8004, [("tpm", None)], readable=False)
    build("diffuser", 0x8000, [("password", PASSWORD)], readable=False)
    build("vista", 0x8000, [("password", PASSWORD)], layout="vista", readable=False)
