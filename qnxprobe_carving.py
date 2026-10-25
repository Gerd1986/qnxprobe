"""Bounded, read-only signature carving. Standard library only.

Candidates must be contiguous. Offsets refer to the logical image stream.
A hit is not evidence that the file was deleted. Fragment recovery is not done.
"""
import hashlib
import json
import os
import struct
import zlib

SIGNATURES = {'jpg': b'\xff\xd8\xff', 'png': b'\x89PNG\r\n\x1a\n',
              'pdf': b'%PDF-', 'zip': b'PK\x03\x04'}


def candidate_length(fh, offset, end, kind, limit, cancelled):
    """Return a bounded candidate's length, or None for incomplete/invalid data."""
    fh.seek(offset)
    if kind == 'png':
        if fh.read(8) != SIGNATURES['png']:
            return None
        first = True
        while fh.tell() + 12 <= min(end, offset + limit):
            if cancelled():
                return None
            n, tag = struct.unpack('>I4s', fh.read(8))
            if n > limit or fh.tell() + n + 4 > min(end, offset + limit):
                return None
            if first and (tag != b'IHDR' or n != 13):
                return None
            first = False
            crc = zlib.crc32(tag)
            remaining = n
            while remaining:
                data = fh.read(min(remaining, 65536))
                if not data or cancelled():
                    return None
                crc = zlib.crc32(data, crc)
                remaining -= len(data)
            if struct.unpack('>I', fh.read(4))[0] != crc & 0xffffffff:
                return None
            if tag == b'IEND':
                return fh.tell() - offset if n == 0 else None
        return None
    marker = {'jpg': b'\xff\xd9', 'pdf': b'%%EOF', 'zip': b'PK\x05\x06'}[kind]
    pos, tail = offset, b''
    while pos < min(end, offset + limit) and not cancelled():
        fh.seek(pos)
        data = fh.read(min(65536, end-pos, offset+limit-pos))
        if not data:
            break
        buf = tail + data
        base = pos - len(tail)
        start = 0
        while True:
            i = buf.find(marker, start)
            if i < 0:
                break
            stop = base + i + len(marker)
            if kind != 'zip':
                return stop - offset
            fh.seek(base + i)
            eocd = fh.read(22)
            if len(eocd) == 22:
                _, disk, cd_disk, count_disk, count, cd_size, cd_off, comment = struct.unpack('<4s4H2IH', eocd)
                length = base+i+22+comment-offset
                if (disk == cd_disk == 0 and count_disk == count and count > 0
                        and cd_off + cd_size == base+i-offset
                        and offset+length <= end and length <= limit):
                    fh.seek(offset + cd_off)
                    if fh.read(4) == b'PK\x01\x02':
                        return length
            start = i + 1
        tail = buf[-len(marker)+1:]
        pos += len(data)
    return None


def scan(fh, size, kinds=None, max_size=64*1024*1024, cancelled=lambda: False,
         progress=lambda value: None, chunk_size=1024*1024):
    """Yield signature candidates without loading the image into memory."""
    kinds = tuple(SIGNATURES if kinds is None else kinds)
    if max_size <= 0 or chunk_size < 8:
        raise ValueError('Positive size limit and chunk size >= 8 required')
    for kind in kinds:
        if kind not in SIGNATURES:
            raise ValueError('Unknown file type: ' + kind)
    pos, tail = 0, b''
    while pos < size and not cancelled():
        fh.seek(pos)
        data = fh.read(min(chunk_size, size-pos))
        if not data:
            break
        buf, base = tail+data, pos-len(tail)
        hits = []
        for kind in kinds:
            start = 0
            while not cancelled():
                i = buf.find(SIGNATURES[kind], start)
                if i < 0:
                    break
                off = base+i
                if off+len(SIGNATURES[kind]) > pos:
                    hits.append((off, kind))
                start = i+1
        for off, kind in sorted(hits):
            if cancelled():
                break
            length = candidate_length(fh, off, size, kind, max_size, cancelled)
            if length and not cancelled():
                yield {'offset': off, 'size': length, 'type': kind,
                       'validation': 'CRC checked' if kind == 'png' else
                       'central directory bounds' if kind == 'zip' else 'header/footer candidate'}
        pos += len(data)
        tail = buf[-7:]
        progress(pos / size if size else 1)


def export_hit(fh, hit, folder):
    """Export exclusively; remove partial output on failure. Return hash and path."""
    name = 'carved_%016x.%s' % (hit['offset'], hit['type'])
    path = os.path.join(folder, name)
    digest = hashlib.sha256()
    with open(path, 'xb') as out:
        try:
            fh.seek(hit['offset'])
            remaining = hit['size']
            while remaining:
                data = fh.read(min(remaining, 1024*1024))
                if not data:
                    raise IOError('Unexpected end of image')
                out.write(data)
                digest.update(data)
                remaining -= len(data)
        except BaseException:
            out.close()
            os.unlink(path)
            raise
    return dict(hit, file=name, sha256=digest.hexdigest())


def main():
    import argparse
    import qnxprobe as q
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('image')
    ap.add_argument('output', help='New output directory')
    ap.add_argument('--types', default='jpg,png,pdf,zip')
    ap.add_argument('--max-mib', type=int, default=64)
    args = ap.parse_args()
    os.mkdir(args.output)
    records = []
    try:
        with q.open_image(args.image) as fh:
            for hit in scan(fh, q.image_size(fh), args.types.split(','), args.max_mib*1024*1024):
                records.append(export_hit(fh, hit, args.output))
                print(records[-1]['file'])
    finally:
        with open(os.path.join(args.output, 'carving.json'), 'x', encoding='utf-8') as out:
            json.dump({'image': os.path.abspath(args.image), 'hits': records}, out, indent=2)


if __name__ == '__main__':
    main()
