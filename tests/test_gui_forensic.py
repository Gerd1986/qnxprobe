"""Content-viewer data paths checked against independently recorded fixture hashes."""
import gzip
import hashlib
import io
import pathlib
import sys
import tarfile
import unittest
import zipfile
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import qnxprobe as q
import qnxprobe_gui as gui

FIX = pathlib.Path(__file__).parent / 'fixtures'

class ContentTests(unittest.TestCase):
    def test_deleted_fixture_hashes_and_free_bytes(self):
        for stem, cls in [('fat32-deleted', q.Fat32Walker),
                          ('exfat-deleted', q.ExfatWalker),
                          ('ntfs-fixture', q.NtfsWalker)]:
            with self.subTest(filesystem=stem):
                raw = gzip.decompress((FIX / (stem + '.img.gz')).read_bytes())
                fh = io.BytesIO(raw)
                walker = cls(fh, 0)
                entries = {name: (node, size) for name, node, size, _, _ in
                           gui.forensic_entries(walker, 'deleted', len(raw)) if size is not None}
                for line in (FIX / (stem + '.deleted.sha256')).read_text().splitlines():
                    if not line or line.startswith('#'):
                        continue
                    digest, path = line.split('  ', 1)
                    name = path.rsplit('/', 1)[-1]
                    node, size = entries.get(name) or entries['_' + name[1:]]
                    data = b''.join(gui.content_chunks(walker, fh, node, size))
                    self.assertEqual(hashlib.sha256(data).hexdigest(), digest)
                free = list(gui.forensic_entries(walker, 'unallocated', len(raw)))
                self.assertTrue(free)
                for _, node, size, _, _ in free[:3]:
                    data = b''.join(gui.content_chunks(walker, fh, node, min(size, 65536)))
                    self.assertEqual(data, raw[node[1]:node[1] + min(size, 65536)])

    def test_archive_lists_without_extracting(self):
        for kind in ('zip', 'tar'):
            buf = io.BytesIO()
            if kind == 'zip':
                with zipfile.ZipFile(buf, 'w') as archive:
                    archive.writestr('../example.txt', b'hello')
            else:
                with tarfile.open(fileobj=buf, mode='w') as archive:
                    entry = tarfile.TarInfo('../example.txt')
                    entry.size = 5
                    archive.addfile(entry, io.BytesIO(b'hello'))
            listing = gui.archive_listing([buf.getvalue()])
            self.assertIn('../example.txt', listing)
            self.assertIn('5', listing)
        with self.assertRaises(ValueError):
            gui.archive_listing([b'12345'], max_bytes=4)
        with self.assertRaises((tarfile.TarError, zipfile.BadZipFile)):
            gui.archive_listing([b'broken archive'])

    def test_partial_image_extent_clipped(self):
        class Walker:
            def free_extents(self):
                return [(4, 10), (20, 4), (-1, 2)]
        entries = list(gui.forensic_entries(Walker(), 'unallocated', 8))
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0][2], 4)

if __name__ == '__main__':
    unittest.main()
