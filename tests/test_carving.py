import io
import os
import struct
import sys
import tempfile
import unittest
import zipfile
import zlib
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
import qnxprobe_carving as c


def chunk(tag, data):
    return struct.pack('>I', len(data)) + tag + data + struct.pack('>I', zlib.crc32(tag+data))


class CarvingTests(unittest.TestCase):
    def test_boundaries_and_export(self):
        jpg = b'\xff\xd8\xffpayload\xff\xd9'
        png = c.SIGNATURES['png'] + chunk(b'IHDR', struct.pack('>IIBBBBB', 1, 1, 8, 2, 0, 0, 0)) + chunk(b'IEND', b'')
        pdf = b'%PDF-1.4\nhello\n%%EOF'
        out = io.BytesIO()
        with zipfile.ZipFile(out, 'w') as z:
            z.writestr('test.txt', b'hello')
        data = b'x'*13 + jpg + b'x'*9 + png + pdf + out.getvalue()
        hits = list(c.scan(io.BytesIO(data), len(data), chunk_size=16))
        self.assertEqual([h['type'] for h in hits], ['jpg', 'png', 'pdf', 'zip'])
        self.assertEqual([h['size'] for h in hits], list(map(len, (jpg, png, pdf, out.getvalue()))))
        with tempfile.TemporaryDirectory() as folder:
            record = c.export_hit(io.BytesIO(data), hits[0], folder)
            with open(os.path.join(folder, record['file']), 'rb') as fh:
                self.assertEqual(fh.read(), jpg)
            with self.assertRaises(FileExistsError):
                c.export_hit(io.BytesIO(data), hits[0], folder)

    def test_invalid_and_limits(self):
        data = c.SIGNATURES['png'] + chunk(b'IHDR', b'x'*13)[:-1] + b'x'
        self.assertEqual(list(c.scan(io.BytesIO(data), len(data))), [])
        data = b'\xff\xd8\xff123456\xff\xd9'
        self.assertEqual(list(c.scan(io.BytesIO(data), len(data), max_size=8)), [])
        self.assertEqual(list(c.scan(io.BytesIO(data), len(data), cancelled=lambda: True)), [])
        self.assertEqual(list(c.scan(io.BytesIO(b'%PDF-incomplete'), 15)), [])

    def test_partial_export_removed(self):
        with tempfile.TemporaryDirectory() as folder:
            with self.assertRaises(IOError):
                c.export_hit(io.BytesIO(b'abc'), dict(offset=0, size=10, type='pdf'), folder)
            self.assertEqual(os.listdir(folder), [])


if __name__ == '__main__':
    unittest.main()
