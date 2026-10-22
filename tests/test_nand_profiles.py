"""Independent transport/ECC fixture through production CLI and shared GUI backend."""
import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import nand_tools
import qnxprobe as q
from nand_encoder import generator, pack_page
from nand_lba_fixture import create


class NandTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='qnxprobe NAND tests ')
        cls.folder = Path(cls.temp.name)
        cls.expected = create(cls.folder / 'fixture')
        cls.source = cls.folder / 'fixture/synthetic-nand-ftl-ecc-fat32.bin'
        cls.profile = cls.folder / 'fixture/synthetic-lba-bch-fat32.json'

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def test_cli_ecc_mapping_discovery_and_extraction(self):
        output = self.folder / 'audit outputs'
        archive = self.folder / 'extracted.zip'
        before = hashlib.sha256(self.source.read_bytes()).hexdigest()
        p = subprocess.run([sys.executable, str(ROOT/'qnxprobe.py'),
                            '--nand-profile', str(self.profile), '--nand-output', str(output),
                            '--extract', str(archive), '--progress', str(self.source)],
                           capture_output=True, text=True, timeout=120)
        self.assertEqual(p.returncode, 0, p.stderr + p.stdout[-2000:])
        self.assertEqual(hashlib.sha256(self.source.read_bytes()).hexdigest(), before)
        logical, = output.glob('nand-*/logical.img')
        self.assertEqual(hashlib.sha256(logical.read_bytes()).hexdigest(), self.expected['reference_sha256'])
        report = json.loads(Path(str(logical)+'.report.json').read_text())
        self.assertEqual(report['corrected_bits'], 6)
        self.assertEqual(report['duplicate_pages'], 2)
        self.assertEqual(report['erased_pages'], 2)
        self.assertEqual(report['lba_mapping']['missing_ranges'], [])
        self.assertEqual((logical.parent/'device-profile.json').read_bytes(), self.profile.read_bytes())
        events = [json.loads(line) for line in p.stderr.splitlines()]
        self.assertTrue(any(e.get('phase') == 'nand' for e in events))
        with zipfile.ZipFile(archive) as z:
            for name, info in self.expected['files'].items():
                data = z.read('lba0/'+name)
                self.assertEqual(hashlib.sha256(data).hexdigest(), info['sha256'])

    def test_shared_gui_backend_preserves_ubi_and_audit(self):
        import gzip
        clean = gzip.decompress((ROOT/'tests/fixtures/ubi-nand-lzo.img.gz').read_bytes())
        source = self.folder/'transport.bin'
        polynomial = generator()
        # Encode the existing kernel-built UBI image using the independent writer.
        from functools import lru_cache
        pack = lru_cache(maxsize=128)(lambda page: pack_page(page, polynomial))
        source.write_bytes(b''.join(pack(clean[i:i+4096]) for i in range(0, len(clean), 4096)))
        damaged = bytearray(source.read_bytes()); damaged[0] ^= 0x80
        source.write_bytes(damaged)
        profile = ROOT/'nand_tools/profiles/qualcomm-kommbox-4352.json'
        out, report = nand_tools.prepare(source, profile, self.folder/'gui outputs')
        self.assertEqual(Path(out).read_bytes(), clean)
        self.assertEqual(report['corrected_bits'], 1)
        with q.open_image(out) as fh:
            self.assertTrue(any(v['kind'] == 'ubi' for v in q.volumes(fh, q.image_size(fh))))

    def test_invalid_profile_partial_page_and_uncorrectable_abort(self):
        profile = ROOT/'nand_tools/profiles/qualcomm-kommbox-4352.json'
        source = self.folder/'broken.bin'
        output = self.folder/'failed outputs'
        source.write_bytes(b'partial page')
        with self.assertRaisesRegex(ValueError, 'complete physical pages'):
            nand_tools.prepare(source, profile, output)
        self.assertEqual(list(output.iterdir()), [])
        page = bytearray(pack_page(bytes(4096), generator()))
        for bit in range(9):
            page[bit//8] ^= 1 << (7-bit % 8)
        source.write_bytes(page)
        with self.assertRaisesRegex(ValueError, 'uncorrectable BCH'):
            nand_tools.prepare(source, profile, output)
        self.assertEqual(source.read_bytes(), page)
        self.assertEqual(list(output.iterdir()), [])
        bad = json.loads(profile.read_text()); bad['operations'][0]['ecc_range'] = [0, 13]
        cfg = self.folder/'invalid.json'; cfg.write_text(json.dumps(bad))
        with self.assertRaisesRegex(ValueError, 'overlapping'):
            nand_tools.prepare(source, cfg, output)
        self.assertEqual(list(output.iterdir()), [])

    def test_conflicting_modes_are_refused_before_reconstruction(self):
        p = subprocess.run([sys.executable, str(ROOT/'qnxprobe.py'), '--nand-profile',
                            str(self.profile), '--ftl100', str(self.source)], capture_output=True, text=True)
        self.assertEqual(p.returncode, 2)
        self.assertIn('select only one', p.stderr)


if __name__ == '__main__':
    unittest.main()
