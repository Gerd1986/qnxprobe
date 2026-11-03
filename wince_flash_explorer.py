#!/usr/bin/env python3
"""WinCE MSFLSH60 Flash Explorer 1.4.0. Python 3.10+, standard library only.
Read-only source access. Experimental AutoFlash partition-relative reconstruction;
optional verified Jacinto ECC. No checkpoint recovery.

Start unter Windows: py -3 wince_flash_explorer.py
Optional: py -3 wince_flash_explorer.py fiat_flash.dmp
Ohne GUI: py -3 wince_flash_explorer.py fiat_flash.dmp --inspect

Dump vorher entpacken. Partition im unteren Baum aufklappen, dann Ordner
aufklappen. Exportbuttons gelten fuer die Auswahl im Inhaltsbaum.
Logisches Image: Page-Nutzdaten nach lokaler LBA, ohne Spare; fehlende Pages
werden Nullbytes. Rohbereich: physische Reihenfolge inkl. Spare und Metadaten.
Datei-/Ordnerexport legt einen JSON-Bericht mit SHA256 und fehlenden LBAs an.
Vorhandene Dateiexportziele werden nicht ueberschrieben. Abgebrochene Exporte
koennen unvollstaendige Dateien hinterlassen; Bericht bzw. .partial beachten.
PART00 mit CE-ROM: NB0-Images, Modul-TOC-Metadaten und gespeicherte Dateien.
CE-komprimierte Dateien behalten die Endung .cecompressed; keine Dekompression.
Tabellenfelder und physische Grenzen folgen dem untersuchten MSFLSH60-Layout;
bei anderen OEMs Geometrie, Kopien und Grenzen kontrollieren. Keine generische
Erkennung beliebiger FTLs. First/Last wins ersetzt keine Versionsrekonstruktion.
MBR-Image: gewaehlte Partition oder alle Partitionen gemeinsam (maximal vier).
Binär-/Firmwarebereiche bleiben logisch unveraendert und erhalten Typ 0xDA.
Bei exFAT: separate abgeleitete Kopie mit neu erzeugten
Bootregionen und umgerechneten Sektorfeldern. Keine bitidentische Rekonstruktion!
Cluster/FAT-Bytepositionen bleiben erhalten. FTK-Kompatibilitaet nicht garantiert.
LBA-Abdeckung pruefen: unterscheidet freie und laut Bitmap belegte Luecken.
ExFAT-Imageexport stoppt bei fehlenden belegten Pages, ausser die ausdrueckliche
Nullfuellungsoption wird aktiviert. Auch dann bleiben die LBA-Positionen erhalten.
ECC nur pruefen / ECC pruefen + anwenden: bestaetigtes Jacinto-Profil mit
RS(520,512) GF(1024), 4 Symbolen je 512 Byte, und Hamming(8,4) fuer OOB-Metadaten.
Korrekturen liegen nur im RAM; Quelle und physischer Rohbereich bleiben unveraendert.
Nach Anwenden werden Mapping und Dateiansicht neu aufgebaut. Vollstaendiger
ECC-Bericht als JSON exportierbar; unkorrigierbare Pages werden nicht geraten.
Quellendump wird ausschliesslich lesend geoeffnet; keine Netzwerkzugriffe.
"""
from __future__ import annotations
import argparse
import collections
import csv
from dataclasses import dataclass, field, asdict
import hashlib
import json
import math
import mmap
import os
from pathlib import Path
import queue
import re
import struct
import threading
import traceback

VERSION = '1.4.0'


class Cancelled(Exception):
    pass


def check_cancel(event):
    if event is not None and event.is_set():
        raise Cancelled('Abgebrochen')


@dataclass
class Geometry:
    page_size: int = 2112
    data_size: int = 2048
    pages_per_block: int = 64
    header_offset: int = 2090
    header_value: int = 0x92
    lba_offset: int = 2094
    lba_bytes: int = 4
    first_data_block: int | None = None

    def validate(self):
        if not (512 <= self.data_size <= self.page_size <= 65536):
            raise ValueError('Ungültige Page-/Datengröße')
        if not 1 <= self.pages_per_block <= 4096:
            raise ValueError('Ungültige Pages pro Löschblock')
        if not 0 <= self.header_value <= 255:
            raise ValueError('Header muss ein Byte sein')
        if not 0 <= self.header_offset < self.page_size:
            raise ValueError('Headerposition außerhalb der Page')
        if self.lba_bytes not in (3, 4):
            raise ValueError('LBA-Länge muss 3 oder 4 Byte sein')
        if not 0 <= self.lba_offset <= self.page_size - self.lba_bytes:
            raise ValueError('LBA außerhalb der Page')
        if self.first_data_block is not None and self.first_data_block < 0:
            raise ValueError('Startblock muss positiv sein')


@dataclass
class Partition:
    name: str
    index: int
    logical_blocks: int
    physical_blocks: int
    start_block: int
    end_block: int
    policy: str = 'last'
    mapping: dict = field(default_factory=dict, repr=False)
    scanned: bool = False
    duplicates: int = 0
    rejected: int = 0
    header_pages: int = 0
    copies: list = field(default_factory=list)

    def summary(self, geometry):
        d = {k: v for k, v in vars(self).items() if k != 'mapping'}
        d.update(raw_start=self.start_block * geometry.pages_per_block * geometry.page_size,
                 raw_end_exclusive=self.end_block * geometry.pages_per_block * geometry.page_size,
                 logical_bytes=self.logical_blocks * geometry.pages_per_block * geometry.data_size,
                 mapped_pages=len(self.mapping))
        return d


@dataclass
class Entry:
    name: str
    cluster: int
    size: int
    valid_size: int
    is_dir: bool
    contiguous: bool
    checksum_ok: bool = True
    entry_offset: int = 0


HAM_CODES = bytes.fromhex('00c1925364a5f63738f9aa6b5c9dce0f')
HAM_DECODE = []
for _value in range(256):
    _dist = [(_value ^ code).bit_count() for code in HAM_CODES]
    _best = min(_dist)
    HAM_DECODE.append((_dist.index(_best), _best) if _best <= 1 else (None, _best))

class JacintoECC:
    def __init__(self):
        self.exp = [0] * 2046
        self.log = [-1] * 1024
        value = 1
        for i in range(1023):
            self.exp[i] = value
            self.log[value] = i
            value <<= 1
            if value & 1024:
                value ^= 0x409
        self.exp[1023:] = self.exp[:1023]
        generator = [1]
        for root in range(1, 9):
            result = [0] * (len(generator) + 1)
            for i, coef in enumerate(generator):
                result[i] ^= coef
                result[i + 1] ^= self.mul(coef, self.exp[root])
            generator = result
        self.encode_table = []
        for value in range(1024):
            word = 0
            for coef in generator[1:]:
                word = (word << 10) | self.mul(value, coef)
            self.encode_table.append(word)
        self.mask = (1 << 80) - 1
        self.constant_ecc = {bytes(512): 0}
        self.constant_ecc[b'\xff' * 512] = self.encode(b'\xff' * 512)

    def mul(self, a, b):
        return self.exp[self.log[a] + self.log[b]] if a and b else 0

    def div(self, a, b):
        if not b:
            raise ValueError('GF division by zero')
        return self.exp[(self.log[a] - self.log[b]) % 1023] if a else 0

    def encode(self, data):
        cached = getattr(self, 'constant_ecc', {}).get(data)
        if cached is not None:
            return cached
        reg = 0
        table, mask = self.encode_table, self.mask
        for value in data:
            reg = ((reg << 10) & mask) ^ table[(reg >> 70) ^ value]
        return reg

    def syndrome(self, word):
        coefficients = [(word >> shift) & 1023 for shift in range(70, -1, -10)]
        result = []
        for root in range(1, 9):
            value = 0
            alpha = self.exp[root]
            for coef in coefficients:
                value = self.mul(value, alpha) ^ coef
            result.append(value)
        return result

    def correct_chunk(self, data, ecc):
        stored = int.from_bytes(ecc, 'little')
        delta = stored ^ self.encode(data)
        if not delta:
            return data, ecc, 'clean', []
        # Erased chunks without programmed parity are not valid RS codewords.
        if ecc == b'\xff' * 10 and data == b'\xff' * 512:
            return data, ecc, 'erased', []
        synd = self.syndrome(delta)
        C = [1] + [0] * 8
        B = [1] + [0] * 8
        L, m, b = 0, 1, 1
        for n in range(8):
            discrepancy = synd[n]
            for i in range(1, L + 1):
                discrepancy ^= self.mul(C[i], synd[n - i])
            if not discrepancy:
                m += 1
                continue
            old = C[:]
            scale = self.div(discrepancy, b)
            for j in range(9 - m):
                C[j + m] ^= self.mul(scale, B[j])
            if 2 * L <= n:
                L, B, b, m = n + 1 - L, old, discrepancy, 1
            else:
                m += 1
        if not 1 <= L <= 4:
            return data, ecc, 'uncorrectable', []
        positions = []
        for pos in range(520):
            z = self.exp[(-(519 - pos)) % 1023]
            value = C[L]
            for i in range(L - 1, -1, -1):
                value = self.mul(value, z) ^ C[i]
            if value == 0:
                positions.append(pos)
        if len(positions) != L:
            return data, ecc, 'uncorrectable', []
        matrix = []
        for row in range(L):
            matrix.append([self.exp[((519 - pos) * (row + 1)) % 1023] for pos in positions] + [synd[row]])
        for col in range(L):
            pivot = next((r for r in range(col, L) if matrix[r][col]), None)
            if pivot is None:
                return data, ecc, 'uncorrectable', []
            matrix[col], matrix[pivot] = matrix[pivot], matrix[col]
            scale = matrix[col][col]
            matrix[col] = [self.div(v, scale) for v in matrix[col]]
            for row in range(L):
                if row == col:
                    continue
                scale = matrix[row][col]
                matrix[row] = [a ^ self.mul(scale, v) for a, v in zip(matrix[row], matrix[col])]
        symbols = list(data) + [(stored >> shift) & 1023 for shift in range(70, -1, -10)]
        changes = []
        for index, pos in enumerate(positions):
            value = symbols[pos] ^ matrix[index][-1]
            if pos < 512 and value > 255:
                return data, ecc, 'uncorrectable', []
            changes.append(dict(symbol=pos, before=symbols[pos], after=value))
            symbols[pos] = value
        new_data = bytes(symbols[:512])
        parity = 0
        for symbol in symbols[512:]:
            parity = (parity << 10) | symbol
        if self.encode(new_data) != parity:
            return data, ecc, 'uncorrectable', []
        return new_data, parity.to_bytes(10, 'little'), 'corrected', changes

    def correct_metadata(self, page):
        out = bytearray(page)
        details = []
        statuses = []
        for name, offset, parity_offset in [('lba', 2094, 2102), ('reserved', 2098, 2106)]:
            if page[parity_offset:parity_offset + 4] == b'\xff' * 4:
                statuses.append('unprotected')
                continue
            status = 'clean'
            changes = []
            for i in range(4):
                value, parity = page[offset + i], page[parity_offset + i]
                result = 0
                for shift in (0, 4):
                    coded = ((value >> shift) & 15) | (((parity >> shift) & 15) << 4)
                    nibble, distance = HAM_DECODE[coded]
                    if nibble is None:
                        status = 'uncorrectable'
                        break
                    result |= nibble << shift
                    if distance:
                        if status != 'uncorrectable':
                            status = 'corrected'
                        changes.append(dict(offset=offset+i, nibble_shift=shift, code_before=coded,
                                            code_after=HAM_CODES[nibble]))
                if status == 'uncorrectable':
                    break
                out[offset+i] = result
                out[parity_offset+i] = (HAM_CODES[result & 15] >> 4) | (HAM_CODES[result >> 4] & 0xf0)
            if status == 'uncorrectable':
                out[offset:offset+4] = page[offset:offset+4]
                out[parity_offset:parity_offset+4] = page[parity_offset:parity_offset+4]
            statuses.append(status)
            if changes and status != 'uncorrectable':
                details.append(dict(area=name, changes=changes))
        return bytes(out), statuses, details

    def validate_profile(self, dump):
        samples = clean = 0
        seen = set()
        for page in range(0, dump.pages, max(1, dump.pages // 512)):
            original = dump.raw[page*2112:(page+1)*2112]
            if len(original) != 2112 or original[2090] != 0x92:
                continue
            for chunk in range(4):
                data = original[chunk*512:(chunk+1)*512]
                ecc = original[2050+chunk*10:2060+chunk*10]
                if data in (bytes(512), b'\xff'*512) or data+ecc in seen:
                    continue
                seen.add(data+ecc)
                samples += 1
                clean += int.from_bytes(ecc,'little') == self.encode(data)
                break
            if samples >= 128:
                break
        if samples < 32 or clean / samples < 0.85:
            raise ValueError('Jacinto-ECC-Profil nicht bestätigt: %d/%d unterschiedliche Datenblöcke '
                             'haben exakt passende ECC. Keine Korrektur angewendet.' % (clean, samples))
        return dict(nonconstant_distinct_samples=samples, exact_ecc_matches=clean,
                    match_rate=clean/samples, confirmed=True)

    def header_candidate(self, page, original):
        if (original[2090] ^ 0x92).bit_count() != 1:
            return None
        decoded, metadata_status, _ = self.correct_metadata(original)
        if any(status not in ('clean', 'corrected') for status in metadata_status):
            return None
        rs_status = [self.correct_chunk(original[k*512:(k+1)*512], original[2050+k*10:2060+k*10])[2]
                     for k in range(4)]
        if any(status not in ('clean', 'corrected') for status in rs_status):
            return None
        return dict(physical_page=page, raw_offset=page*2112, observed_header=original[2090],
                    expected_header=0x92, candidate_lba=int.from_bytes(decoded[2094:2098], 'little'),
                    metadata_status=metadata_status, rs_status=rs_status, applied=False,
                    note='Nur Kandidat: Header ist nicht ECC-geschützt; keine automatische Änderung.')

    def audit(self, dump, progress=None, cancel=None):
        from collections import Counter
        import hashlib
        if (dump.g.page_size, dump.g.data_size, dump.g.header_offset, dump.g.header_value,
            dump.g.lba_offset) != (2112, 2048, 2090, 0x92, 2094):
            raise ValueError('ECC-Profil nur für bestätigtes Jacinto-Layout 2048+64 / Header 0x92 / LBA 2094.')
        validation = self.validate_profile(dump)
        stats = Counter()
        corrections = []
        failures = []
        header_candidates = []
        patches = {}
        bad_data, bad_lba = set(), set()
        for page in range(dump.pages):
            if page % 1024 == 0:
                if cancel is not None and cancel.is_set():
                    raise ValueError('ECC-Prüfung abgebrochen; keine neuen Korrekturen angewendet.')
                if progress:
                    progress('ECC: %.1f %% · %d korrigierte Pages' % (100*page/dump.pages, len(patches)))
            original = dump.raw[page*2112:(page+1)*2112]
            if original == b'\xff'*2112:
                stats['erased_pages'] += 1
                continue
            if original[2090] != 0x92:
                stats['pages_other_header_unchecked'] += 1
                candidate = self.header_candidate(page, original)
                if candidate is not None:
                    header_candidates.append(candidate)
                continue
            stats['checked_pages'] += 1
            corrected, statuses, meta = self.correct_metadata(original)
            for name, status in zip(('lba', 'reserved'), statuses):
                stats['metadata_'+name+'_'+status] += 1
                if name == 'lba' and status == 'uncorrectable':
                    bad_lba.add(page)
            data = bytearray(corrected)
            chunks = []
            failed = []
            for k in range(4):
                begin, parity = k*512, 2050+k*10
                fixed, ecc, status, changes = self.correct_chunk(original[begin:begin+512], original[parity:parity+10])
                stats['rs_chunks_'+status] += 1
                if status == 'corrected':
                    data[begin:begin+512] = fixed
                    data[parity:parity+10] = ecc
                    chunks.append(dict(chunk=k, changes=changes))
                    stats['corrected_data_symbols'] += sum(c['symbol']<512 for c in changes)
                    stats['corrected_parity_symbols'] += sum(c['symbol']>=512 for c in changes)
                elif status == 'uncorrectable':
                    failed.append(k)
                    bad_data.add(page)
            if failed or 'uncorrectable' in statuses:
                failures.append(dict(physical_page=page, raw_offset=page*2112,
                                     rs_uncorrectable_chunks=failed, metadata_status=statuses))
            if bytes(data) != original:
                patches[page] = bytes(data)
                corrections.append(dict(physical_page=page, raw_offset=page*2112,
                    original_lba=int.from_bytes(original[2094:2098],'little'),
                    corrected_lba=int.from_bytes(data[2094:2098],'little'),
                    metadata=meta, rs=chunks,
                    sha256_before=hashlib.sha256(original).hexdigest(),
                    sha256_after=hashlib.sha256(data).hexdigest()))
        stats['corrected_pages'] = len(patches)
        stats['changed_lba_values'] = sum(c['original_lba'] != c['corrected_lba'] for c in corrections)
        stats['pages_with_uncorrectable_data'] = len(bad_data)
        stats['pages_with_uncorrectable_lba'] = len(bad_lba)
        report = dict(profile='Jacinto RS GF(1024), polynomial 0x409, roots 1..8 + Hamming(8,4)',
            source=str(dump.path), source_size=len(dump.raw), source_sha256=hashlib.sha256(dump.raw).hexdigest(), validation=validation, counts=dict(stats),
            data_layout=dict(data_chunks=4, chunk_bytes=512, ecc_bytes_per_chunk=10,
                             ecc_start=2050, gf_symbol_bits=10, data_symbol_bits=8, correction_limit_symbols=4),
            metadata_layout=dict(lba_bytes=[2094,2098],lba_ecc_bytes=[2102,2106],
                                 reserved_bytes=[2098,2102],reserved_ecc_bytes=[2106,2110]),
            corrections=corrections, failures=failures, header_candidates=header_candidates,
            limitations=['Korrektur bis vier RS-Symbole je 512 Byte; jenseits dieser Grenze sind Fehlkorrekturen grundsätzlich möglich.',
                         'Nibble-ECC mit Mindestabstand 3: ein Bit korrigierbar; Mehrfachfehler nicht zuverlässig erkennbar, Fehlkorrekturen möglich.',
                         'Headerbytes 2090..2093 werden nicht korrigiert. Pages mit anderem Header bleiben ungeprüft.',
                         'Unkorrigierbare Daten bleiben unverändert und werden als ungeklärt protokolliert.',
                         'Keine Checkpoint-/Versionsauswahl; ECC-Konsistenz beweist keine Aktualität.'])
        return report, patches, bad_data, bad_lba


class FlashDump:
    def __init__(self, path, geometry=None, cancel=None, progress=None):
        self.path = Path(path).resolve()
        self.g = geometry or Geometry()
        self.g.validate()
        self.cancel = cancel
        self.progress = progress or (lambda text: None)
        self.f = self.path.open('rb')
        try:
            if self.path.stat().st_size < self.g.page_size:
                raise ValueError('Dump ist zu klein')
            self.raw = mmap.mmap(self.f.fileno(), 0, access=mmap.ACCESS_READ)
            self.pages = len(self.raw) // self.g.page_size
            self.warnings = []
            self.page_patches = {}
            self.ecc_bad_data = set()
            self.ecc_bad_lba = set()
            self.ecc_report = None
            self.ecc_last_report = None
            self.ecc_applied = False
            if len(self.raw) % self.g.page_size:
                self.warnings.append('Unvollständige letzte Page wird nicht gemappt.')
            self.table_offsets = []
            self.partitions = self._tables()
        except Exception:
            self.close()
            raise

    def close(self):
        if getattr(self, 'raw', None) is not None:
            self.raw.close()
            self.raw = None
        if getattr(self, 'f', None) is not None:
            self.f.close()
            self.f = None

    def _tables(self):
        g = self.g
        self.progress('MSFLSH60-Tabellen suchen …')
        records = []
        pos = 0
        while True:
            check_cancel(self.cancel)
            off = self.raw.find(b'MSFLSH60', pos)
            if off < 0:
                break
            pos = off + 8
            if off % g.page_size or off + 120 > len(self.raw):
                continue
            b = self.raw[off:off + 120]
            name = b[8:72].decode('utf-16le', 'replace').split('\0')[0]
            logical, physical = struct.unpack_from('<QQ', b, 72)
            index = struct.unpack_from('<I', b, 116)[0]
            if not re.fullmatch(r'PART\d{2,4}', name) or index > 255:
                continue
            if not 0 < logical <= physical <= self.pages // g.pages_per_block:
                continue
            records.append((off, name, index, logical, physical))
        if not records:
            raise ValueError('Keine unterstützte MSFLSH60-Tabelle gefunden. Geometrie prüfen.')
        # Each copy is a consecutive series of partition-entry pages starting at index 0.
        by_offset = {r[0]: r for r in records}
        groups = []
        for r in records:
            if r[2] != 0:
                continue
            group = []
            for idx in range(256):
                row = by_offset.get(r[0] + idx * g.page_size)
                if row is None or row[2] != idx:
                    break
                group.append(row)
            if group:
                groups.append(group)
        if not groups:
            raise ValueError('Keine vollständige Tabellenfolge ab PART00 erkannt.')
        # Prefer the most complete repeated table, rather than merging unrelated entries.
        max_count = max(map(len, groups))
        groups = [x for x in groups if len(x) == max_count]
        signatures = collections.Counter(tuple(tuple(r[1:]) for r in group) for group in groups)
        signature, copies = signatures.most_common(1)[0]
        winners = [x for x in groups if tuple(tuple(r[1:]) for r in x) == signature]
        self.table_offsets = [x[0][0] for x in winners]
        self.table_copy_count = copies
        if len(signatures) > 1:
            self.warnings.append('Abweichende Tabellenkopien: häufigste vollständige Variante gewählt.')
        metadata_end = max(r[0] // g.page_size // g.pages_per_block
                           for group in winners for r in group) + 1
        base = g.first_data_block if g.first_data_block is not None else metadata_end
        self.base_block = base
        self.warnings.append('Physische Bereiche kumulativ ab Block %d abgeleitet; '
                             'Bad-Block-Remapping/Checkpoints werden nicht ausgewertet.' % base)
        parts = []
        for name, index, logical, physical in signature:
            end = base + physical
            if end * g.pages_per_block > self.pages:
                raise ValueError('Partitionen überschreiten den Dump. Startblock/Geometrie prüfen.')
            part = Partition(name, index, logical, physical, base, end)
            part.copies = [group[index][0] for group in winners]
            parts.append(part)
            base = end
        return parts

    def audit_ecc(self, apply=False):
        report, patches, bad_data, bad_lba = JacintoECC().audit(self, self.progress, self.cancel)
        report['applied_to_logical_view'] = bool(apply)
        self.ecc_last_report = report
        if apply:
            # Commit only after the complete scan and validation have succeeded.
            self.page_patches = patches
            self.ecc_bad_data = bad_data
            self.ecc_bad_lba = bad_lba
            self.ecc_report = report
            self.ecc_applied = True
            for part in self.partitions:
                part.mapping.clear()
                part.scanned = False
        return report

    def clear_ecc(self):
        self.page_patches.clear()
        self.ecc_bad_data.clear()
        self.ecc_bad_lba.clear()
        self.ecc_applied = False
        self.ecc_report = None
        for part in self.partitions:
            part.mapping.clear()
            part.scanned = False

    def physical_page(self, page):
        corrected = self.page_patches.get(page)
        if corrected is not None:
            return corrected
        off = page * self.g.page_size
        return self.raw[off:off + self.g.page_size]

    def ecc_summary(self):
        if not self.ecc_applied or self.ecc_report is None:
            return dict(applied=False, note='Logische Ansicht ohne ECC-Korrektur.')
        return dict(applied=True, profile=self.ecc_report['profile'],
                    validation=self.ecc_report['validation'], counts=self.ecc_report['counts'])

    def scan(self, part, policy=None):
        if policy is not None:
            part.policy = policy
        if part.policy not in ('first', 'last'):
            raise ValueError('Unbekannte Duplikatstrategie')
        g = self.g
        mp = {}
        dup = rejected = accepted = 0
        maximum = part.logical_blocks * g.pages_per_block
        sentinel = (1 << (g.lba_bytes * 8)) - 1
        for page in range(part.start_block * g.pages_per_block,
                          part.end_block * g.pages_per_block):
            if page % 4096 == 0:
                check_cancel(self.cancel)
                self.progress('%s: Mapping Page %d …' % (part.name, page))
            off = page * g.page_size
            page_data = self.physical_page(page)
            if page_data[g.header_offset] != g.header_value:
                continue
            accepted += 1
            if self.ecc_applied and page in self.ecc_bad_lba:
                rejected += 1
                continue
            lba = int.from_bytes(page_data[g.lba_offset:g.lba_offset + g.lba_bytes], 'little')
            if lba == sentinel or lba >= maximum:
                rejected += 1
                continue
            if lba in mp:
                dup += 1
                if part.policy == 'first':
                    continue
            mp[lba] = page
        check_cancel(self.cancel)
        part.mapping = mp
        part.duplicates, part.rejected, part.header_pages = dup, rejected, accepted
        part.scanned = True

    def sector(self, part, lba, missing=None):
        if not part.scanned:
            self.scan(part)
        if not 0 <= lba < part.logical_blocks * self.g.pages_per_block:
            raise ValueError('Sektor außerhalb der Partition: %d' % lba)
        page = part.mapping.get(lba)
        if page is None:
            if missing is not None:
                missing.add(lba)
            return bytes(self.g.data_size)
        off = page * self.g.page_size
        return self.physical_page(page)[:self.g.data_size]

    def guard_output(self, path):
        path = Path(path)
        if path.resolve() == self.path or (path.exists() and os.path.samefile(path, self.path)):
            raise ValueError('Quelldump darf nicht überschrieben werden')
        return path

    def export_partition(self, part, path, raw=False, allow_holes=False):
        coverage = None
        if not raw:
            try:
                fs = Exfat(self, part)
            except ValueError:
                fs = None
            if fs is not None:
                coverage = fs.coverage()
                require_coverage(coverage, allow_holes)
        path = self.guard_output(path)
        temp = Path(str(path) + '.partial')
        self.guard_output(temp)
        report_path = Path(str(path) + '.report.json')
        self.guard_output(report_path)
        if report_path.exists():
            raise ValueError('Berichtsdatei existiert bereits: %s' % report_path)
        digest = hashlib.sha256()
        holes = 0
        try:
            # Exclusive temporary file: no silent overwrite of existing recovery work.
            with temp.open('xb') as out:
                if raw:
                    start = part.start_block * self.g.pages_per_block * self.g.page_size
                    end = part.end_block * self.g.pages_per_block * self.g.page_size
                    for off in range(start, end, 1024 * 1024):
                        check_cancel(self.cancel)
                        data = self.raw[off:min(end, off + 1024 * 1024)]
                        out.write(data)
                        digest.update(data)
                        self.progress('Rohbereich: %.1f %%' % (100 * (off - start) / max(1, end - start)))
                else:
                    if not part.scanned:
                        self.scan(part)
                    count = part.logical_blocks * self.g.pages_per_block
                    for lba in range(0, count, 256):
                        check_cancel(self.cancel)
                        data = bytearray()
                        for s in range(lba, min(count, lba + 256)):
                            if s not in part.mapping:
                                holes += 1
                            data.extend(self.sector(part, s))
                        out.write(data)
                        digest.update(data)
                        self.progress('Logisches Image: %.1f %%' % (100 * lba / count))
            os.replace(temp, path)
        except Exception:
            # Leave partial output explicit and reviewable, never present it as complete.
            raise
        report = dict(version=VERSION, source=str(self.path), source_size=len(self.raw),
                      geometry=asdict(self.g), partition=part.summary(self.g),
                      export_mode='physical_raw_with_spare' if raw else 'logical_data_only',
                      allocation_coverage=coverage, holes_explicitly_allowed=allow_holes,
                      ecc_processing=self.ecc_summary(), ecc_applied_to_payload=self.ecc_applied and not raw,
                      ecc_correction_report=self.ecc_report if not raw else None,
                      output=str(path), output_size=path.stat().st_size,
                      sha256=digest.hexdigest(), zero_filled_missing_pages=holes,
                      warnings=self.warnings + ['ECC optional über die ECC-Schaltflächen; keine Checkpoint-/Versionsrekonstruktion.'])
        report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
        return report


    def _mbr_plan(self, part, start_sector, allow_holes):
        if not part.scanned:
            self.scan(part)
        try:
            fs = Exfat(self, part)
        except ValueError:
            fs = None
        if fs is None:
            count = part.logical_blocks * self.g.pages_per_block
            missing = count - len(part.mapping)
            bad = sum(page in self.ecc_bad_data for page in part.mapping.values())
            if (missing or bad) and not allow_holes:
                raise ValueError('%s: %d fehlende Pages im Binärbereich. Ohne Allocation-Bitmap '
                                 'ist keine Belegt/Frei-Unterscheidung möglich; ggf. unkorrigierbare ECC-Pages. Für diesen Export '
                                 'muss die ausdrückliche Nullfüllungsoption aktiviert sein.' % (part.name, missing))
            length = count * self.g.data_size
            if length % 512:
                raise ValueError('Binärbereich ist nicht auf 512 Byte ausgerichtet')
            return dict(part=part, sectors=length // 512, original_pages=count,
                        start_sector=start_sector, mbr_type=0xda, patch=b'',
                        source_filesystem=dict(format='Binär-/Firmwarebereich',
                            note='Synthetischer Partitionstyp 0xDA; keine Dateisystemkonvertierung.'),
                        allocation_coverage=dict(classification='unknown_no_allocation_bitmap',
                                                 missing_total_pages=missing, ecc_uncorrectable_mapped_pages=bad),
                        modifications=['MBR-Hülle ergänzt; logische Partitionsbytes nicht verändert.'])
        coverage = fs.coverage()
        require_coverage(coverage, allow_holes)
        factor = self.g.data_size // 512
        if self.g.data_size % 512 or factor not in (1, 2, 4, 8):
            raise ValueError('Sektorgröße kann nicht auf 512 Byte umgerechnet werden')
        source_boot = fs.boot
        volume_sectors = fs.volume_sectors * factor
        fat_start_bytes = struct.unpack_from('<I', source_boot, 80)[0] * self.g.data_size
        if fat_start_bytes < 24 * 512:
            raise ValueError('Bootbereich würde die FAT überlappen')
        boot = bytearray(source_boot[:512])
        boot[:3] = b'\xeb\x76\x90'
        boot[11:64] = bytes(53)
        struct.pack_into('<Q', boot, 64, start_sector)
        struct.pack_into('<Q', boot, 72, volume_sectors)
        for offset in (80, 84, 88):
            struct.pack_into('<I', boot, offset, struct.unpack_from('<I', source_boot, offset)[0] * factor)
        flags = struct.unpack_from('<H', source_boot, 106)[0]
        main = self.sector(part, 0)
        if fs._valid_boot(main) and all(main[a:b] == source_boot[a:b] for a, b in ((72, 104), (108, 111))):
            flags = struct.unpack_from('<H', main, 106)[0]
        struct.pack_into('<H', boot, 106, flags & 0x000f)
        boot[108] = 9
        boot[109] = source_boot[109] + factor.bit_length() - 1
        boot[113:120] = bytes(7)
        boot[120:510] = bytes(390)
        boot[510:512] = b'\x55\xaa'
        region = bytearray(11 * 512)
        region[:512] = boot
        for sector in range(1, 9):
            region[sector * 512 + 508:sector * 512 + 512] = b'\0\0\x55\xaa'
        checksum = 0
        for index, value in enumerate(region):
            if index not in (106, 107, 112):
                checksum = (((checksum & 1) << 31) + (checksum >> 1) + value) & 0xffffffff
        region.extend(struct.pack('<I', checksum) * 128)
        return dict(part=part, sectors=volume_sectors, original_pages=fs.volume_sectors,
                    start_sector=start_sector, mbr_type=7, patch=bytes(region + region),
                    source_filesystem=fs.info(), allocation_coverage=coverage,
                    modifications=[
                        'Synthetischer MBR-Partitionseintrag 0x07 und 1-MiB-Ausrichtung.',
                        'Erste 12288 Volume-Bytes durch zwei synthetische Bootregionen ersetzt.',
                        'Sektorgröße auf 512 Byte umgerechnet; Cluster-Bytegröße unverändert.',
                        'VolumeLength, FAT-Offsets/-Länge und HeapOffset auf 512-Byte-Einheiten umgerechnet.',
                        'PartitionOffset auf tatsächlichen MBR-Start gesetzt; reservierte Bootfelder normalisiert.',
                        'PC-Bootcode/OEM-Parameter der synthetischen Bootregion nicht übernommen.',
                        'Erweiterte Bootsignaturen und beide Bootprüfsummen neu erzeugt.',
                        'FATs, Clusteradressen, Verzeichnisse und Dateidaten außerhalb des Bootpatches unverändert.'])

    def export_mbr(self, parts, path, allow_holes=False):
        """One to four logical partitions in a derived, 512-byte MBR disk image.

        exFAT is converted at the boot-metadata level only. Non-exFAT partitions
        are included as unmodified logical binary payloads (including zero-filled
        holes explicitly authorized by allow_holes). This does not turn ROM into
        a filesystem, implement checkpoint recovery, or guarantee FTK support.
        """
        parts = list(parts)
        if not 1 <= len(parts) <= 4:
            raise ValueError('MBR-Export unterstützt eine bis vier primäre Partitionen')
        if len({id(part) for part in parts}) != len(parts):
            raise ValueError('Eine Partition wurde mehrfach ausgewählt')
        path = self.guard_output(path)
        temp = self.guard_output(Path(str(path) + '.partial'))
        report_path = self.guard_output(Path(str(path) + '.report.json'))
        if report_path.exists():
            raise ValueError('Berichtsdatei existiert bereits: %s' % report_path)
        # Preflight every partition before creating any output file.
        plans = []
        start = 2048
        for part in parts:
            check_cancel(self.cancel)
            plan = self._mbr_plan(part, start, allow_holes)
            if not 0 < plan['sectors'] <= 0xffffffff or start + plan['sectors'] > 0x100000000:
                raise ValueError('MBR-LBA-Grenze überschritten; GPT wäre erforderlich')
            plans.append(plan)
            start = ((start + plan['sectors'] + 2047) // 2048) * 2048
        mbr = bytearray(512)
        mbr[440:444] = b'WCEF'
        for index, plan in enumerate(plans):
            mbr[446 + index * 16:462 + index * 16] = struct.pack(
                '<B3sB3sII', 0, b'\xfe\xff\xff', plan['mbr_type'], b'\xfe\xff\xff',
                plan['start_sector'], plan['sectors'])
        mbr[510:512] = b'\x55\xaa'
        digest = hashlib.sha256()
        results = []
        with temp.open('xb') as out:
            out.write(mbr)
            digest.update(mbr)
            for index, plan in enumerate(plans):
                gap = plan['start_sector'] * 512 - out.tell()
                while gap:
                    check_cancel(self.cancel)
                    data = bytes(min(gap, 1024 * 1024))
                    out.write(data)
                    digest.update(data)
                    gap -= len(data)
                part, patch = plan['part'], plan['patch']
                original_digest = hashlib.sha256()
                payload_digest = hashlib.sha256()
                missing = 0
                for lba in range(0, plan['original_pages'], 256):
                    check_cancel(self.cancel)
                    data = bytearray()
                    for sector in range(lba, min(plan['original_pages'], lba + 256)):
                        if sector not in part.mapping:
                            missing += 1
                        data.extend(self.sector(part, sector))
                    original_digest.update(data)
                    byte_offset = lba * self.g.data_size
                    if byte_offset < len(patch):
                        count = min(len(data), len(patch) - byte_offset)
                        data[:count] = patch[byte_offset:byte_offset + count]
                    out.write(data)
                    digest.update(data)
                    payload_digest.update(data)
                    self.progress('MBR %d/%d · %s: %.1f %%' % (
                        index + 1, len(plans), part.name, 100 * lba / plan['original_pages']))
                item = dict(partition=part.summary(self.g),
                            mbr_type='0x%02X' % plan['mbr_type'],
                            partition_start_sector=plan['start_sector'],
                            partition_sector_count=plan['sectors'],
                            disk_byte_offset=plan['start_sector'] * 512,
                            source_filesystem=plan['source_filesystem'],
                            allocation_coverage=plan['allocation_coverage'],
                            original_logical_volume_sha256=original_digest.hexdigest(),
                            exported_partition_sha256=payload_digest.hexdigest(),
                            zero_filled_missing_original_pages=missing,
                            partition_metadata_modified=bool(patch), modifications=plan['modifications'])
                if patch:
                    item['original_boot_region_prefix_hex'] = b''.join(self.sector(part, i) for i in range(
                        math.ceil(len(patch) / self.g.data_size)))[:len(patch)].hex()
                    item['new_boot_region_hex'] = patch.hex()
                results.append(item)
        os.replace(temp, path)
        report = dict(version=VERSION, source=str(self.path), geometry=asdict(self.g),
                      export_mode='DERIVED_MBR_DISK_512', bit_identical=False,
                      holes_explicitly_allowed=allow_holes, output=str(path),
                      output_size=path.stat().st_size, output_sha256=digest.hexdigest(),
                      output_sector_size=512, partitions=results,
                      ecc_processing=self.ecc_summary(), ecc_correction_report=self.ecc_report,
                      warnings=['Abgeleitete Analysekopie mit synthetischem MBR.',
                                'Binär-/Firmware-Partitionen werden durch den MBR nicht zu exFAT.',
                                'Zwei FATs/TexFAT-Strukturen bleiben erhalten; FTK-Kompatibilität nicht verifiziert.',
                                'ECC-Modus siehe ecc_processing; keine Checkpoint-Recovery; erlaubte Lücken bleiben nullgefüllt.'])
        # Preserve the single-partition API/report fields from versions 1.2.x.
        if len(results) == 1:
            report.update(results[0])
        report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
        return report

    def export_compatible(self, part, path, allow_holes=False):
        return self.export_mbr([part], path, allow_holes)

    def export_all_mbr(self, path, allow_holes=False):
        return self.export_mbr(self.partitions, path, allow_holes)



class Exfat:
    def __init__(self, dump, part):
        self.d, self.p = dump, part
        self.missing = set()
        self.ecc_unverified_reads = set()
        if not part.scanned:
            dump.scan(part)
        self.boot_source = None
        for lba in (0, 12):
            b = dump.sector(part, lba)
            if self._valid_boot(b):
                self.boot_source, self.boot = lba, b
                # Prefer a boot region with a valid checksum; fall back to a
                # structurally plausible boot only if neither copy verifies.
                if self._boot_checksum(lba):
                    break
        if self.boot_source is None:
            raise ValueError('Kein plausibler exFAT-Bootsektor bei LBA 0 oder 12; '
                             'Partition als logisches oder physisches Image exportierbar.')
        b = self.boot
        self.volume_sectors = struct.unpack_from('<Q', b, 72)[0]
        self.fat_offset, self.fat_length, self.heap, self.clusters, self.root = struct.unpack_from('<5I', b, 80)
        self.spc = 1 << b[109]
        self.cluster_bytes = self.spc * dump.g.data_size
        self.active_fat = (struct.unpack_from('<H', b, 106)[0] & 1) if b[110] == 2 else 0
        self.fat_offset += self.active_fat * self.fat_length

    def _boot_checksum(self, base):
        checksum = 0
        sectors = []
        for lba in range(base, base + 12):
            if lba not in self.p.mapping:
                return False
            sectors.append(self.d.sector(self.p, lba))
        for k, value in enumerate(b''.join(sectors[:11])):
            if k not in (106, 107, 112):
                checksum = (((checksum & 1) << 31) + (checksum >> 1) + value) & 0xffffffff
        return all(int.from_bytes(sectors[11][k:k + 4], 'little') == checksum
                   for k in range(0, self.d.g.data_size, 4))

    def _valid_boot(self, b):
        if len(b) < 512 or b[3:11] != b'EXFAT   ' or b[510:512] != b'\x55\xaa':
            return False
        if not 9 <= b[108] <= 12 or (1 << b[108]) != self.d.g.data_size:
            return False
        if b[109] > 25 - b[108] or b[110] not in (1, 2):
            return False
        length = struct.unpack_from('<Q', b, 72)[0]
        fo, fl, heap, count, root = struct.unpack_from('<5I', b, 80)
        return (0 < length <= self.p.logical_blocks * self.d.g.pages_per_block
                and 24 <= fo < heap < length and fl > 0 and fo + fl * b[110] <= heap
                and 2 <= root < count + 2 and count > 0
                and heap + (count << b[109]) <= length
                and fl * self.d.g.data_size >= (count + 2) * 4)

    def sector(self, lba):
        if not 0 <= lba < self.volume_sectors:
            raise ValueError('exFAT-LBA außerhalb des Volumes')
        if self.p.mapping.get(lba) in getattr(self.d, 'ecc_bad_data', set()):
            self.ecc_unverified_reads.add(lba)
        return self.d.sector(self.p, lba, self.missing)

    def next_cluster(self, cluster):
        off = cluster * 4
        sector = self.sector(self.fat_offset + off // self.d.g.data_size)
        return struct.unpack_from('<I', sector, off % self.d.g.data_size)[0]

    def cluster_chain(self, cluster, contiguous=False, size=None):
        seen = set()
        need = math.ceil(size / self.cluster_bytes) if size is not None else None
        while need is None or len(seen) < need:
            check_cancel(self.d.cancel)
            if not 2 <= cluster < self.clusters + 2:
                raise ValueError('Ungültiger/abgebrochener Clusterverweis: 0x%X' % cluster)
            if cluster in seen:
                raise ValueError('Zyklische FAT-Kette bei Cluster %d' % cluster)
            seen.add(cluster)
            yield cluster
            if need is not None and len(seen) >= need:
                return
            nxt = cluster + 1 if contiguous else self.next_cluster(cluster)
            if nxt >= 0xfffffff8:
                if need is not None and len(seen) < need:
                    raise ValueError('FAT-Kette endet vor der Dateigröße')
                return
            cluster = nxt

    def file_chunks(self, entry, limit=None):
        remaining = entry.size if limit is None else min(entry.size, limit)
        if remaining <= 0:
            return
        pos = 0
        for cluster in self.cluster_chain(entry.cluster, entry.contiguous, remaining):
            start = self.heap + (cluster - 2) * self.spc
            for k in range(self.spc):
                if remaining <= 0:
                    return
                n = min(remaining, self.d.g.data_size)
                if pos >= entry.valid_size:
                    data = bytes(n)
                else:
                    data = self.sector(start + k)[:n]
                    valid = max(0, min(n, entry.valid_size - pos))
                    data = data[:valid] + bytes(n - valid)
                yield data
                pos += n
                remaining -= n

    def directory(self, entry=None):
        cap = 64 * 1024 * 1024
        if entry is not None and entry.size > cap:
            raise ValueError('Verzeichnis größer als 64 MiB; Sicherheitslimit erreicht')
        if entry is None:
            data = bytearray()
            for cluster in self.cluster_chain(self.root):
                if len(data) + self.cluster_bytes > cap:
                    raise ValueError('Root-Verzeichnis überschreitet 64 MiB')
                start = self.heap + (cluster - 2) * self.spc
                block = b''.join(self.sector(start + k) for k in range(self.spc))
                data.extend(block)
                if any(block[j] == 0 for j in range(0, len(block), 32)):
                    break
        else:
            data = b''.join(self.file_chunks(entry))
        entries = []
        j = 0
        while j + 32 <= len(data):
            e = data[j:j + 32]
            if e[0] == 0:
                break
            if e[0] != 0x85:
                j += 32
                continue
            offset = j
            length = (e[1] + 1) * 32
            if not 64 <= length <= 8192 or j + length > len(data):
                raise ValueError('Unvollständiger exFAT-Eintrag bei Offset %d' % j)
            group = data[j:j + length]
            j += length
            streams = [group[k:k + 32] for k in range(32, length, 32) if group[k] == 0xc0]
            if len(streams) != 1:
                continue
            s = streams[0]
            namebytes = b''.join(group[k + 2:k + 32] for k in range(32, length, 32) if group[k] == 0xc1)
            if not s[3] or len(namebytes) < s[3] * 2:
                continue
            name = namebytes[:s[3] * 2].decode('utf-16le', 'replace')
            checksum = 0
            for k, value in enumerate(group):
                if k not in (2, 3):
                    checksum = (((checksum & 1) << 15) + (checksum >> 1) + value) & 65535
            size, valid = int.from_bytes(s[24:32], 'little'), int.from_bytes(s[8:16], 'little')
            entries.append(Entry(name, int.from_bytes(s[20:24], 'little'), size, valid,
                                 bool(e[4] & 16), bool(s[1] & 2),
                                 checksum == int.from_bytes(e[2:4], 'little') and valid <= size, offset))
        return entries

    def coverage(self):
        """Allocation-aware coverage; unknown bitmap pages never imply free space."""
        previous_missing = self.missing
        self.missing = set()
        result = dict(active_fat=self.active_fat, bitmap_complete=False,
                      missing_total_pages=sum(lba not in self.p.mapping for lba in range(self.volume_sectors)),
                      missing_allocated_pages=None, missing_fat_pages=None,
                      missing_root_pages=None, missing_bitmap_pages=None,
                      missing_allocated_lba_ranges=[], warnings=[])
        try:
            root = bytearray()
            root_sectors = []
            for cluster in self.cluster_chain(self.root):
                if len(root) + self.cluster_bytes > 64 * 1024 * 1024:
                    raise ValueError('Root-Verzeichnis überschreitet Coverage-Limit')
                start = self.heap + (cluster - 2) * self.spc
                block = b''.join(self.sector(start + k) for k in range(self.spc))
                root_sectors.extend(range(start, start + self.spc))
                root.extend(block)
                if any(block[j] == 0 for j in range(0, len(block), 32)):
                    break
            root_holes = [l for l in root_sectors if l not in self.p.mapping]
            bad_root = [l for l in root_sectors if self.p.mapping.get(l) in getattr(self.d, 'ecc_bad_data', set())]
            bad_fat = [l for l in range(self.fat_offset, self.fat_offset+self.fat_length)
                       if self.p.mapping.get(l) in getattr(self.d, 'ecc_bad_data', set())]
            result['ecc_uncorrectable_root_pages'] = len(bad_root)
            result['ecc_uncorrectable_fat_pages'] = len(bad_fat)
            result['missing_root_pages'] = len(root_holes)
            result['missing_root_lba_ranges'] = lba_ranges(root_holes)
            records = []
            for j in range(0, len(root), 32):
                record = root[j:j + 32]
                if record[0] == 0:
                    break
                if record[0] == 0x81 and (record[1] & 1) == self.active_fat:
                    records.append((int.from_bytes(record[20:24], 'little'),
                                    int.from_bytes(record[24:32], 'little')))
            if len(records) != 1 or root_holes or bad_root or bad_fat:
                raise ValueError('Root oder aktive FAT unvollständig/mit unkorrigierbaren ECC-Fehlern; Bitmap-Zuordnung nicht verlässlich')
            cluster, size = records[0]
            needed = (self.clusters + 7) // 8
            if size < needed or size > 64 * 1024 * 1024:
                raise ValueError('Ungültige Allocation-Bitmap-Länge')
            # FAT reads are tracked too: a missing chain page makes bitmap coverage unknown.
            bitmap_bad = []
            for bitmap_cluster in self.cluster_chain(cluster, False, size):
                bitmap_start = self.heap + (bitmap_cluster-2)*self.spc
                bitmap_bad.extend(l for l in range(bitmap_start, bitmap_start+self.spc)
                                  if self.p.mapping.get(l) in getattr(self.d, 'ecc_bad_data', set()))
            result['ecc_uncorrectable_bitmap_pages'] = len(bitmap_bad)
            if bitmap_bad:
                raise ValueError('Allocation-Bitmap enthält unkorrigierbare ECC-Daten; Belegung unbekannt')
            self.missing = set()
            bitmap = b''.join(self.file_chunks(Entry('AllocationBitmap', cluster, size, size, False, False)))
            result['missing_bitmap_pages'] = len(self.missing)
            if self.missing:
                raise ValueError('Allocation-Bitmap oder ihre FAT-Kette enthält fehlende Pages')
            result['bitmap_complete'] = True
            allocated_holes = []
            free_holes = allocated_clusters = 0
            bad_allocated = []
            for index in range(self.clusters):
                if index % 8192 == 0:
                    check_cancel(self.d.cancel)
                allocated = bool(bitmap[index // 8] & (1 << (index % 8)))
                allocated_clusters += allocated
                for k in range(self.spc):
                    lba = self.heap + index * self.spc + k
                    if allocated and self.p.mapping.get(lba) in getattr(self.d, 'ecc_bad_data', set()):
                        bad_allocated.append(lba)
                    if lba not in self.p.mapping:
                        if allocated:
                            allocated_holes.append(lba)
                        else:
                            free_holes += 1
            fat_holes = [lba for lba in range(self.fat_offset, self.fat_offset + self.fat_length)
                         if lba not in self.p.mapping]
            result.update(allocated_clusters=allocated_clusters,
                          ecc_uncorrectable_allocated_pages=len(bad_allocated),
                          ecc_uncorrectable_allocated_lba_ranges=lba_ranges(bad_allocated),
                          missing_allocated_pages=len(allocated_holes), missing_free_cluster_pages=free_holes,
                          missing_allocated_lba_ranges=lba_ranges(allocated_holes),
                          missing_fat_pages=len(fat_holes), missing_fat_lba_ranges=lba_ranges(fat_holes))
        except ValueError as exc:
            result['warnings'].append(str(exc))
        finally:
            self.missing = previous_missing | self.missing
        result['safe_without_zero_filling_allocated_data'] = (
            result['bitmap_complete'] and result['missing_allocated_pages'] == 0
            and result['missing_fat_pages'] == 0 and result['missing_root_pages'] == 0
            and result.get('ecc_uncorrectable_allocated_pages', 0) == 0
            and not any(page in getattr(self.d, 'ecc_bad_data', set()) for lba, page in self.p.mapping.items() if lba < self.heap))
        return result

    def info(self):
        checks = {str(base): self._boot_checksum(base) for base in (0, 12)}
        return dict(boot_lba=self.boot_source, volume_bytes=self.volume_sectors * self.d.g.data_size,
                    cluster_bytes=self.cluster_bytes, cluster_count=self.clusters,
                    root_cluster=self.root, active_fat=self.active_fat,
                    boot_checksums=checks)

    def export(self, entry, destination):
        dest = Path(destination)
        if dest.exists():
            raise ValueError('Exportziel muss neu sein: %s' % dest)
        self.d.guard_output(dest)
        report = dict(source=str(self.d.path), partition=self.p.name, policy=self.p.policy,
                      ecc_processing=self.d.ecc_summary(), ecc_correction_report=self.d.ecc_report,
                      geometry=asdict(self.d.g), mapping=self.p.summary(self.d.g),
                      files=[], warnings=[], missing_lbas=[])
        visited = set()
        count = 0

        def walk(e, path, depth=0):
            nonlocal count
            check_cancel(self.d.cancel)
            count += 1
            if count > 200000 or depth > 100:
                raise ValueError('Exportlimit für Dateianzahl/Verzeichnistiefe erreicht')
            if e is None or e.is_dir:
                cl = self.root if e is None else e.cluster
                if cl in visited:
                    report['warnings'].append('Zyklisches/mehrfach referenziertes Verzeichnis: %s' % path)
                    return
                visited.add(cl)
                path.mkdir()
                for child in self.directory(e):
                    if not child.checksum_ok:
                        report['warnings'].append('Eintrag mit ungültiger Prüfsumme übersprungen: %s' % child.name)
                        continue
                    walk(child, unique_child(path, child.name), depth + 1)
            else:
                if not e.checksum_ok:
                    report['warnings'].append('Explizit gewählte Datei hat eine ungültige Eintragsprüfsumme.')
                digest = hashlib.sha256()
                with path.open('xb') as out:
                    for chunk in self.file_chunks(e):
                        out.write(chunk)
                        digest.update(chunk)
                report['files'].append(dict(name=e.name, output=str(path), size=e.size,
                                            sha256=digest.hexdigest(), checksum_ok=e.checksum_ok))
                self.d.progress('Exportiert: %s' % e.name)
        previous_missing = self.missing
        previous_unverified = self.ecc_unverified_reads
        self.missing = set()
        self.ecc_unverified_reads = set()
        report_path = Path(str(dest) + '.report.json')
        if report_path.exists():
            raise ValueError('Bericht existiert bereits: %s' % report_path)
        try:
            walk(entry, dest)
            report['status'] = 'completed'
        except Exception as exc:
            report['status'] = 'incomplete'
            report['warnings'].append(str(exc))
            raise
        finally:
            report['missing_lbas'] = sorted(self.missing)
            report['ecc_uncorrectable_read_lbas'] = sorted(self.ecc_unverified_reads)
            if self.ecc_unverified_reads:
                report['warnings'].append('Export enthält unveränderte Daten aus unkorrigierbaren ECC-Pages; Inhalt unvollständig verifiziert.')
            self.ecc_unverified_reads = previous_unverified | self.ecc_unverified_reads
            report['warnings'].extend(getattr(self, 'export_warnings', []))
            report['warnings'].append('Fehlende Pages werden mit Nullbytes aufgefüllt; ECC-Modus siehe ecc_processing.')
            self.missing = previous_missing | self.missing
            report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
        return report


class FirmwareView(Exfat):
    """Read-only logical bytes and validated CE ROMHDR/TOC views.

    ROM modules are exposed as metadata, NOT fabricated PE/DLL files.
    Compressed FILES records are exported in their stored representation.
    """
    def __init__(self, dump, part):
        self.d, self.p = dump, part
        self.missing = set()
        self.ecc_unverified_reads = set()
        self.root = -1
        self.nodes = {-1: []}
        self.blobs = {}
        self.next_id = -2
        self.length = part.logical_blocks * dump.g.pages_per_block * dump.g.data_size
        self.roms = []
        self.export_warnings = [
            'Firmware-Ansicht: DLL/EXE-Module werden nur als TOC-Metadaten exportiert.',
            'Dateien mit Endung .cecompressed sind gespeicherte CE-Daten, nicht dekomprimiert.']
        if not part.scanned:
            dump.scan(part)
        self.nodes[-1].append(Entry('Partition_logisch.bin', 0, self.length, self.length, False, True))
        candidates = set()
        for n, lba in enumerate(sorted(part.mapping)):
            if n % 2048 == 0:
                check_cancel(dump.cancel)
                dump.progress('%s: Windows-CE-ROM-Strukturen suchen …' % part.name)
            data = dump.sector(part, lba)
            pos = 0
            while True:
                k = data.find(b'ECEC', pos)
                if k < 0:
                    break
                pos = k + 4
                sig = lba * dump.g.data_size + k
                base = sig - 64
                if base < 0 or base in candidates:
                    continue
                try:
                    ptr, relative = struct.unpack('<II', self.read_at(sig + 4, 8))
                    if relative < 76 or relative > self.length - base - 84 or ptr < relative:
                        continue
                    hdr_offset = base + relative
                    hdr = struct.unpack('<21I', self.read_at(hdr_offset, 84))
                    physical_base = ptr - relative
                    first, last, modules, files = hdr[2], hdr[3], hdr[4], hdr[12]
                    if first != physical_base or not first < last or base + last - first > self.length:
                        continue
                    if modules > 65535 or files > 65535 or not modules + files:
                        continue
                    if hdr_offset + 84 + modules * 32 + files * 28 > base + last - first:
                        continue
                    # Require a plausible first TOC name to avoid recognizing code constants.
                    if modules:
                        record = struct.unpack('<8I', self.read_at(hdr_offset + 84, 32))
                        self.rom_name(base, first, last, record[4])
                    candidates.add(base)
                    rom = dict(offset=base, size=last - first, romhdr_offset=hdr_offset,
                               physical_base=first, physical_end=last, modules=modules, files=files)
                    self.roms.append(rom)
                except (ValueError, struct.error):
                    continue
        for number, rom in enumerate(sorted(self.roms, key=lambda r: r['offset'])):
            self.add_rom(number, rom)
        self.missing.clear()  # Discovery probes are not exported-file holes.
        self.format_name = 'Windows CE ROM' if self.roms else 'Binärbereich / Dateisystem nicht unterstützt'

    def read_at(self, offset, size):
        if offset < 0 or size < 0 or offset + size > self.length:
            raise ValueError('Firmware-Zugriff außerhalb des logischen Bereichs')
        data = bytearray()
        sector_size = self.d.g.data_size
        while size:
            lba, inner = divmod(offset, sector_size)
            take = min(size, sector_size - inner)
            if self.p.mapping.get(lba) in getattr(self.d, 'ecc_bad_data', set()):
                self.ecc_unverified_reads.add(lba)
            data.extend(self.d.sector(self.p, lba, self.missing)[inner:inner + take])
            offset += take
            size -= take
        return bytes(data)

    def rom_name(self, base, first, last, pointer):
        if not first <= pointer < last:
            raise ValueError('ROM-Dateiname außerhalb des Images')
        raw = self.read_at(base + pointer - first, min(260, last - pointer))
        end = raw.find(b'\0')
        if end < 1 or any(c < 32 or c > 126 for c in raw[:end]):
            raise ValueError('Ungültiger ROM-Dateiname')
        return raw[:end].decode('ascii')

    def folder(self, parent, name):
        key = self.next_id
        self.next_id -= 1
        self.nodes[key] = []
        entry = Entry(name, key, 0, 0, True, True)
        self.nodes[parent].append(entry)
        return key

    def metadata(self, parent, name, value):
        key = self.next_id
        self.next_id -= 1
        data = json.dumps(value, ensure_ascii=False, indent=2).encode('utf-8')
        self.blobs[key] = data
        self.nodes[parent].append(Entry(name, key, len(data), len(data), False, True))

    def add_rom(self, number, rom):
        base, first, last = rom['offset'], rom['physical_base'], rom['physical_end']
        folder = self.folder(-1, 'ROM_%02d_0x%08X' % (number, base))
        self.nodes[folder].append(Entry('ROM_Image.nb0', base, rom['size'], rom['size'], False, True))
        self.metadata(folder, 'ROM_Info.json', rom)
        mods = self.folder(folder, 'Module (TOC-Metadaten)')
        files = self.folder(folder, 'Dateien (gespeicherte Daten)')
        errors = []
        for i in range(rom['modules']):
            check_cancel(self.d.cancel)
            offset = rom['romhdr_offset'] + 84 + i * 32
            values = struct.unpack('<8I', self.read_at(offset, 32))
            try:
                name = self.rom_name(base, first, last, values[4])
                self.metadata(mods, name + '.toc.json', dict(
                    name=name, attributes=values[0], filetime_low=values[1], filetime_high=values[2],
                    original_file_size=values[3], e32_address=values[5], o32_address=values[6],
                    load_address=values[7], toc_logical_offset=offset,
                    note='ROM-Modul; keine rekonstruierte PE-Datei.'))
            except ValueError as exc:
                errors.append('Modul %d: %s' % (i, exc))
        for i in range(rom['files']):
            check_cancel(self.d.cancel)
            offset = rom['romhdr_offset'] + 84 + rom['modules'] * 32 + i * 28
            values = struct.unpack('<7I', self.read_at(offset, 28))
            attributes, time_low, time_high, real_size, stored_size, name_ptr, data_ptr = values
            try:
                name = self.rom_name(base, first, last, name_ptr)
                if not first <= data_ptr <= last or stored_size > last - data_ptr:
                    raise ValueError('Dateidaten außerhalb des ROM-Images')
                suffix = '.cecompressed' if stored_size != real_size else ''
                self.nodes[files].append(Entry(name + suffix, base + data_ptr - first,
                                               stored_size, stored_size, False, True))
                self.metadata(files, name + '.rom.json', dict(name=name, attributes=attributes,
                    real_size=real_size, stored_size=stored_size, data_address=data_ptr,
                    logical_offset=base + data_ptr - first, filetime_low=time_low, filetime_high=time_high,
                    compressed=stored_size != real_size))
            except ValueError as exc:
                errors.append('Datei %d: %s' % (i, exc))
        if errors:
            self.metadata(folder, 'Lesefehler.json', errors)

    def directory(self, entry=None):
        return self.nodes[self.root if entry is None else entry.cluster]

    def file_chunks(self, entry, limit=None):
        remaining = entry.size if limit is None else min(entry.size, limit)
        if entry.cluster in self.blobs:
            yield self.blobs[entry.cluster][:remaining]
            return
        offset = entry.cluster
        while remaining:
            check_cancel(self.d.cancel)
            take = min(remaining, 128 * 1024)
            yield self.read_at(offset, take)
            remaining -= take
            offset += take

    def info(self):
        return dict(format=self.format_name, roms=self.roms,
                    note='ROM-Images und gespeicherte Dateien exportierbar; '
                         'CE-Dekompression und PE-Rekonstruktion nicht implementiert.')


def filesystem_view(dump, part):
    try:
        return Exfat(dump, part)
    except ValueError:
        return FirmwareView(dump, part)


def lba_ranges(numbers):
    ranges = []
    for number in sorted(set(numbers)):
        if ranges and number == ranges[-1][1]:
            ranges[-1][1] += 1
        else:
            ranges.append([number, number + 1])
    return ranges  # [start, end_exclusive]


def require_coverage(coverage, allow_holes):
    if not allow_holes and not coverage['safe_without_zero_filling_allocated_data']:
        raise ValueError('Image-Export angehalten: fehlende belegte Pages=%s, FAT-Pages=%s; '
                         'Bitmap vollständig=%s. Unkorrigierbare belegte ECC-Pages=%s. Details über "LBA-Abdeckung prüfen". '
                         'Für eine bewusst unvollständige Kopie die Option '
                         '"Unvollständigen Export erlauben" aktivieren.' % (
                             coverage['missing_allocated_pages'], coverage['missing_fat_pages'],
                             coverage['bitmap_complete'], coverage.get('ecc_uncorrectable_allocated_pages', 'ungeprüft')))


def safe_name(name):
    name = re.sub(r'[<>:"/\\|?*\x00-\x1f]', '_', name).strip(' .') or '_'
    if name.split('.')[0].upper() in {'CON', 'PRN', 'AUX', 'NUL'} | {'COM%d' % i for i in range(1, 10)} | {'LPT%d' % i for i in range(1, 10)}:
        name = '_' + name
    return name[:180]


def unique_child(parent, name):
    base = safe_name(name)
    candidate = parent / base
    existing = {p.name.casefold() for p in parent.iterdir()}
    n = 1
    while candidate.name.casefold() in existing:
        candidate = parent / (base + '_%d' % n)
        n += 1
    return candidate


def launch_gui(initial_path=None):
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox, simpledialog

    class App:
        def __init__(self, root):
            self.root = root
            root.title('WinCE Flash Explorer ' + VERSION)
            root.geometry('1250x820')
            root.minsize(900, 600)
            self.dump = None
            self.models = {}
            self.filesystems = {}
            self.loaded = set()
            self.events = queue.Queue()
            self.cancel = threading.Event()
            self.busy = False
            self.closing = False
            self.buttons = []
            self.path = tk.StringVar()
            top = ttk.Frame(root, padding=8)
            top.pack(fill='x')
            self.button(top, 'Dump öffnen …', self.open_dump).pack(side='left')
            ttk.Entry(top, textvariable=self.path, state='readonly').pack(side='left', fill='x', expand=True, padx=8)
            self.button(top, 'Geometrie …', self.geometry_dialog).pack(side='left')
            self.button(top, 'Tabelle exportieren …', self.export_table).pack(side='left', padx=5)
            self.g = Geometry()
            tools = ttk.Frame(root, padding=(8, 0, 8, 6))
            tools.pack(fill='x')
            for text, callback in [('Logisches Originalimage exportieren', self.export_image),
                                   ('Rohbereich exportieren', lambda: self.export_image(True)),
                                   ('Datei/Ordner exportieren', self.export_files),
                                   ('Bereich anpassen', self.edit_range),
                                   ('Mapping-Strategie ändern', self.change_policy)]:
                self.button(tools, text, callback).pack(side='left', padx=(0, 5))
            ttk.Button(tools, text='Abbrechen', command=self.cancel.set).pack(side='right')
            mbrbar = ttk.Frame(root, padding=(8, 0, 8, 6))
            mbrbar.pack(fill='x')
            self.button(mbrbar, 'MBR-Image: gewählte Partition …', self.export_compatible).pack(side='left', padx=(0, 5))
            self.button(mbrbar, 'MBR-Image: alle Partitionen …', self.export_all_mbr).pack(side='left', padx=(0, 5))
            self.button(mbrbar, 'LBA-Abdeckung prüfen', self.check_coverage).pack(side='left')
            eccbar = ttk.Frame(root, padding=(8, 0, 8, 6))
            eccbar.pack(fill='x')
            self.button(eccbar, 'ECC nur prüfen', lambda: self.audit_ecc(False)).pack(side='left', padx=(0, 5))
            self.button(eccbar, 'ECC prüfen + anwenden', lambda: self.audit_ecc(True)).pack(side='left', padx=(0, 5))
            self.button(eccbar, 'ECC-Bericht exportieren …', self.export_ecc_report).pack(side='left', padx=(0, 5))
            self.button(eccbar, 'ECC-Korrekturen zurücksetzen', self.reset_ecc).pack(side='left')
            self.ecc_state = tk.StringVar(value='ECC: nicht angewendet')
            ttk.Label(eccbar, textvariable=self.ecc_state).pack(side='left', padx=10)
            panes = ttk.Panedwindow(root, orient='vertical')
            panes.pack(fill='both', expand=True, padx=8)
            table_frame = ttk.Labelframe(panes, text='Partitionstabelle · physische Endgrenze exklusiv')
            panes.add(table_frame, weight=1)
            columns = ('blocks', 'offset', 'logical', 'policy', 'mapped')
            self.table = self.make_tree(table_frame, columns)
            self.table.heading('#0', text='Partition')
            self.table.column('#0', width=110)
            for c, title, width in [('blocks', 'Blockbereich', 150), ('offset', 'Rohdump-Bereich [Start, Ende)', 270),
                                    ('logical', 'Logische Größe', 130), ('policy', 'Duplikate', 100), ('mapped', 'Gemappte Pages', 130)]:
                self.table.heading(c, text=title)
                self.table.column(c, width=width)
            self.table.bind('<<TreeviewSelect>>', self.select_partition)
            lower = ttk.Panedwindow(panes, orient='horizontal')
            panes.add(lower, weight=4)
            content = ttk.Labelframe(lower, text='Inhalt · Ordner aufklappen; Datei für Vorschau auswählen')
            lower.add(content, weight=3)
            self.tree = self.make_tree(content, ('size', 'cluster', 'check'))
            self.tree.heading('#0', text='Name')
            self.tree.column('#0', width=300)
            for c, title, width in [('size', 'Bytes', 110), ('cluster', 'Cluster / Offset', 115), ('check', 'Prüfsumme', 100)]:
                self.tree.heading(c, text=title)
                self.tree.column(c, width=width)
            self.tree.bind('<<TreeviewOpen>>', self.expand)
            self.tree.bind('<<TreeviewSelect>>', self.preview)
            self.tree.tag_configure('bad', foreground='#b03030')
            detail = ttk.Labelframe(lower, text='Details / begrenzte Text- und Hex-Vorschau')
            lower.add(detail, weight=2)
            self.details = tk.Text(detail, wrap='word', font=('Consolas', 10), state='disabled')
            self.details.pack(fill='both', expand=True)
            self.status = tk.StringVar(value='Bereit · 2112 Byte/Page · 64 Pages/Löschblock · Header 0x92')
            statusbar = ttk.Frame(root)
            statusbar.pack(fill='x')
            self.allow_holes = tk.BooleanVar(value=False)
            ttk.Checkbutton(statusbar, text='Unvollständigen Export erlauben (Lücken nullgefüllt; ECC-Fehler unverändert)',
                            variable=self.allow_holes).pack(side='right', padx=8)
            ttk.Label(statusbar, textvariable=self.status, padding=8).pack(side='left', fill='x', expand=True)
            root.protocol('WM_DELETE_WINDOW', self.close)
            root.after(80, self.poll)
            if initial_path:
                root.after(100, lambda: self.open_dump(initial_path))

        def button(self, frame, text, command):
            b = ttk.Button(frame, text=text, command=command)
            self.buttons.append(b)
            return b

        def make_tree(self, frame, columns):
            tree = ttk.Treeview(frame, columns=columns, selectmode='browse')
            scroll = ttk.Scrollbar(frame, orient='vertical', command=tree.yview)
            tree.configure(yscrollcommand=scroll.set)
            scroll.pack(side='right', fill='y')
            tree.pack(fill='both', expand=True)
            return tree

        def show(self, text):
            self.details.configure(state='normal')
            self.details.delete('1.0', 'end')
            self.details.insert('end', text)
            self.details.configure(state='disabled')

        def progress(self, text):
            self.events.put(('status', text))

        def run(self, action, done):
            if self.busy:
                return
            self.cancel.clear()
            self.busy = True
            for b in self.buttons:
                b.state(['disabled'])
            def worker():
                try:
                    self.events.put(('done', (done, action())))
                except Exception as exc:
                    self.events.put(('error', (str(exc), traceback.format_exc())))
            threading.Thread(target=worker, daemon=True).start()

        def poll(self):
            latest = None
            try:
                while True:
                    kind, payload = self.events.get_nowait()
                    if kind == 'status':
                        latest = payload
                    else:
                        self.busy = False
                        for b in self.buttons:
                            b.state(['!disabled'])
                        if kind == 'done':
                            callback, value = payload
                            callback(value)
                        else:
                            messagebox.showerror('Vorgang nicht abgeschlossen', payload[0])
                            self.show(payload[1])
                        latest = 'Bereit' if kind == 'done' else 'Vorgang nicht abgeschlossen'
            except queue.Empty:
                pass
            if latest:
                self.status.set(latest)
            if self.closing and not self.busy:
                if self.dump:
                    self.dump.close()
                self.root.destroy()
                return
            self.root.after(80, self.poll)

        def close(self):
            self.closing = True
            self.cancel.set()
            if self.busy:
                self.status.set('Laufenden Vorgang abbrechen …')

        def geometry_dialog(self):
            if self.busy:
                return
            dialog = tk.Toplevel(self.root)
            dialog.title('Geometrie für den nächsten geöffneten Dump')
            values = {}
            fields = [('page_size', 'Pagegröße inkl. Spare'), ('data_size', 'Nutzdaten pro Page'),
                      ('pages_per_block', 'Pages pro physischem Löschblock'), ('header_offset', 'Header-Byteposition'),
                      ('header_value', 'Headerwert (z. B. 0x92)'), ('lba_offset', 'LBA-Byteposition (Little Endian)'),
                      ('lba_bytes', 'LBA-Länge: 3 oder 4'), ('first_data_block', 'Erster Datenblock (leer = automatisch)')]
            for row, (key, label) in enumerate(fields):
                ttk.Label(dialog, text=label).grid(row=row, column=0, padx=8, pady=5, sticky='w')
                value = getattr(self.g, key)
                values[key] = tk.StringVar(value='' if value is None else hex(value) if key == 'header_value' else str(value))
                ttk.Entry(dialog, textvariable=values[key]).grid(row=row, column=1, padx=8)
            def save():
                try:
                    settings = {k: (None if k == 'first_data_block' and not v.get().strip()
                                    else int(v.get().strip(), 0)) for k, v in values.items()}
                    geometry = Geometry(**settings)
                    geometry.validate()
                    self.g = geometry
                    dialog.destroy()
                    self.status.set('Geometrie gespeichert; zum Anwenden Dump neu öffnen.')
                except Exception as exc:
                    messagebox.showerror('Geometrie', str(exc), parent=dialog)
            ttk.Button(dialog, text='Übernehmen', command=save).grid(row=len(fields), column=1, pady=10)
            dialog.transient(self.root)
            dialog.grab_set()

        def open_dump(self, path=None):
            if self.busy:
                return
            path = path or filedialog.askopenfilename(title='Entpackten Rohdump öffnen', filetypes=[('Flash-Dumps', '*.dmp *.bin *.img *.raw'), ('Alle Dateien', '*')])
            if not path:
                return
            def action():
                new = FlashDump(path, self.g, self.cancel, self.progress)
                return new
            def done(new):
                if self.dump:
                    self.dump.close()
                self.dump = new
                self.ecc_state.set('ECC: nicht angewendet')
                self.path.set(str(new.path))
                self.table.delete(*self.table.get_children())
                self.tree.delete(*self.tree.get_children())
                self.models.clear()
                self.loaded.clear()
                self.filesystems.clear()
                for part in new.partitions:
                    self.add_partition(part)
                self.show('MSFLSH60: %d übereinstimmende Tabellenkopien.\nErster Datenblock: %d\n\n%s\n\n'
                          'Partition im Inhaltsbaum aufklappen, um das Mapping und exFAT zu laden.\n'
                          'Quelle bleibt schreibgeschützt geöffnet.\nECC optional; keine Checkpoint-Recovery.'
                          % (new.table_copy_count, new.base_block, '\n'.join(new.warnings)))
            self.run(action, done)

        def add_partition(self, part):
            iid = 'p%d' % part.index
            self.models[iid] = (part, None)
            self.table.insert('', 'end', iid=iid, text=part.name)
            self.tree.insert('', 'end', iid=iid, text=part.name, values=('', '', ''))
            self.tree.insert(iid, 'end', text='Laden …')
            self.update_partition(part)

        def update_partition(self, part):
            g = self.dump.g
            self.table.item('p%d' % part.index, values=(
                '%d–%d' % (part.start_block, part.end_block - 1),
                '0x%X–0x%X' % (part.start_block * g.pages_per_block * g.page_size, part.end_block * g.pages_per_block * g.page_size),
                '%s Byte' % format(part.logical_blocks * g.pages_per_block * g.data_size, ','),
                part.policy, len(part.mapping) if part.scanned else 'nicht geladen'))

        def selected(self):
            selected = self.tree.selection()
            if selected and selected[0] in self.models:
                return self.models[selected[0]]
            selected = self.table.selection()
            return self.models.get(selected[0]) if selected else None

        def select_partition(self, event=None):
            if self.busy:
                return
            selected = self.table.selection()
            if selected:
                iid = selected[0]
                self.tree.selection_set(iid)
                self.tree.see(iid)

        def fs(self, part):
            if part.index not in self.filesystems:
                self.filesystems[part.index] = filesystem_view(self.dump, part)
            return self.filesystems[part.index]

        def expand(self, event=None):
            if self.busy:
                return
            iid = self.tree.focus()
            if iid in self.loaded or iid not in self.models:
                return
            part, entry = self.models[iid]
            if entry is not None and not entry.is_dir:
                return
            def action():
                fs = self.fs(part)
                return fs.directory(entry), fs.info() if entry is None else None
            def done(result):
                entries, info = result
                self.tree.delete(*self.tree.get_children(iid))
                for entry in sorted(entries, key=lambda e: (not e.is_dir, e.name.casefold())):
                    child = self.tree.insert(iid, 'end', text=entry.name,
                                             values=(entry.size, entry.cluster, 'OK' if entry.checksum_ok else 'FEHLER'),
                                             tags=() if entry.checksum_ok else ('bad',))
                    self.models[child] = (part, entry)
                    if entry.is_dir:
                        self.tree.insert(child, 'end', text='Laden …')
                self.loaded.add(iid)
                self.update_partition(part)
                if info:
                    if info.get('format'):
                        self.tree.item(iid, text=part.name + ' · ' + info['format'])
                    self.show(json.dumps(dict(partition=part.summary(self.dump.g), filesystem=info), ensure_ascii=False, indent=2))
            self.run(action, done)

        def preview(self, event=None):
            if self.busy:
                return
            selected = self.selected()
            if not selected:
                return
            part, entry = selected
            if entry is None:
                self.show(json.dumps(part.summary(self.dump.g), ensure_ascii=False, indent=2))
            elif entry.is_dir:
                self.show(json.dumps(asdict(entry), ensure_ascii=False, indent=2))
            else:
                def action():
                    fs = self.fs(part)
                    old_missing = set(fs.missing)
                    data = b''.join(fs.file_chunks(entry, 65536))
                    return data, sorted(fs.missing - old_missing)
                def done(result):
                    data, missing = result
                    text = data.decode('utf-16' if data.startswith((b'\xff\xfe', b'\xfe\xff')) else 'utf-8', 'replace')
                    hexlines = ['%08X  %-47s  %s' % (o, data[o:o + 16].hex(' '),
                                ''.join(chr(c) if 32 <= c < 127 else '.' for c in data[o:o + 16]))
                                for o in range(0, min(len(data), 4096), 16)]
                    self.show(json.dumps(asdict(entry), ensure_ascii=False, indent=2) +
                              '\n\nVorschau: max. 64 KiB Text / 4 KiB Hex; fehlende neue LBAs: %s\n\nHEX\n%s\n\nTEXT\n%s'
                              % (missing, '\n'.join(hexlines), text))
                self.run(action, done)

        def invalidate(self, part):
            iid = 'p%d' % part.index
            def remove_children(parent):
                for child in self.tree.get_children(parent):
                    remove_children(child)
                    self.models.pop(child, None)
                    self.loaded.discard(child)
                    self.tree.delete(child)
            remove_children(iid)
            self.tree.item(iid, open=False)
            self.tree.insert(iid, 'end', text='Laden …')
            self.loaded.discard(iid)
            self.filesystems.pop(part.index, None)
            part.mapping.clear()
            part.scanned = False
            self.update_partition(part)

        def change_policy(self):
            selected = self.selected()
            if selected:
                part, _ = selected
                part.policy = 'first' if part.policy == 'last' else 'last'
                self.invalidate(part)
                self.status.set('%s: %s wins; zum Laden erneut aufklappen.' % (part.name, part.policy))

        def edit_range(self):
            selected = self.selected()
            if not selected:
                return
            part, _ = selected
            value = simpledialog.askstring('Physischen Bereich ändern', 'Startblock, Endblock exklusiv (dezimal oder 0x…):',
                                           initialvalue='%d,%d' % (part.start_block, part.end_block), parent=self.root)
            if value is None:
                return
            try:
                start, end = [int(x.strip(), 0) for x in value.split(',')]
                if not 0 <= start < end <= self.dump.pages // self.dump.g.pages_per_block:
                    raise ValueError('Bereich außerhalb des Dumps')
                part.start_block, part.end_block = start, end
                self.invalidate(part)
                self.dump.warnings.append('%s: Bereich manuell auf [%d,%d) geändert.' % (part.name, start, end))
            except Exception as exc:
                messagebox.showerror('Bereich', str(exc))

        def export_table(self):
            if self.dump is None:
                return
            path = filedialog.asksaveasfilename(title='Partitionstabelle exportieren',
                                               initialfile='partitionen.json', defaultextension='.json',
                                               filetypes=[('JSON', '*.json'), ('CSV', '*.csv')])
            if not path:
                return
            try:
                target = self.dump.guard_output(path)
                rows = [p.summary(self.dump.g) for p in self.dump.partitions]
                if target.suffix.lower() == '.csv':
                    keys = ['name', 'index', 'logical_blocks', 'physical_blocks', 'start_block', 'end_block',
                            'raw_start', 'raw_end_exclusive', 'logical_bytes', 'policy', 'scanned', 'mapped_pages']
                    with target.open('w', newline='', encoding='utf-8-sig') as out:
                        writer = csv.DictWriter(out, fieldnames=keys, extrasaction='ignore', delimiter=';')
                        writer.writeheader()
                        writer.writerows(rows)
                else:
                    target.write_text(json.dumps(dict(source=str(self.dump.path), geometry=asdict(self.dump.g),
                                                      table_offsets=self.dump.table_offsets,
                                                      warnings=self.dump.warnings, partitions=rows),
                                                 ensure_ascii=False, indent=2), encoding='utf-8')
                self.status.set('Partitionstabelle exportiert: ' + str(target))
            except Exception as exc:
                messagebox.showerror('Tabellenexport', str(exc))

        def audit_ecc(self, apply):
            if self.dump is None:
                return
            def done(report):
                if apply:
                    self.ecc_state.set('ECC: angewendet')
                    for part in self.dump.partitions:
                        self.invalidate(part)
                self.show(json.dumps(dict(profile=report['profile'], validation=report['validation'],
                                          counts=report['counts'], applied=report['applied_to_logical_view'],
                                          header_candidates=report.get('header_candidates', []),
                                          limitations=report['limitations']), ensure_ascii=False, indent=2))
                messagebox.showinfo('ECC-Prüfung abgeschlossen',
                    '%d korrigierbare Pages, %d Pages mit unkorrigierbaren Daten.\n%s' % (
                        report['counts']['corrected_pages'], report['counts']['pages_with_uncorrectable_data'],
                        'Korrekturen in der logischen Ansicht aktiv; Partitionen erneut aufklappen.' if apply
                        else 'Nur geprüft; logische Ansicht nicht verändert.'))
            self.run(lambda: self.dump.audit_ecc(apply), done)

        def export_ecc_report(self):
            if self.dump is None or self.dump.ecc_last_report is None:
                messagebox.showinfo('ECC', 'Zuerst ECC prüfen.')
                return
            path = filedialog.asksaveasfilename(title='Vollständigen ECC-Bericht exportieren',
                                               initialfile=self.dump.path.stem + '_ECC.json', defaultextension='.json')
            if not path:
                return
            try:
                target = self.dump.guard_output(path)
                target.write_text(json.dumps(self.dump.ecc_last_report, ensure_ascii=False, indent=2), encoding='utf-8')
                self.status.set('ECC-Bericht exportiert: ' + str(target))
            except Exception as exc:
                messagebox.showerror('ECC-Bericht', str(exc))

        def reset_ecc(self):
            if self.dump is None:
                return
            self.dump.clear_ecc()
            self.ecc_state.set('ECC: nicht angewendet')
            for part in self.dump.partitions:
                self.invalidate(part)
            self.show('ECC-Korrekturen zurückgesetzt. Logische Ansicht nutzt wieder die ursprünglichen Pages.')

        def check_coverage(self):
            selected = self.selected()
            if not selected:
                return
            part, _ = selected
            def action():
                fs = self.fs(part)
                if isinstance(fs, FirmwareView):
                    return dict(status='Keine exFAT-Allocation-Bitmap; freie/belegte Lücken nicht klassifizierbar.',
                                mapping=part.summary(self.dump.g))
                return fs.coverage()
            self.run(action, lambda result: (self.update_partition(part),
                                            self.show(json.dumps(result, ensure_ascii=False, indent=2))))

        def export_compatible(self):
            selected = self.selected()
            if not selected:
                return
            part, _ = selected
            path = filedialog.asksaveasfilename(title='Gewählte Partition als MBR-Analyseimage (exFAT-Bootmetadaten werden angepasst)',
                                               initialfile=part.name + '_ANALYSE_512_MBR.img', defaultextension='.img')
            if not path:
                return
            allow = self.allow_holes.get()
            self.run(lambda: self.dump.export_compatible(part, path, allow),
                     lambda result: (self.update_partition(part),
                                     self.show(json.dumps(result, ensure_ascii=False, indent=2)),
                                     messagebox.showinfo('Analyseimage exportiert',
                                         str(path) + '\n\nSynthetischer MBR; bei exFAT angepasste Bootmetadaten.\n'
                                         'Änderungen stehen im JSON-Bericht; FTK-Erkennung bitte prüfen.')))

        def export_all_mbr(self):
            if self.dump is None:
                return
            path = filedialog.asksaveasfilename(title='Alle Partitionen in einem MBR-Analyseimage',
                                               initialfile=self.dump.path.stem + '_ALLE_MBR.img',
                                               defaultextension='.img')
            if not path:
                return
            allow = self.allow_holes.get()
            def done(result):
                for part in self.dump.partitions:
                    self.update_partition(part)
                self.show(json.dumps(result, ensure_ascii=False, indent=2))
                messagebox.showinfo('MBR-Image exportiert', str(path) +
                                    '\n\nAlle Partitionen mit 1-MiB-Ausrichtung.\n'
                                    'PART00 bleibt ein Firmwarebereich; FTK-Dateisystemerkennung nicht garantiert.')
            self.run(lambda: self.dump.export_all_mbr(path, allow), done)

        def export_image(self, raw=False):
            selected = self.selected()
            if not selected:
                return
            part, _ = selected
            path = filedialog.asksaveasfilename(title='Rohbereich mit Spare exportieren' if raw else 'Logisches Image ohne Spare exportieren',
                                               initialfile=part.name + ('.raw' if raw else '.img'), defaultextension='.raw' if raw else '.img')
            if not path:
                return
            allow = self.allow_holes.get()
            self.run(lambda: self.dump.export_partition(part, path, raw, allow),
                     lambda result: (self.update_partition(part), self.show(json.dumps(result, ensure_ascii=False, indent=2)),
                                     messagebox.showinfo('Export abgeschlossen', str(path))))

        def export_files(self):
            selected = self.selected()
            if not selected:
                return
            part, entry = selected
            if entry is None or entry.is_dir:
                parent = filedialog.askdirectory(title='Zielordner wählen; neuer Unterordner wird angelegt')
                if not parent:
                    return
                destination = unique_child(Path(parent), part.name if entry is None else entry.name)
            else:
                if not entry.checksum_ok and not messagebox.askyesno('Eintragsprüfsumme fehlerhaft', 'Diese Datei trotzdem versuchsweise exportieren?'):
                    return
                destination = filedialog.asksaveasfilename(title='Datei exportieren (neues Ziel erforderlich)', initialfile=safe_name(entry.name))
                if not destination:
                    return
            self.run(lambda: self.fs(part).export(entry, destination),
                     lambda result: (self.show(json.dumps(result, ensure_ascii=False, indent=2)),
                                     messagebox.showinfo('Export abgeschlossen', str(destination))))

    root = tk.Tk()
    App(root)
    root.mainloop()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('dump', nargs='?', help='Entpackter Rohdump')
    parser.add_argument('--inspect', action='store_true', help='Partitionen und exFAT ohne GUI als JSON prüfen')
    parser.add_argument('--policy', choices=['first', 'last'], default='last')
    args = parser.parse_args()
    if args.inspect:
        if not args.dump:
            parser.error('--inspect benötigt einen Dump')
        dump = FlashDump(args.dump)
        try:
            result = dict(version=VERSION, geometry=asdict(dump.g), warnings=dump.warnings,
                          table_offsets=dump.table_offsets, partitions=[])
            for part in dump.partitions:
                dump.scan(part, args.policy)
                summary = part.summary(dump.g)
                try:
                    fs = filesystem_view(dump, part)
                    summary['filesystem'] = fs.info()
                    if not isinstance(fs, FirmwareView):
                        summary['allocation_coverage'] = fs.coverage()
                    summary['root'] = [asdict(e) for e in fs.directory()]
                except ValueError as exc:
                    summary['filesystem_status'] = str(exc)
                result['partitions'].append(summary)
            print(json.dumps(result, ensure_ascii=False, indent=2))
        finally:
            dump.close()
    else:
        launch_gui(args.dump)


if __name__ == '__main__':
    main()
