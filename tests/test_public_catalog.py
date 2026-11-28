import gzip
import io
import json
import tempfile
import unittest
from pathlib import Path
from zipfile import ZipFile

from aegis.public_catalog import nvd_rows, osv_rows, source_urls


class TestPublicCatalog(unittest.TestCase):
    def test_only_fixed_public_archives(self):
        self.assertEqual(source_urls('npm')[0], 'https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip')
        self.assertTrue(source_urls('NVD-2002')[0].endswith('/nvdcve-2.0-2002.json.gz'))
        for source in ('npm/../../', 'https://other.invalid', 'NVD-1999', 'NVD-latest'):
            with self.assertRaises(ValueError):
                source_urls(source)

    def test_official_zip_reads_old_and_withdrawn_advisories(self):
        with tempfile.TemporaryDirectory() as folder:
            file = Path(folder) / 'osv.zip'
            with ZipFile(file, 'w') as archive:
                archive.writestr('GHSA-aa.json', json.dumps({'id': 'GHSA-aa', 'modified': '2022-01-01T00:00:00Z',
                    'database_specific': {'severity': 'HIGH', 'unused': 'metadata'},
                    'affected': [{'package': {'name': 'example', 'ecosystem': 'npm'}, 'versions': ['1.0.0']}]}))
                archive.writestr('GHSA-bb.json', json.dumps({'id': 'GHSA-bb', 'withdrawn': '2023-01-01T00:00:00Z'}))
            rows = list(osv_rows(file))
            self.assertEqual([row['id'] for row in rows], ['GHSA-aa', 'GHSA-bb'])
            self.assertEqual(rows[0]['database_specific'], {'severity': 'HIGH'})
            self.assertIn('withdrawn', rows[1])

    def test_annual_format_validates_count_and_tail_across_chunks(self):
        entries = [{'cve': {'id': 'CVE-2002-0123', 'vulnStatus': 'Analyzed', 'descriptions': ['a' * 100000],
                            'metrics': {'cvssMetricV31': [
                                {'type': 'Secondary', 'cvssData': {'baseSeverity': 'MEDIUM'}},
                                {'type': 'Primary', 'cvssData': {'baseSeverity': 'HIGH'}},
                            ]}}},
                   {'cve': {'id': 'CVE-2002-0124', 'vulnStatus': 'Rejected'}}]
        raw = json.dumps({'format': 'NVD_CVE', 'version': '2.0', 'totalResults': 2, 'vulnerabilities': entries}).encode()
        def read(body):
            return list(nvd_rows(gzip.GzipFile(fileobj=io.BytesIO(gzip.compress(body))), len(body)))
        rows = read(raw)
        self.assertEqual(rows[1]['cve']['vulnStatus'], 'Rejected')
        self.assertNotIn('descriptions', rows[0]['cve'])
        self.assertEqual(rows[0]['cve']['severity'], 'HIGH')
        for bad in (raw[:-1], raw.replace(b'"totalResults": 2', b'"totalResults": 3')):
            with self.assertRaises(ValueError):
                read(bad)
