"""Stream bounded, public advisory snapshots for the browser's local index."""
from __future__ import annotations

import codecs
import gzip
import hashlib
import json
import re
import signal
import struct
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from urllib.request import HTTPRedirectHandler, Request, build_opener
from zipfile import ZipFile

MIB = 1024 * 1024
MAX_DOWNLOAD = 384 * MIB
MAX_DECOMPRESSED_NVD = 800 * MIB
MAX_OSV_TOTAL = 1024 * MIB
MAX_RECORD = 4 * MIB
MAX_ENTRIES = 400_000
CHUNK = 64 * 1024
OSV = 'https://osv-vulnerabilities.storage.googleapis.com'
NVD = 'https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-'
ADVISORY_ID = re.compile(r'[A-Za-z0-9][A-Za-z0-9._:+-]{0,127}\Z')


def source_urls(source):
    if source in ('npm', 'PyPI', 'Go'):
        return (f'{OSV}/{source}/all.zip',)
    if re.fullmatch(r'NVD-[0-9]{4}', source) and 2002 <= int(source[4:]) <= datetime.now(timezone.utc).year:
        return (f'{NVD}{source[4:]}.json.gz', f'{NVD}{source[4:]}.meta')
    raise ValueError('unsupported public source')


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def public_response(url):
    return build_opener(NoRedirect()).open(Request(url, headers={'Accept-Encoding': 'identity'}), timeout=25)


def download(url, path, max_bytes):
    with public_response(url) as response, path.open('wb') as output:
        length = int(response.headers.get('Content-Length', '0'))
        if not 0 < length <= max_bytes or response.status != 200:
            raise ValueError('invalid archive length')
        total = 0
        while chunk := response.read(CHUNK):
            total += len(chunk)
            if total > length:
                raise ValueError('archive exceeds declared length')
            output.write(chunk)
        if total != length:
            raise ValueError('truncated archive')
        return response.headers.get('Last-Modified')


def nvd_meta(url):
    with public_response(url) as response:
        raw = response.read(4097)
    if len(raw) > 4096:
        raise ValueError('metadata too large')
    meta = dict(line.split(':', 1) for line in raw.decode('ascii').splitlines() if ':' in line)
    size = int(meta['size'])
    if not 0 < size <= MAX_DECOMPRESSED_NVD or not re.fullmatch(r'[A-Fa-f0-9]{64}', meta['sha256']):
        raise ValueError('invalid NVD metadata')
    return size, meta['sha256'].lower(), meta.get('lastModifiedDate')


def check_zip_directory(path):
    with path.open('rb') as stream:
        stream.seek(0, 2)
        length = stream.tell()
        stream.seek(max(0, length - 65_557))
        tail = stream.read()
        offset = tail.rfind(b'PK\x05\x06')
        if offset < 0 or len(tail) - offset < 22:
            raise ValueError('missing ZIP directory')
        disk, directory_disk, _, entries, size, _, comment = struct.unpack_from('<4H2LH', tail, offset + 4)
        if disk or directory_disk or offset + 22 + comment != len(tail):
            raise ValueError('unsupported ZIP directory')
        if entries == 0xffff or size == 0xffffffff:
            locator = offset - 20
            if locator < 0 or tail[locator:locator + 4] != b'PK\x06\x07':
                raise ValueError('missing ZIP64 locator')
            disk, directory, disks = struct.unpack_from('<LQL', tail, locator + 4)
            if disk or disks != 1 or directory + 56 > length:
                raise ValueError('invalid ZIP64 directory')
            stream.seek(directory)
            header = stream.read(56)
            if not header.startswith(b'PK\x06\x06'):
                raise ValueError('missing ZIP64 directory')
            entries, size = struct.unpack_from('<QQ', header, 32)
        if not 0 < entries <= MAX_ENTRIES or not 0 < size <= 48 * MIB:
            raise ValueError('ZIP directory exceeds processing limit')


def osv_rows(path):
    check_zip_directory(path)
    with ZipFile(path) as archive:
        members = archive.infolist()
        if not 0 < len(members) <= MAX_ENTRIES or sum(member.file_size for member in members) > MAX_OSV_TOTAL:
            raise ValueError('archive exceeds processing limit')
        seen = set()
        for member in members:
            identifier = member.filename.removesuffix('.json')
            if (not member.filename.endswith('.json') or not ADVISORY_ID.fullmatch(identifier)
                    or not 0 < member.file_size <= MAX_RECORD):
                raise ValueError('unexpected archive member')
            if identifier in seen:
                raise ValueError('duplicate archive member')
            seen.add(identifier)
            advisory = json.loads(archive.read(member))
            if advisory.get('id') != identifier or (not advisory.get('withdrawn') and not isinstance(advisory.get('affected'), list)):
                raise ValueError('invalid advisory')
            row = {key: advisory[key] for key in ('id', 'aliases', 'modified', 'withdrawn') if key in advisory}
            if not row.get('withdrawn'):
                severity = advisory.get('database_specific')
                if isinstance(severity, dict) and severity.get('severity') in ('LOW', 'MODERATE', 'MEDIUM', 'HIGH', 'CRITICAL'):
                    row['database_specific'] = {'severity': severity['severity']}
                row['affected'] = [
                    {key: affected[key] for key in ('package', 'ranges', 'versions') if key in affected}
                    for affected in advisory['affected']
                ]
            yield row


def nvd_rows(stream, expected_size, expected_hash=None):
    utf8 = codecs.getincrementaldecoder('utf-8')()
    digest = hashlib.sha256()
    size = 0
    eof = False
    buffer = ''

    def fill():
        nonlocal buffer, eof, size
        chunk = stream.read(CHUNK)
        size += len(chunk)
        if size > expected_size:
            raise ValueError('NVD exceeds declared size')
        digest.update(chunk)
        eof = not chunk
        buffer += utf8.decode(chunk, final=eof)

    fill()
    match = re.search(r'"vulnerabilities"\s*:\s*\[', buffer)
    if match is None:
        raise ValueError('missing NVD array header')
    header = json.loads(buffer[:match.end()] + ']}')
    count = header.get('totalResults')
    if (header.get('format') != 'NVD_CVE' or header.get('version') != '2.0'
            or type(count) is not int or not 0 < count <= MAX_ENTRIES):
        raise ValueError('invalid NVD header')
    buffer = buffer[match.end():]
    decoder = json.JSONDecoder()

    def skip_space():
        nonlocal buffer
        buffer = buffer.lstrip()
        while not buffer and not eof:
            fill()
            buffer = buffer.lstrip()

    for index in range(count):
        skip_space()
        if index:
            if not buffer.startswith(','):
                raise ValueError('NVD array count differs from header')
            buffer = buffer[1:]
            skip_space()
        while True:
            try:
                item, offset = decoder.raw_decode(buffer)
                break
            except json.JSONDecodeError as error:
                if eof or len(buffer) >= MAX_RECORD:
                    raise ValueError('invalid or oversized NVD item') from error
                fill()
        cve = item['cve']
        if not re.fullmatch(r'CVE-[0-9]{4}-[0-9]{4,}', cve.get('id', '')):
            raise ValueError('invalid NVD id')
        row = {key: cve[key] for key in ('id', 'vulnStatus', 'lastModified', 'configurations') if key in cve}
        for kind in ('cvssMetricV40', 'cvssMetricV31', 'cvssMetricV30'):
            scores = cve.get('metrics', {}).get(kind, [])
            if scores:
                score = next((score for score in scores if score.get('type') == 'Primary'), scores[0])
                severity = score.get('cvssData', {}).get('baseSeverity')
                if severity in ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL'):
                    row['severity'] = severity
                    break
        yield {'cve': row}
        buffer = buffer[offset:]
    skip_space()
    if not buffer.startswith(']'):
        raise ValueError('NVD array did not end')
    buffer = buffer[1:]
    skip_space()
    if not buffer.startswith('}'):
        raise ValueError('NVD document did not end')
    buffer = buffer[1:]
    skip_space()
    if buffer or size != expected_size or (expected_hash and digest.hexdigest() != expected_hash):
        raise ValueError('NVD archive integrity check failed')


def emit_rows(rows, published_at):
    count = 0
    for row in rows:
        encoded = json.dumps(row, separators=(',', ':'), ensure_ascii=True)
        if len(encoded) > MAX_RECORD:
            raise ValueError('normalized record too large')
        print(encoded)
        count += 1
    print(json.dumps({'complete': count, 'publishedAt': published_at}))


def main(source):
    urls = source_urls(source)
    with tempfile.TemporaryDirectory(prefix='vulnix-public-catalog-') as directory:
        path = Path(directory) / 'archive'
        if len(urls) == 1:
            modified = download(urls[0], path, MAX_DOWNLOAD)
            emit_rows(osv_rows(path), modified)
        else:
            size, digest, modified = nvd_meta(urls[1])
            download(urls[0], path, MAX_DOWNLOAD)
            with gzip.open(path, 'rb') as stream:
                emit_rows(nvd_rows(stream, size, digest), modified)


def stop_catalog(_signum, _frame):
    raise SystemExit(1)


if __name__ == '__main__':
    signal.signal(signal.SIGTERM, stop_catalog)
    main(sys.argv[1])
