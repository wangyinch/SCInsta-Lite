"""Read-only IPA preflight. No extraction, network, credentials or decryption.

Checks the main executable only; cannot establish provenance or runtime compatibility.
"""
import argparse
import hashlib
import json
import plistlib
import struct
import zipfile
from pathlib import Path


def cryptids(data):
    data = bytes(data)
    if data[:4] in (b'\xca\xfe\xba\xbe', b'\xca\xfe\xba\xbf'):
        wide = data[:4] == b'\xca\xfe\xba\xbf'
        count = struct.unpack_from('>I', data, 4)[0]
        if not 1 <= count <= 32:
            raise ValueError('Invalid fat architecture count')
        found = []
        for i in range(count):
            pos = 8 + i * (32 if wide else 20)
            offset, size = struct.unpack_from('>QQ' if wide else '>II', data, pos + 8)
            if offset + size > len(data):
                raise ValueError('Truncated fat binary')
            found.extend(cryptids(data[offset:offset + size]))
        return found
    formats = {b'\xcf\xfa\xed\xfe': ('<', 32), b'\xce\xfa\xed\xfe': ('<', 28),
               b'\xfe\xed\xfa\xcf': ('>', 32), b'\xfe\xed\xfa\xce': ('>', 28)}
    if data[:4] not in formats:
        raise ValueError('Not a supported Mach-O executable')
    endian, pos = formats[data[:4]]
    count, size = struct.unpack_from(endian + 'II', data, 16)
    end = pos + size
    if end > len(data) or count > size // 8:
        raise ValueError('Invalid Mach-O load commands')
    result = []
    for _ in range(count):
        if pos + 8 > end:
            raise ValueError('Truncated load command')
        cmd, length = struct.unpack_from(endian + 'II', data, pos)
        if length < 8 or pos + length > end:
            raise ValueError('Invalid load command size')
        if cmd in (0x21, 0x2C):
            if length < (24 if cmd == 0x2C else 20):
                raise ValueError('Truncated encryption command')
            result.append(struct.unpack_from(endian + 'I', data, pos + 16)[0])
        pos += length
    if pos != end:
        raise ValueError('Load command size mismatch')
    return result


def inspect(path):
    with zipfile.ZipFile(path) as z:
        infos = [n for n in z.namelist() if n.startswith('Payload/') and
                 n.endswith('.app/Info.plist') and n.count('/') == 2]
        if len(infos) != 1:
            raise ValueError('Expected exactly one main app')
        def read_bounded(name, limit):
            if z.getinfo(name).file_size > limit:
                raise ValueError('File exceeds inspection size limit')
            return z.read(name)
        info = plistlib.loads(read_bounded(infos[0], 1024 * 1024))
        exe = info['CFBundleExecutable']
        if not isinstance(exe, str) or '/' in exe or '\\' in exe or exe in ('.', '..'):
            raise ValueError('Invalid executable name')
        ids = cryptids(read_bounded(infos[0].rsplit('/', 1)[0] + '/' + exe, 512 * 1024 * 1024))
        bundle = info.get('CFBundleIdentifier')
        version = info.get('CFBundleShortVersionString')
        return {'bundle_id': bundle, 'version': version, 'cryptids': ids,
                'main_executable_encrypted': any(ids),
                'matches_upstream_tested_version': version == '418.2.0',
                'candidate_only': bundle == 'com.burbn.instagram' and bool(ids) and not any(ids),
                'warning': 'Main executable only. Authenticity, embedded frameworks, signing and device behavior NOT verified.'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('ipa', type=Path)
    args = parser.parse_args()
    try:
        result = inspect(args.ipa)
        digest = hashlib.sha256()
        with args.ipa.open('rb') as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b''):
                digest.update(chunk)
        result['sha256'] = digest.hexdigest()
        print(json.dumps(result, indent=2))
        raise SystemExit(0 if result['candidate_only'] else 2)
    except (OSError, ValueError, KeyError, struct.error, zipfile.BadZipFile, plistlib.InvalidFileException) as e:
        print(json.dumps({'error': str(e)}))
        raise SystemExit(2)
