import struct
import unittest
from check_ipa import cryptids

def macho(value):
    return struct.pack('<8I', 0xfeedfacf, 0x100000c, 0, 2, 1, 24, 0, 0) + struct.pack('<6I', 0x2c, 24, 0, 0, value, 0)

class EncryptionInspectionTests(unittest.TestCase):
    def test_decrypted(self):
        self.assertEqual(cryptids(macho(0)), [0])
    def test_encrypted(self):
        self.assertEqual(cryptids(macho(1)), [1])
    def test_fat_mixed(self):
        a, b = macho(0), macho(1)
        fat = struct.pack('>2I', 0xcafebabe, 2)
        fat += struct.pack('>5I', 0x100000c, 0, 48, len(a), 0)
        fat += struct.pack('>5I', 0x100000c, 0, 48 + len(a), len(b), 0)
        self.assertEqual(cryptids(fat + a + b), [0, 1])
    def test_truncated(self):
        with self.assertRaises(ValueError):
            cryptids(macho(0)[:-1])
    def test_non_executable(self):
        with self.assertRaises(ValueError):
            cryptids(b'not a Mach-O')
    def test_invalid_command(self):
        data = bytearray(macho(0))
        struct.pack_into('<I', data, 36, 0)
        with self.assertRaises(ValueError):
            cryptids(data)

if __name__ == '__main__':
    unittest.main()
