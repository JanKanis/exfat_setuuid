import io
import unittest
from unittest.mock import patch

from exfat_setuuid import *


class Misc(unittest.TestCase):
    def test_get_uuid_bytes(self):
        u = get_uuid_bytes('12AB-E9FF')
        self.assertEqual(u, b'\xff\xe9\xab\x12')

    def test_uuid_str(self):
        self.assertEqual('12AB-E9FF', uuid_str(0x12abe9ff))

    def test_format_value(self):
        self.assertEqual(VBR.format_value(0x123, 'uuid'), '0000-0123')
        self.assertEqual(VBR.format_value(0x123, 'hex'), '0x123')
        self.assertEqual(VBR.format_value(0x123, 'version'), '1.35')
        self.assertEqual(VBR.format_value(1, 'flags'), 'ActiveFat')
        self.assertEqual(VBR.format_value(18, 'flags'), 'VolumeDirty,Reserved=0x10')
        self.assertEqual(VBR.format_value(4096, 'bytes'), "4096 (4 KiB)")
        self.assertEqual(VBR.format_value(123, 'number'), '123')


class FS_tests(unittest.TestCase):
    # Intellij tester doesn't seem to recognize a setUpClass classmethod
    img = open('./exfatimg.img', 'rb')
    img4k = open('./exfatimg-4k.img', 'rb')

    @classmethod
    def tearDownClass(cls) -> None:
        cls.img.close()
        cls.img4k.close()

    def setUp(self):
        self.img.seek(0)
        self.img4k.seek(0)

    def tearDown(self) -> None:
        self.file.close()

    def test_fs(self):
        self.file = MemFS(self.img.read())
        fs = ExFatFS(self.file)
        fs.check()

        for vbr in (fs.vbr, fs.backup_vbr):
            expected = dict(
                partition_offset = 0,
                volume_length = 2048,
                fat_offset = 32,
                fat_length = 16,
                cluster_heap_offset = 48,
                cluster_count = 125,
                first_cluster_of_root_directory = 4,
                volume_serial_number = int.from_bytes(get_uuid_bytes('6FFF-FF82'), byteorder='little'),
                file_system_revision = 0x100,
                volume_flags = 0,
                bytes_per_sector_shift = 9,
                sectors_per_cluster_shift = 4,
                number_of_fats = 1,
                drive_select = 128,
                percent_in_use = 0,
                boot_signature = 0xAA55,
                checksum = 0x93234828,
                bytes_per_sector = 512,
                bytes_per_cluster = 8192,
                partition_offset_bytes = 0,
                volume_length_bytes = 1048576,
                fat_offset_bytes = 16384,
                fat_length_bytes = 8192,
                cluster_heap_offset_bytes = 24576,
                cluster_heap_length_bytes = 1024000,
            )
            found = {k: v for k, v in vars(vbr).items() if k in expected}
            self.assertDictEqual(found, expected)

    def test_4k(self):
        self.file = MemFS(self.img4k.read())
        fs = ExFatFS(self.file)
        fs.check()

        for vbr in (fs.vbr, fs.backup_vbr):
            expected = dict(
                partition_offset = 0,
                volume_length = 256,
                fat_offset = 24,
                fat_length = 2,
                cluster_heap_offset = 26,
                cluster_count = 115,
                first_cluster_of_root_directory = 4,
                volume_serial_number = int.from_bytes(get_uuid_bytes('766F-83A4'), byteorder='little'),
                file_system_revision = 0x100,
                volume_flags = 0,
                bytes_per_sector_shift = 12,
                sectors_per_cluster_shift = 1,
                number_of_fats = 1,
                drive_select = 128,
                percent_in_use = 0,
                boot_signature = 0xAA55,
                checksum = 0x249ECA1D,
                bytes_per_sector = 4096,
                bytes_per_cluster = 8192,
                partition_offset_bytes = 0,
                volume_length_bytes = 1048576,
                fat_offset_bytes = 98304,
                fat_length_bytes = 8192,
                cluster_heap_offset_bytes = 106496,
                cluster_heap_length_bytes = 942080,
            )
            found = {k: v for k, v in vars(vbr).items() if k in expected}
            self.assertDictEqual(found, expected)

    @patch('os.fsync', lambda x: None)
    def test_write(self):
        self.file = MemFS(self.img.read())
        fs = ExFatFS(self.file)

        self.assertEqual(fs.vbr.volume_serial_number, 0x6FFFFF82)
        self.assertEqual(fs.vbr.checksum, 0x93234828)

        fs.set_uuid(b'\x78\x56\x34\x12')
        fs.check()

        self.assertEqual(fs.vbr.volume_serial_number, 0x12345678)
        self.assertEqual(fs.vbr.checksum, 0x931bd828)


    @patch('os.fsync', lambda x: None)
    def test_write_4k(self):
        self.file = MemFS(self.img4k.read())
        fs = ExFatFS(self.file)

        self.assertEqual(fs.vbr.volume_serial_number, 0x766F83A4)
        self.assertEqual(fs.vbr.checksum, 0x249ECA1D)

        fs.set_uuid(b'\x78\x56\x34\x12')
        fs.check()

        self.assertEqual(fs.vbr.volume_serial_number, 0x12345678)
        self.assertEqual(fs.vbr.checksum, 614086685)

    def test_wrong_blocksize(self):
        self.file = MemFS(self.img4k.read())
        fs = ExFatFS(self.file, sector_size=512)

        fs.check()
        self.assertTrue(fs.inconsistent)

    def test_not_matching_vbrs(self):
        self.file = MemFS(self.img.read())
        offset = VBR.fields['FatOffset'].offset
        self.file.getbuffer()[offset:offset+4] = (35).to_bytes(4, byteorder='little')
        fs = ExFatFS(self.file)
        fs.check()
        self.assertEqual(fs.vbr.fat_offset, 35)
        self.assertEqual(fs.backup_vbr.fat_offset, 32)
        self.assertTrue(fs.inconsistent)
        self.assertEqual(fs.vbr.fat_length, fs.backup_vbr.fat_length)



class MemFS(io.BytesIO):
    def fileno(self):
        return "foobar"


if __name__ == '__main__':
    unittest.main()
