#!/usr/bin/env python3

import sys, re
from camel_converter import to_snake, to_pascal
from humanize import naturalsize




SECTOR_SIZE = 512

# Volume Boot Record / Volume Boot Region
VBR_OFFSET = 0*SECTOR_SIZE

BACKUP_VBR_OFFSET = 12*SECTOR_SIZE

UUID_OFFSET = 0x100		# relative to start of VBR

CHECKSUM_OFFSET = 11*SECTOR_SIZE    # relative to start of VBR
CHECKSUMMED_DATA_LENGTH = CHECKSUM_OFFSET

FILE_SYSTEM_NAME = b'EXFAT   '  # mind the spaces
BOOT_SIGNATURE = 0xaa55



UUID = "ABCD-EFGH"
device = './testdrive'


def get_uuid_bytes(uuid_str):
	if not re.fullmatch('[0-9a-fA-F]{4}-[0-9a-fA-F]{4}', uuid_str):
		raise ValueError("invalid UUID, expected format: 12AB-E9FF")
		
	bytes_str = [uuid_str[7:9], uuid_str[5:7], uuid_str[2:4], uuid_str[0:2]]
	return bytes(int(x, 16) for x in bytes_str)

def uuid_str(uuid_num):
	b1, b2, b3, b4 = (format(b, 'X') for b in reversed(uuid_num.to_bytes(4, byteorder='little')))
	return f"{b1+b2}-{b3+b4}"


class ExFatFS:
	def __init__(self, file):
		self.file = file
		self.vbr = VBR(self.file, VBR_OFFSET)
		self.backup_vbr = VBR(self.file, BACKUP_VBR_OFFSET, is_backup=True)

	def write_uuid(self, uuid, vbr_offset):
		self.vbr.write_uuid(uuid)
		self.backup_vbr.write_uuid(uuid)
		
	def check(self):
		self.vbr.check()
		self.backup_vbr.check()



class VBR:

	fields = dict(
	  # name (as in spec)         offset   unit    size (bytes, default 4)
		PartitionOffset =             (64,  'sectors', 8),
		VolumeLength =                (72,  'sectors', 	8),
		FatOffset =                   (80,  'sectors'),
		FatLength =                   (84,  'sectors'),
		ClusterHeapOffset =           (88,  'sectors'),
		ClusterCount =                (92,  'clusters'),
		FirstClusterOfRootDirectory = (96,  'clusters'),
		VolumeSerialNumber =          (100, 'uuid'),
		FileSystemRevision =          (104, 'bytes', 2),
		VolumeFlags =                 (106, 'number', 2),
		BytesPerSectorShift =         (108, 'log2', 1),
		SectorsPerClusterShift =      (109, 'log2', 1),
		NumberOfFats =                (110, 'number', 1),
		DriveSelect =                 (111, 'number', 1),
		PercentInUse =                (112, 'number', 1),
		BootSignature =               (510, '', 2),
	)
		
	def __init__(self, file, offset, is_backup=False):
		self.vbr_fields = []

		self.file = file
		self.offset = offset
		self.is_backup = is_backup
		
		self.file.seek(offset)
		self.vbr = file.read(512)
		
		self.file_system_name = self.vbr[3:3+8]
		self._readfields()


	def _read(self, offset, length=4):
		return int.from_bytes(self.vbr[offset:offset+length], byteorder='little')
		

	def _readfields(self):
		sectorfields = []
		for name, desc in self.fields.items():
			offset, unit, *size = desc
			if len(size) > 1:
				raise AssertionError("more than 4 values in field spec")
			if len(size):
				size = size[0]
			else:
				size = 4

			fieldname = to_snake(name)
			value = self._read(offset, size)
			if unit == 'sectors':
				sectorfields.append(fieldname)

			setattr(self, fieldname, value)
			self.vbr_fields.append(fieldname)

		self.bytes_per_sector = 2**self.bytes_per_sector_shift
		self.bytes_per_cluster = self.bytes_per_sector * 2**self.sectors_per_cluster_shift
		self.vbr_fields.extend(('bytes_per_sector', 'bytes_per_cluster'))

		for fieldname in sectorfields:
			f = fieldname+'_bytes'
			setattr(self, f, getattr(self, fieldname) * self.bytes_per_sector)
			self.vbr_fields.append(f)

		self.cluster_heap_length_bytes = self.cluster_count * self.bytes_per_cluster
		self.vbr_fields.append('cluster_heap_length_bytes')


	def get_checksum(self):
		self.file.seek(self.offset+CHECKSUM_OFFSET)
		checksum_block = file.read(SECTOR_SIZE)
		checksum_bytes = checksum_block[0:4]
		if not checksum_block == checksum_bytes * (SECTOR_SIZE//4):
			raise InconsistentExFatException(f"Checksum block of {'backup ' if self.is_backup else ''}volume boot record is corrupt. Expecting a repetition of the checksum value, found {checksum_block}")
		return int.from_bytes(checksum_bytes, byteorder='little')


	def calc_checksum(self):
		self.file.seek(self.offset)
		data = self.file.read(CHECKSUMMED_DATA_LENGTH)

		checksum = 0
		for i, byte in enumerate(data):
			if i in (106, 107, 112):
				continue
			checksum = (0x80000000 if (checksum & 1) else 0) + (checksum >> 1) + byte
			checksum &= 0xffffffff
		return checksum


	def check(self):
		self.file.seek(self.offset+11)
		must_be_zero = self.file.read(53)

		file.seek(self.offset+510)
		boot_sig = file.read(2)

		if self.file_system_name != FILE_SYSTEM_NAME:
			raise InconsistentExFatException(f"Invalid EXFAT filesystem name in {self._backup_str()}volume boot record. Found {self.file_system_name}, expected {FILE_SYSTEM_NAME}")

		if must_be_zero != b'\x00'*53:
			raise InconsistentExFatException(f"Invalid EXFAT filesystem: MustBeZero field in {self._backup_str()}volume boot record is not all zeros. Found {must_be_zero}")

		if self.boot_signature != BOOT_SIGNATURE:
			raise InconsistentExFatException(f"Invalid EXFAT filesystem: boot signature in {self._backup_str()}volume boot record is not 0x{BOOT_SIGNATURE:x}. Found 0x{self.boot_signature:x}.")

		checksum = self.get_checksum()
		expected_checksum = self.calc_checksum()
		if checksum != expected_checksum:
			raise InconsistentExFatException(f"Invalid checksum for {self._backup_str()}volume boot record: expected {expected_checksum:x}, found {checksum:x}")


	def write_uuid(self, uuid):
		self.file.seek(self.offset+UUID_OFFSET)
		self.file.write(uuid)


	def _backup_str(self):
		return 'backup ' if self.is_backup else ''


	def __str__(self):
		s = "FSInfo:\n"
		for f in self.vbr_fields:
			unit = self.fields.get(to_pascal(f), (None,None))[1]
			val = getattr(self, f)

			s += f"  {f}: "
			if unit == 'uuid':
				s += uuid_str(val)
			elif unit is None:
				s += f"{val} ({naturalsize(val, binary=True)})"
			else:
				s += str(val)
			s += "\n"
		return s


class InconsistentExFatException(Exception):
	pass


file = open(sys.argv[1], 'rb+')
fs = ExFatFS(file)
fs.check()
print(fs.vbr)

print('Done')

