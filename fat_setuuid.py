#!/usr/bin/env python3

import sys, re
from camel_converter import to_snake




SECTOR_SIZE = 512

# Volume Boot Record / Volume Boot Region
VBR_OFFSET = 0*SECTOR_SIZE

BACKUP_VBR_OFFSET = 12*SECTOR_SIZE

UUID_OFFSET = 0x100		# relative to start of VBR

CHECKSUM_OFFSET = 11*SECTOR_SIZE    # relative to start of VBR
CHECKSUMMED_DATA_LENGTH = CHECKSUM_OFFSET



UUID = "ABCD-EFGH"
device = './testdrive'


def get_uuid_bytes(uuid_str):
	if not re.fullmatch('[0-9a-fA-F]{4}-[0-9a-fA-F]{4}', uuid_str):
		raise ValueError("invalid UUID, expected format: 12AB-E9FF")
		
	bytes_str = [uuid_str[7:9], uuid_str[5:7], uuid_str[2:4], uuid_str[0:2]]
	return bytes(int(x, 16) for x in bytes_str)


class ExFatFS:
	def __init__(self, file):
		self.file = file
		pass
	

	def write_uuid(uuid, file, vbr_offset):
		file.seek(vbr_offset+UUID_OFFSET)
		file.write(uuid)
	
	def get_checksum(vbr_offset, is_backup_vbr=False):
		file.seek(vbr_offset+CHECKSUM_OFFSET)
		checksum_block = file.read(SECTOR_SIZE)
		checksum_bytes = checksum_block[0:4]
		if not checksum_block == checksum_bytes * (SECTOR_SIZE//4):
			print(f"Checksum block of {'backup ' if is_backup_vbr else ''}volume boot record is corrupt. Expecting a repetition of the checksum value, found {checksum_block}",
						file=sys.stderr)
			sys.exit(1)
		return int.from_bytes(checksum_bytes, byteorder='little')
	
	def calc_checksum(vbr_offset):
		file.seek(vbr_offset)
		data = file.read(CHECKSUMMED_DATA_LENGTH)
		
		checksum = 0
		for i, byte in enumerate(data):
			if i in (106, 107, 112):
				continue
			checksum = (0x80000000 if (checksum & 1) else 0) + (checksum >> 1) + byte
			checksum &= 0xffffffff
		return checksum
	
	def check_vbr(file, vbr_offset, is_backup_vbr=False):
		file.seek(vbr_offset+3)
		fsname = file.read(61)
		
		file.seek(vbr_offset+510)
		boot_sig = file.read(2)

		if fsname != b'EXFAT   '+b'\x00'*53 or boot_sig != b'\x55\xaa':
			print(f"Invalid EXFAT {'backup ' if is_backup_vbr else ''}volume boot record. Found fsname {fsname}, boot signature {boot_sig}",
						file=sys.stderr)
			sys.exit(1)
		
		checksum = get_checksum(vbr_offset, is_backup_vbr)
		expected_checksum = calc_checksum(vbr_offset)
		if checksum != expected_checksum:
			print(f"Invalid checksum for {'backup ' if is_backup_vbr else ''}volume boot record. Expected {expected_checksum:x}, found {checksum:x}",
						file=sys.stderr)
			sys.exit(1)
	

class FSInfo:

	fields = [
	  # name (as in spec)          offset   unit    size (bytes, default 4)
		('PartitionOffset',             64,  'bytes', 8),
		('VolumeLength',                72,  'bytes', 	8),
		('FatOffset',                   80,  'sectors'),
		('FatLength',                   84,  'sectors'),
		('ClusterHeapOffset',           88,  'number'),
		('ClusterCount',                92,  'number'),
		('FirstClusterOfRootDirectory', 96,  'clusters'),
		('VolumeSerialNumber',          100, 'number'),
		('FileSystemRevision',          104, 'bytes', 2),
		('VolumeFlags',                 106, 'number', 2),
		('BytesPerSectorShift',         108, 'log2', 1),
		('SectorsPerClusterShift',      109, 'log2', 1),
		('NumberOfFats',                110, 'number', 1),
		('DriveSelect',                 111, 'number', 1),
		('PercentInUse',                112, 'number', 1),
		('BootSignature',               510, '', 2),
	]
	
	
	def __init__(self, file):
		file.seek(VBR_OFFSET)
		self.vbr = file.read(512)
		self.file_system_name = self.vbr[3:3+8]
		self._readfields()		
		
		#self.partition_offset = self._read(64, 8)
		#self.volume_length = self._read(72, 8)
		#self.fat_offset = self._read(80)
		#self.fat_length = self._read(84)
		#self.cluster_heap_offset = self._read(88)
		#self.
		
	def _read(self, offset, length=4):
		return int.from_bytes(self.vbr[offset:offset+length], byteorder='little')
		
	def _readfields(self):
		sectorfields, clusterfields = ([], [])
		for f in self.fields:
			name, offset, unit, *size = f
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
			elif unit == 'clusters':
				clusterfields.append(fieldname)
			
			setattr(self, fieldname, value)
		
		self.bytes_per_sector = 2**self.bytes_per_sector_shift
		self.bytes_per_cluster = self.bytes_per_sector * 2**self.sectors_per_cluster_shift
		
		for fieldname in sectorfields:
			setattr(self, fieldname+'_bytes', getattr(self, fieldname) * self.bytes_per_sector)
			
		for fieldname in clusterfields:
			setattr(self, fieldname+'_bytes', getattr(self, fieldname) * self.bytes_per_cluster)
	
	def check(self, is_backup=False):
		
	
	def __str__(self):
		s = "FSInfo:\n"
		for k, v in self.__dict__.items():
			if k == 'vbr':
				continue
			s += f"  {k}: {v}\n"
		return s
			
				
		

	
	
file = open('testdisk', 'rb+')
check_vbr(file, VBR_OFFSET)
check_vbr(file, BACKUP_VBR_OFFSET, is_backup_vbr=True)
fsinfo = FSInfo(file)
print(fsinfo)

print('Done')

