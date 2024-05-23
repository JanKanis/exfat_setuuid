#!/usr/bin/env python3

import sys, os, re, argparse, pathlib, subprocess, weakref
from collections import namedtuple

from camel_converter import to_snake, to_pascal
from humanfriendly import parse_size, format_size



DEFAULT_BLOCK_SIZE = 512

# Volume Boot Record / Volume Boot Region
BACKUP_VBR_OFFSET = 12

CHECKSUM_OFFSET = 11    # no. of sectors relative to start of VBR
CHECKSUMMED_DATA_LENGTH = CHECKSUM_OFFSET

FILE_SYSTEM_NAME = b'EXFAT   '  # mind the spaces
BOOT_SIGNATURE = 0xAA55



def get_uuid_bytes(uuid_str):
	if not re.fullmatch('[0-9a-fA-F]{4}-[0-9a-fA-F]{4}', uuid_str):
		raise ValueError("invalid UUID, expected format: 12AB-E9FF")
		
	bytes_str = [uuid_str[7:9], uuid_str[5:7], uuid_str[2:4], uuid_str[0:2]]
	return bytes(int(x, 16) for x in bytes_str)

def uuid_str(uuid_num):
	b1, b2, b3, b4 = (format(b, '02X') for b in reversed(uuid_num.to_bytes(4, byteorder='little')))
	return f"{b1+b2}-{b3+b4}"


def try_get_block_size(device):
	try:
		p = subprocess.run(['blockdev', '--getbsz', device], capture_output=True, encoding='utf8')
		if p.returncode == 0:
			return int(p.stdout)
		else:
			print("Unable to determine device block size, defaulting to 512: "+p.stderr)
			return None
	except (FileNotFoundError, ValueError):
		return None


class ExFatFS:
	def __init__(self, file, sector_size=None):
		self.inconsistent = False
		self.file = file
		self.vbr = VBR(self.file, 0, self, sector_size=sector_size)
		if sector_size is None:
			sector_size = self.vbr.sector_size
		self.backup_vbr = VBR(self.file, BACKUP_VBR_OFFSET*sector_size, self, sector_size=sector_size, is_backup=True)

	def set_uuid(self, uuid):
		self.vbr.set_uuid(uuid)
		self.file.flush()
		os.fsync(self.file.fileno())  # Update main and backup VBR one by one for recoverability
		self.backup_vbr.set_uuid(uuid)
		self.file.flush()
		os.fsync(self.file.fileno())
		
	def check(self):
		self.vbr.check()
		self.backup_vbr.check()
		for field, desc in VBR.fields.items():
			if field in {'VolumeFlags', 'PercentInUse'}:
				continue
			f = to_snake(field)
			if not getattr(self.vbr, f) == getattr(self.backup_vbr, f):
				self.inconsistentFS(f"Invalid EXFAT filesystem: {field} in VBR does not equal {field} in backup VBR. Found {VBR.format_value(getattr(self.vbr, f), desc[1])} and {VBR.format_value(getattr(self.backup_vbr, f), desc[1])}")


	def inconsistentFS(self, message):
		self.inconsistent = True
		print(message, file=sys.stderr)



D = Desc = namedtuple('Desc', 'offset unit size', defaults=[4])
class VBR:

	fields = dict(
		# name (as in spec)          offset   unit      size (bytes, default 4)
		PartitionOffset =             D(64,  'sectors', 8),
		VolumeLength =                D(72,  'sectors', 8),
		FatOffset =                   D(80,  'sectors'),
		FatLength =                   D(84,  'sectors'),
		ClusterHeapOffset =           D(88,  'sectors'),
		ClusterCount =                D(92,  'clusters'),
		FirstClusterOfRootDirectory = D(96,  'clusters'),
		VolumeSerialNumber =          D(100, 'uuid'),
		FileSystemRevision =          D(104, 'version', 2),
		VolumeFlags =                 D(106, 'flags', 2),
		BytesPerSectorShift =         D(108, 'log2', 1),
		SectorsPerClusterShift =      D(109, 'log2', 1),
		NumberOfFats =                D(110, 'number', 1),
		DriveSelect =                 D(111, 'number', 1),
		PercentInUse =                D(112, 'number', 1),
		BootSignature =               D(510, 'hex', 2),
	)
	
	calculated_fields = dict(
		**fields,
		Checksum = D(None, 'hex'),
		BytesPerSector = D(None, 'bytes'),
		BytesPerCluster = D(None, 'bytes'),
		**{k+'Bytes': D(None, 'bytes') for k, v in fields.items() if v[1] == 'sectors'},
		ClusterHeapLengthBytes = D(None, 'bytes'),
	)


	def __init__(self, file, offset, exfatfs, sector_size=None, is_backup=False):
		self.file = file
		self.offset = offset
		self.exfatfs = weakref.ref(exfatfs)
		self.sector_size = sector_size
		self.is_backup = is_backup

		self.read_data()


	def read_data(self):
		self.file.seek(self.offset)
		self.vbr = self.file.read(512)
		
		self.file_system_name = self.vbr[3:3+8]
		self._readfields()


	def _read(self, offset, length=4):
		return int.from_bytes(self.vbr[offset:offset+length], byteorder='little')
		

	def _readfields(self):
		sectorfields = []
		for name, desc in self.fields.items():
			offset, unit, size = desc

			fieldname = to_snake(name)
			value = self._read(offset, size)
			if unit == 'sectors':
				sectorfields.append(fieldname)

			setattr(self, fieldname, value)

		self.bytes_per_sector = 2**self.bytes_per_sector_shift
		self.bytes_per_cluster = self.bytes_per_sector * 2**self.sectors_per_cluster_shift

		if self.sector_size is None:
			self.sector_size = self.bytes_per_sector
			print(f"Using filesystem reported sector size of {self.sector_size} bytes", file=sys.stderr)

		self.checksum = self.get_checksum(report_bad=False)

		for fieldname in sectorfields:
			f = fieldname+'_bytes'
			setattr(self, f, getattr(self, fieldname) * self.bytes_per_sector)

		self.cluster_heap_length_bytes = self.cluster_count * self.bytes_per_cluster


	def get_checksum(self, report_bad=True):
		self.file.seek(self.offset+self.sector_size*CHECKSUM_OFFSET)
		checksum_block = self.file.read(self.sector_size)
		checksum_bytes = checksum_block[0:4]
		if report_bad and not checksum_block == checksum_bytes * (self.sector_size//4):
			self.inconsistentFS(f"Invalid EXFAT filesystem: Checksum block of {'backup ' if self.is_backup else ''}volume boot record is corrupt. Expecting a repetition of the checksum value.")
		return int.from_bytes(checksum_bytes, byteorder='little')


	def calc_checksum(self):
		self.file.seek(self.offset)
		data = self.file.read(CHECKSUMMED_DATA_LENGTH*self.sector_size)

		checksum = 0
		for i, byte in enumerate(data):
			if i in (106, 107, 112):
				continue
			checksum = (0x80000000 if (checksum & 1) else 0) + (checksum >> 1) + byte
			checksum &= 0xffffffff
		return checksum


	def write_checksum(self):
		checksum_sector = self.calc_checksum().to_bytes(4, byteorder='little') * (self.sector_size//4)
		self.file.seek(self.offset + self.sector_size*CHECKSUM_OFFSET)
		self.file.write(checksum_sector)


	def check(self):
		self.file.seek(self.offset+11)
		must_be_zero = self.file.read(53)

		self.file.seek(self.offset+510)
		boot_sig = self.file.read(2)

		if self.file_system_name != FILE_SYSTEM_NAME:
			self.inconsistentFS(f"Invalid EXFAT filesystem: name in {self._backup_str()}volume boot record. Found {self.file_system_name}, expected {FILE_SYSTEM_NAME}")

		if must_be_zero != b'\x00'*53:
			self.inconsistentFS(f"Invalid EXFAT filesystem: MustBeZero field in {self._backup_str()}volume boot record is not all zeros.")

		if self.boot_signature != BOOT_SIGNATURE:
			self.inconsistentFS(f"Invalid EXFAT filesystem: boot signature in {self._backup_str()}volume boot record is not 0x{BOOT_SIGNATURE:X}. Found 0x{self.boot_signature:X}.")
		
		if self.bytes_per_sector != self.sector_size:
			self.inconsistentFS(f"Invalid EXFAT filesystem: Using a blocksize of {self.sector_size}, but {self._backup_str()}volume boot record says blocksize is {self.bytes_per_sector}")

		checksum = self.get_checksum()
		expected_checksum = self.calc_checksum()
		if checksum != expected_checksum:
			self.inconsistentFS(f"Invalid EXFAT filesystem: Invalid checksum for {self._backup_str()}volume boot record: expected {expected_checksum:x}, found {checksum:x}")


	def base_write_uuid(self, uuid):
		self.file.seek(self.offset+self.fields['VolumeSerialNumber'].offset)
		self.file.write(uuid)


	def set_uuid(self, uuid):
		self.base_write_uuid(uuid)
		self.write_checksum()
		self.read_data()


	def inconsistentFS(self, message):
		self.exfatfs().inconsistentFS(message)

	def _backup_str(self):
		return 'backup ' if self.is_backup else ''


	def __str__(self):
		s = "FSInfo:\n"
		for name, desc in self.calculated_fields.items():
			f = to_snake(name)
			val = getattr(self, f)
			s += f"  {f}: {self.format_value(val, desc.unit)}\n"
		return s


	@staticmethod
	def format_value(val, unit):
		if unit == 'uuid':
			return uuid_str(val)
		if unit == 'hex':
			return f"0x{val:X}"
		if unit == 'version':
			return f"{val//256}.{val%256}"
		if unit == 'flags':
			return ','.join(name for name, flag in (('ActiveFat', 1), ('VolumeDirty', 2), ('MediaFailure', 4), ('ClearToZero', 8), (f'Reserved=0x{val&0xfff0:X}', 0xfff0)) if flag&val) or '(none)'
		if unit == 'bytes':
			return f"{val} ({format_size(val, binary=True)})"
		return str(val)		


class InconsistentExFatException(Exception):
	pass



def main():
	argp = argparse.ArgumentParser(description="This program shows low level configuration of an ExFat filesystem and checks the volume boot record (superblock) for consistecy. It also allows setting the UUID/serial number. Without options, will check consistency and show configuration.")
	argp.add_argument('device', type=pathlib.Path, help="The device file to use.")
	argp.add_argument('--write-uuid', dest='uuid', type=get_uuid_bytes, help="Write this UUID (serial number) to the filesystem superblock. Before writing, the program will verify the consistency of the filesystem superblock. WARNING: There should NEVER be more than one active filesystem with the same UUID on your system. This should only be used if you are replacing an old ExFat filesystem!")
	argp.add_argument('--read-device-sector-size', action='store_true', help='Use device block size')
	argp.add_argument('--sector-size', '-b', default=None, type=lambda x: parse_size(x, binary=True), help='The sector size of the file system. K-suffix is supported. If omitted, will read sector size from filesystem superblock.')
	argp.add_argument('--ignore-invalid', action='store_true', help='Report configuration even if filesystem is corrupt')
	args = argp.parse_args()

	mode = 'rb' if args.uuid is None else 'rb+'
	with open(args.device, mode) as file:
		if args.sector_size is None and args.read_device_sector_size:
			args.sector_size = try_get_block_size(args.device)

		fs = ExFatFS(file, sector_size=args.sector_size)
		fs.check()
		if fs.inconsistent:
			print(f"Error: Not an ExFat filesystem or filesystem is corrupted.", file=sys.stderr)
			if not args.ignore_invalid:
				sys.exit(1)

		if not args.uuid:
			print(fs.vbr)

		if not fs.inconsistent and args.uuid:
			fs.set_uuid(args.uuid)
			fs.check()
			print(f"Updated UUID to {uuid_str(int.from_bytes(args.uuid, byteorder='little'))}")


if __name__ == '__main__':
	main()
