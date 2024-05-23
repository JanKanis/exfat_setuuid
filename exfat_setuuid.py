#!/usr/bin/env python3

import sys, re, argparse, pathlib, subprocess, weakref
from camel_converter import to_snake, to_pascal
from humanfriendly import parse_size, format_size



DEFAULT_BLOCK_SIZE = 512

# Volume Boot Record / Volume Boot Region
VBR_OFFSET = 0

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
			return DEFAULT_BLOCK_SIZE
	except (FileNotFoundError, ValueError):
		return DEFAULT_BLOCK_SIZE


class ExFatFS:
	def __init__(self, file, sector_size=512):
		self.inconsistent = False
		self.file = file
		self.vbr = VBR(self.file, VBR_OFFSET*sector_size, self, sector_size=sector_size)
		self.backup_vbr = VBR(self.file, BACKUP_VBR_OFFSET*sector_size, self, sector_size=sector_size, is_backup=True)

	def set_uuid(self, uuid):
		self.vbr.set_uuid(uuid)
		self.file.flush()
		os.fsync(self.file.fileno())
		self.backup_vbr.set_uuid(uuid)
		self.file.flush()
		os.fsync(self.file.fileno())
		
	def check(self):
		self.vbr.check()
		self.backup_vbr.check()


	def inconsistentFS(self, message):
		self.inconsistent = True
		print(message, file=sys.stderr)



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
		FileSystemRevision =          (104, 'version', 2),
		VolumeFlags =                 (106, 'flags', 2),
		BytesPerSectorShift =         (108, 'log2', 1),
		SectorsPerClusterShift =      (109, 'log2', 1),
		NumberOfFats =                (110, 'number', 1),
		DriveSelect =                 (111, 'number', 1),
		PercentInUse =                (112, 'number', 1),
		BootSignature =               (510, 'hex', 2),
	)
	
	calculated_fields = dict(
		**fields,
		Checksum = (None, 'hex'),
		BytesPerSector = (None, 'bytes'),
		BytesPerCluster = (None, 'bytes'),
		**{k+'Bytes': (None, 'bytes') for k, v in fields.items() if v[1] == 'sectors'},
		ClusterHeapLengthBytes = (None, 'bytes'),
	)
	
	
	#vbr_fields = [to_snake(k) for k in fields.keys()]\
	# + [to_snake(k)+'_bytes' for k, v in fields.items() if v[1] == 'sectors']\
	# + ['checksum', 'bytes_per_sector', 'bytes_per_cluster', 'cluster_heap_length_bytes']
	#hex_fields = ['checksum']


	def __init__(self, file, offset, exfatfs, sector_size=512, is_backup=False):
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
			#self.vbr_fields.append(fieldname)

		#sectorsize = 2**self.bytes_per_sector_shift
		#self.file.seek(self.offset + 11*sectorsize)
		#self.checksum = int.from_bytes(self.file.read(4), byteorder='little')
		#self.hex_fields.append('checksum')
		#self.vbr_fields.append('checksum')

		self.bytes_per_sector = 2**self.bytes_per_sector_shift
		self.bytes_per_cluster = self.bytes_per_sector * 2**self.sectors_per_cluster_shift
		#self.vbr_fields.extend(('bytes_per_sector', 'bytes_per_cluster'))
		
		self.checksum = self.get_checksum(report_bad=False)
		#self.hex_fields.append('checksum')
		#self.vbr_fields.append('checksum')

		for fieldname in sectorfields:
			f = fieldname+'_bytes'
			setattr(self, f, getattr(self, fieldname) * self.bytes_per_sector)
			#self.vbr_fields.append(f)

		self.cluster_heap_length_bytes = self.cluster_count * self.bytes_per_cluster
		#self.vbr_fields.append('cluster_heap_length_bytes')


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
		checksum_sector = self.get_checksum().to_bytes(4, byteorder='little') * (self.sector_size//4)
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
		self.file.seek(self.offset+self.fields['VolumeSerialNumber'][0])
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
			unit = desc[1]
			f = to_snake(name)
			val = getattr(self, f)
			s += f"  {f}: {self.format_value(val, unit)}\n"
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
	argp.add_argument('--autodetect-sector-size', action='store_true', help='Use device block size')
	argp.add_argument('--sector-size', default=None, type=lambda x: parse_size(x, binary=True), help='The sector size of the medium (defaults to 512 bytes). K-suffix is supported.')
	argp.add_argument('--ignore-invalid', action='store_true', help='Report configuration even if filesystem is corrupt')
	args = argp.parse_args()
	print(args)

	mode = 'rb' if args.uuid is None else 'rb+'
	with open(args.device, mode) as file:
		if args.sector_size is None and args.autodetect_sector_size:
			args.sector_size = try_get_block_size(args.device)
		if args.sector_size is None:
			args.sector_size = DEFAULT_BLOCK_SIZE
		print(args)

		fs = ExFatFS(file, sector_size=args.sector_size)
		fs.check()
		if fs.inconsistent:
			print(f"Not an ExFat filesystem or filesystem is corrupted. Did you specify the right block size? (using: {args.sector_size})", file=sys.stderr)
		if not fs.inconsistent or args.ignore_invalid:
			print(fs.vbr)
		
		if fs.inconsistent and not args.ignore_invalid:
			sys.exit(1)


if __name__ == '__main__':
	main()

