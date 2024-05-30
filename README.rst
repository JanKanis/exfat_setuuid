exfat_setuuid
=============

This python script will show some low level settings of an ExFAT file system, and can update the UUID (also known as serial number). It will also check the validity of the ExFAT superblock and backup superblock (also known as volume boot region).


Dependencies
------------
This script can (optionally) use the `humanfriendly` module to print values in human friendly ways and parse human friendly values on the command line. Without the module, it will show only the raw values.


Usage
-----

Show filesystem information::

    python3 exfat_setuuid.py /path/to/exfat/device

Set UUID::

    python3 exfat_setuuid.py /path/to/exfat/device --write-uuid ABCD-EF91

Other usage information::

    usage: exfat_setuuid.py [-h] [--write-uuid UUID] [--read-device-sector-size] [--sector-size SECTOR_SIZE] [--ignore-invalid] device

    This program shows low level configuration of an ExFat filesystem and checks the volume boot record (superblock) for consistecy. It also allows
    setting the UUID/serial number. Without options, will check consistency and show configuration.

    positional arguments:
      device                The device file to use.

    options:
      -h, --help            show this help message and exit
      --write-uuid UUID     Write this UUID (serial number) to the filesystem superblock. Before writing, the program will verify the consistency of
                            the filesystem superblock. WARNING: There should NEVER be more than one active filesystem with the same UUID on your
                            system. This should only be used if you are replacing an old ExFat filesystem!
      --read-device-sector-size
                            Use device block size (does not work on image files; this requires the `blockdev` program)
      --sector-size SECTOR_SIZE, -b SECTOR_SIZE
                            The sector size of the file system. K-suffix is supported. If omitted, will read sector size from filesystem superblock.
      --ignore-invalid      Report configuration even if filesystem is corrupt


Alternatives
------------

On Linux, the programs `exfatlabel` and `tune.exfat` (part of `exfatprogs`) can also edit the serial number/UUID.
