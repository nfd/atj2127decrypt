"""
The Actions ADFU upgrade script, translated from Actions scripting language
"""
import os
import json
import struct
import argparse
import time
from collections import namedtuple

import adfu, adfu_mock_usb_device

# Types of command
ADFU_COMMAND_RAM = 19 # Write data to RAM
ADFU_COMMAND_STORAGE = 16 # NAND-related commands
ADFU_COMMAND_SWIT = 32 # Switch from HW ADFU to SW ADFU, unclear how this differs from CALL_ENTRY
ADFU_COMMAND_CALL_ENTRY = 33 # Run code on device
ADFU_COMMAND_GET_STATUS = 35 # Read a block of memory from a predefined location

class NANDNotFound(Exception):
	pass

def chunks(b, size):
	return [b[n:n+size] for n in range(0, len(b), size)]

# Parameters for this particular ADFU
CONFIG = {
	'erase_flash': True,

	'adfus': {
		# Software ADFU, called ADFUS in original script
		'filename': 'adfus.bin',
		'download_address': 0xbfc18000,
	},
	'hwsc': {
		# HWSC, which returns NAND parameter info
		'filename': 'nandhwsc.bin',
		'download_address': 0xbfc1e000,
	},
	'flash_id': {
		# Flash ID constants for the NAND driver
		'filename': 'flash_id.bin',
		# Download address is returned by the HWSC program
	},
	'brec': {
		'filename_template': 'brec%04x.bin',
		# These become part of brec: the bin is inserted at 4k into the file,
		# and the res is written immediately after brec. 
		'welcome_bin_template': 'welcome%04x.bin',
		'wecome_bin': 'welcome.bin', # use if templated file not available
		'welcome_res_template': 'welcome%04x.res',
		'welcome_res': 'welcome.res', # ditto
		'welcome_bin_merge_location': 4 * 1024,
		'download_address': 0x46000000,
	},
	'mbrec': {
		'filename': 'mbrec.bin',
		'download_address': 0x40000000,
	},
	'fwsc': {
		# Firmware scan?
		'filename_template': 'fwsc%04x.bin', # %x is the Flash type e.g. f650
		'download_address': 0xbfc1e000,
		'entrypoint': 0xbfc1e200,

		#INSERT INTO "FWSC" VALUES('fwscf644.bin',-1077813248,8,63044);
	},
	'fwimage': {
		'sdk_description': '20121228_SVN9494_Formal_AddUHost',
		'download_address': 0xc0000000,
		'INF_USERDEFINED_ID_48': '4512482ADF0FEEEE', # AKA UsbSetupInfo
		'SDK_VER': '1.10',
		'files': [
			'kernel.drv', 'KER_TEXT.BIN', 'KER_INIT.BIN', 'KER_DATA.BIN',
			'fmtdata.bin', 'card.DRV', 'cards.DRV', 'nand.DRV', 'uhost.DRV',
			'fat32n.drv', 'fat16n.drv', 'exfatn.drv', 'aud_dev.drv',
			'mmm_mp.al', 'adWMA.al', 'adWAV.al', 'adMP3.al', 'adAPE.al',
			'adFLAC.al', 'mmm_id.al', 'mmm_vp.al', 'mmm_mr.al', 'aeWAV.al',
			'aeMP3.al', 'adOGG.al', 'adAAX.al', 'adAUD.al', 'adAAC.al',
			'adAIN.al', 'adACT.al', 'aeACT.al', 'FWDec.al', 'config.bin',
			'config.spc', 'config.txt', 'legal.txt', 'm_type.txt',
			'alarm1.mp3', 'fmtool.cfg', 'drv_lcd.drv', 'drv_ui.drv', 'key.drv',
			'drv_fm.drv', 'V936GBK.TBL', 'V950BIG.TBL', 'V932JIS.TBL',
			'V949KOR.TBL', 'V874.TBL', 'V1250.TBL', 'V1251.TBL', 'V1252.TBL',
			'V1253.TBL', 'V1254.TBL', 'V1255.TBL', 'V1256.TBL', 'V1257.TBL',
			'FTBL_GB.$$$', 'FTBL_B5.$$$', 'FTBL_JP.$$$', 'FTBL_KR.$$$',
			'874L.TBL', '1250L.TBL', '1251L.TBL', '1252L.TBL', '1253L.TBL',
			'1254L.TBL', '1255L.TBL', '1256L.TBL', '1257L.TBL', 'UNICODE.FON',
			'common.sty', 'MainMenu.sty', 'music.sty', 'video.sty',
			'picture.sty', 'browser.sty', 'setting.sty', 'ebook.sty',
			'playlist.sty', 'tools.sty', 'udisk.sty', 'alarm.sty',
			'record.sty', 'radio.sty', 'config.sty', 'upgrade.sty',
			'mainmenu.mcg', 'music.mcg', 'video.mcg', 'picture.mcg',
			'browser.mcg', 'setting.mcg', 'ebook.mcg', 'tools.mcg',
			'record.mcg', 'radio.mcg', 'manager.AP', 'config.ap',
			'mainmenu.AP', 'music.ap', 'mengine.ap', 'browser.ap',
			'picture.ap', 'udisk.ap', 'setting.ap', 'video.ap', 'playlist.ap',
			'ebook.ap', 'tools.ap', 'alarm.ap', 'radio.ap', 'fmengine.ap',
			'record.AP', 'fwupdate.AP']
	},

}

def c_struct_basic_type(struct_typ):
	class BasicType:
		_FMT_STRING = None # set below
		LENGTH = None # set below
		BASIC_TYPE = True

		def __init__(self, backing, offset=0):
			self._backing = backing
			self.offset = offset

		def get(self):
			return struct.unpack(self.FMT_STRING, self.get_bytes())[0]

		def get_bytes(self):
			return self._backing[self.offset:self.offset + self.LENGTH]

		def set(self, value):
			struct.pack_into(self.FMT_STRING, self._backing, self.offset, value)
	
	BasicType.FMT_STRING = '<' + struct_typ
	BasicType.LENGTH = struct.calcsize(BasicType.FMT_STRING)
	BasicType.__name__ = 'BasicType_%s' % (struct_typ)

	return BasicType

BASIC_TYPES = {
		'B': c_struct_basic_type('B'),
		'H': c_struct_basic_type('H'),
		'I': c_struct_basic_type('I')
}

StructMember = namedtuple('StructMember', ('offset', 'typ', 'count'))

def round_up(num, rounding):
	round_up_amt = rounding - (num % rounding)
	if round_up_amt != rounding:
		num += round_up_amt

	return num

def c_struct(name, *members):
	struct_members = {}
	current_offset = 0

	for member in members:
		count = member[2] if len(member) == 3 else 1

		typ = BASIC_TYPES[member[0]] if isinstance(member[0], str) else member[0]

		struct_member = StructMember(offset=current_offset, typ=typ, count=count)

		struct_members[member[1]] = struct_member
		current_offset += (typ.LENGTH * count)
	
	class CStruct:
		MEMBERS = None # Set below
		LENGTH = None # Set below
		BASIC_TYPE = False

		def __init__(self, backing=None, offset=0):
			self.offset = offset

			if isinstance(backing, bytes):
				backing = bytearray(backing)
			elif backing is None:
				backing = bytearray(len(self))

			assert isinstance(backing, bytearray), type(backing)
			self._backing = backing

			self.members = {}
			for name, struct_member in self.MEMBERS.items():
				member_array = []
				for idx in range(struct_member.count):
					member_offset = self.offset + struct_member.offset + (struct_member.typ.LENGTH * idx)
					member_obj = struct_member.typ(backing, offset=member_offset)
					member_array.append(member_obj)

				self.members[name] = member_array

		def get(self):
			return self._backing[self.offset:self.offset + self.LENGTH]

		def set(self, val):
			raise NotImplementedError()

		def get_item(self, name, index=0):
			val = self.members[name][index]
			return val.get() if val.BASIC_TYPE else val

		def __getitem__(self, key):
			return self.get_item(key)

		def get_bytes(self, name, index=0, count=1):
			offset = self.members[name][index].offset

			return self._backing[offset:offset+self.members[name][index].LENGTH * count]

		def set_bytes(self, name, val):
			offset = self.members[name][0].offset

			self._backing[offset:offset+len(val)] = val

		def set_item(self, name, value, index=0):
			self.members[name][index].set(value)

		def __setitem__(self, key, value):
			self.set_item(key, value, index=0)

		def __len__(self):
			return self.LENGTH

	CStruct.__name__ = name
	CStruct.MEMBERS = struct_members
	CStruct.LENGTH = sum(member.typ.LENGTH * member.count for member in struct_members.values())

	return CStruct

# What we get back from nandhwsc.bin
HWScanInfo = c_struct('HWScanInfo', ('H', 'frametype'), ('B', 'hwscflag', 14), ('I', 'flash_id', 2),
		('I', 'nafbscparaddr'), ('B', 'reserved', 128))

# What we write into FWSC prior to flashing it.
FWInfoBlock = c_struct('FWInfoBlock',
		('B', 'pad1', 2),		# 0, 1
		('B', 'bEraseFlag'), # 2: Erase Flash?
		('B', 'pad2', 3), # 3, 4, 5: padding
		('H', 'dBRECCap'), # ?
		('I', 'dLFICap'),
		('I', 'flash_size'),
		('B', 'spi_nor_decrypt_mode'))

def get_nand_info_block(nand_id_data, nand_id):
	found = False
	nand_info_block = None

	for nand_info_block in chunks(nand_id_data, 128):
		if len(nand_info_block) != 128:
			break

		for nand_id_byte, infoblock_id_byte in zip(nand_id, nand_info_block[:8]):
			if infoblock_id_byte != 255 and infoblock_id_byte != nand_id_byte:
				break
		else:
			found = True
			break

	if found is False:
		raise NANDNotFound()
	else:
		return nand_info_block

def get_flash_type(nand_info_block):
	# This is pretty nasty.
	# NB this makes more sense in hex, e.g. 63045 = 0xF645 = hynix 26nm MLC flash (see ap_upgrade)
	if nand_info_block[0] == 173 and (nand_info_block[5] & 7) == 3:
		# Hynix 26nm MLC
		return 0xf645
	elif nand_info_block[0] == 152:
		# Toshiba 26nm MLC
		return 0xf646
	elif nand_info_block[0] == 173 and (nand_info_block[5] & 7) == 1:
		# Hynix 20nm MLC
		return 0xf647
	elif nand_info_block[0] == 236 and (nand_info_block[5] & 7) == 4:
		# Samsung 21nm MLC
		return 0xf648
	elif nand_info_block[0] == 44 and nand_info_block[2] == 68 and (nand_info_block[1] & 15) == 4:
		# Micron 20nm MLC
		return 0xf649
	elif nand_info_block[0] == 69 and nand_info_block[5] == 87:
		# Sandisk 19nm MLC
		return 0xf650
	else:
		return 0xf644

def align(b, amt):
	padding = len(b) % amt if amt else 0
	if padding == 0:
		return b
	else:
		return b + (b'\x00' * (amt - padding))

LFICapInfo_t = c_struct('LFICapInfo_t',
		('I', 'SD_Capacity'),
		('I', 'VM_Capacity'),
		('I', 'MI_Capacity'),
		('I', 'UI_Capacity'),
		('I', 'UserDisk_Start_Addr'),
		('I', 'vm_disk_cap'),
		('I', 'udisk_cap'),
		('I', 'hide_disk_cap'),
		('I', 'auto_disk_cap'),
		('I', 'reserved', 3))

DFUCapInfo_t = c_struct('DFUCapInfo_t',
		('I', 'vm_disk_cap'),
		('I', 'udisk_cap'),
		('I', 'hide_disk_cap'),
		('I', 'auto_disk_cap'),
		('I', 'Reserved', 4))

LDIR_t = c_struct('LDIR_t',
		('B', 'filename', 11),
		('B', 'attr'),
		('B', 'subtype'),
		('B', 'reserved0'),
		('H', 'version'),
		('I', 'offset'),
		('I', 'length'),
		('B', 'reserve1', 4),
		('I', 'checksum'))

LFIHead_t = c_struct('LFIHead_t', 
		('I', 'LFIFlag'),			# 0..3
		('B', 'sdkversion', 4),		# from SDK_VER   4..7
		('B', 'version', 4),		# from VER  8..11
		('H', 'VID'),				# 12..13
		('H', 'PID'),				# 14..15
		('I', 'DirItemCheckSum'),   # 16..19
		(LFICapInfo_t, 'CapInfo'),  # 20..67
		('B', 'Reserve0', 11),		# 68..78
		('B', 'udisk_setting'),		# from udisk_set_value  79..79
		('B', 'UsbSetupInfo', 48),	# from INF_USERDEFINED_ID_48  80..127
		('B', 'sdk_description', 336),	# from SDK_DESCRIPTION   128...463
		('B', 'Reserve3', 42),		# 464..505
		('I', 'R3_cfg_offset'),		# 506..509
		('H', 'Headchecksum'),		# 510..513
		(LDIR_t, 'ldiritem', 240))	# 514...

ADFU_FWScanInfo_t = c_struct('ADFU_FWScanInfo_t',
	('B', 'FrameType', 2),
	('H', 'VID'),
	('H', 'PID'),
	('B', 'FwscFlag', 14),
	('I', 'Logical_Cap'),
	('H', 'wFwStatus'),
	('H', 'logic_block_cap'),
	('I', 'Lfi_Cap'),
	('I', 'Vm_Cap'),
	('B', 'reserved', 476))

def file_checksum(b, stride=2, magic=0):
	"""
	Calculate a rather literal checksum.

	Note that although this function reads and returns 32-bit words, it is
	sometimes used with a 16-bit stride, which means the reads overlap.
	"""
	checksum = 0
	offset = 0

	if stride == 4:
		# Optimisation -- same logic as 'else' path below.
		for intvals in struct.iter_unpack('<I', b):
			checksum += intvals[0]
	else:
		# Slow path
		for offset in range(0, len(b) - 4, stride):
			checksum += (b[offset] + (b[offset + 1] << 8) + (b[offset + 2] << 16) + (b[offset + 3] << 24))
	
	checksum += magic
	return checksum

def ldir_style_filename(filename):
	filename = filename.split('.')
	if len(filename) == 1:
		filename.append('')
	padded_filename = '%-8s%-3s' % (filename[0].upper(), filename[1].upper())
	return padded_filename

class LFI:
	def __init__(self, package):
		self.download_address = package['fwimage']['download_address']

		if package['fwimage'].get('premerged', False):
			self._load_premerged(package)
		else:
			self._create_fwimage(package)

	def _load_premerged(self, package):
		fwimage_bytes = package.read_and_pad(package['fwimage']['premerged_filename'], 512)
		self.lfihead = LFIHead_t(fwimage_bytes)
		self.fwimage = [fwimage_bytes]

	def _create_fwimage(self, package):
		lfihead_bytes = bytearray(LFIHead_t.LENGTH)
		lfihead = LFIHead_t(lfihead_bytes)

		lfihead['LFIFlag'] = 0x0ff0aa55 # magic LFI signature
		lfihead.set_bytes('sdk_description', package['fwimage']['sdk_description'].encode('utf-8'))
		lfihead.set_bytes('UsbSetupInfo', package['fwimage']['INF_USERDEFINED_ID_48'].encode('utf-8'))
		lfihead.set_bytes('sdkversion', package['fwimage']['SDK_VER'].encode('utf-8'))
		lfihead.set_bytes('version', package['fwimage']['SDK_VER'].encode('utf-8')) # ?

		r3_config_filename = package['fwimage'].get('r3_config_filename')

		fwimage = [lfihead_bytes]
		offset  = len(lfihead_bytes)

		for idx, filename in enumerate(package['fwimage']['files']):
			file_bytes = package.read_and_pad(filename, 512)

			ldir = lfihead.get_item('ldiritem', idx)
			ldir.set_bytes('filename', ldir_style_filename(filename).encode('utf-8')),
			ldir['offset'] = offset // 512
			ldir['checksum'] = file_checksum(file_bytes, stride=4) & 0xffffffff
			ldir['length'] = len(file_bytes)
			fwimage.append(file_bytes)

			if r3_config_filename == filename:
				lfihead['R3_cfg_offset'] = offset // 512

			offset += len(file_bytes)

		lfihead['DirItemCheckSum'] = file_checksum(lfihead.get_bytes('ldiritem', 0, 240), stride=4) & 0xffffffff

		lfihead['udisk_setting'] = 1 # TODO what is this?

		self.fwimage = fwimage
		self.lfihead = lfihead
		self.compute_head_checksum()

	def compute_head_checksum(self):
		lfihead_bytes = self.fwimage[0]
		self.lfihead['Headchecksum'] = file_checksum(lfihead_bytes[:510], stride=2) & 0xffff # TODO nasty offset

	def set_cap(self, vm_disk_cap, udisk_cap):
		""" Capacities, I think. """
		self.lfihead['CapInfo']['vm_disk_cap'] = vm_disk_cap
		self.lfihead['CapInfo']['udisk_cap'] = udisk_cap
		self.compute_head_checksum()

	def get(self):
		return b''.join(self.fwimage)

	def __len__(self):
		return sum(len(part) for part in self.fwimage)

class BrecWithResources:
	def __init__(self, package, flash_type):
		if package['brec'].get('premerged', False):
			self._brec_bin = package.read_and_pad(package['brec']['filename_template'] % (flash_type), 1024)
			self._res = b''
		else:
			self._res = self._load_res(package, flash_type)
			self._brec_bin = self._load_merged_brec_bin(package, flash_type, len(self._res))

		self.sector_count = (len(self._brec_bin) + len(self._res)) // 512 # dwSector_Size = dBRECCap in original
		self.download_address = package['brec']['download_address']

		# TODO: Load this from the Upgrade thing below, also do the struct
		# merging. Probably should make a struct class tbh

	def get(self):
		if self._res:
			return self._brec_bin + self._res
		else:
			return self._brec_bin

	def set_header_data(self, dLFICap, sCapInfo, flash_size, spi_nor_decrypt_mode, nand_info_block):
		struct.pack_into('<I', self._brec_bin, 8, dLFICap)
		self._brec_bin[128:128+64] = nand_info_block[:64]
		self._brec_bin[192:192 + 32] = sCapInfo

	def _load_merged_brec_bin(self, package, flash_type, resource_len):
		"""
		Retrieve brec and welcome.bin, insert welcome.bin 4k inside the brec,
		and return the result. 
		"""
		brec_bytes = package.read_and_pad(package['brec']['filename_template'] % (flash_type), 1024)
		welcome_bin_bytes = self._load_with_fallback(package, 'welcome_bin_template', 'welcome_bin', flash_type)

		if welcome_bin_bytes:
			# Merge it in.
			merge_start = package['brec']['welcome_bin_merge_location']
			brec_bytes[merge_start:merge_start + len(welcome_bin_bytes)] = welcome_bin_bytes

			# Store location of start and end of welcome resources
			struct.pack_into('<HH', brec_bytes, 12, len(brec_bytes) // 512, resource_len // 512)

		# Length of brec in sectors, length of whole ensemble in sectors.
		struct.pack_into('<HH', brec_bytes, 4, len(brec_bytes) // 512, (len(brec_bytes) + resource_len) // 512)

		# Bizzarre-o checksum
		checksum = file_checksum(brec_bytes[512:], stride=2, magic=0x1234)
		struct.pack_into('<H', brec_bytes, 0, checksum & 0xffff)

		return brec_bytes

	def _load_res(self, package, flash_type):
		return self._load_with_fallback(package, 'welcome_res_template', 'welcome_res', flash_type)

	def _load_with_fallback(self, package, key, fallback_key, flash_type):
		"""
		try to load welcome650.bin and .res (for numbers varying with flash type),
		falling back to generic welcome.bin and welcome.res,
		or None if neither of these is present.
		"""
		filenames = [
				package['brec'][key] % (flash_type) if key in package['brec'] else None,
				package['brec'][fallback_key] if fallback_key in package['brec'] else None]

		for filename in filenames:
			if filename and package.exists(filename):
				return package.read_and_pad(filename, 512)
		else:
			return None

def load_mbrec(package):
	"""
	Load master boot record and compute magic checksum
	"""
	data = package.read_and_pad(package['mbrec']['filename'], 512)

	checksum = file_checksum(data[2:-2], stride=2, magic=0x1234)
	checksum &= 0xffff

	struct.pack_into('<H', data, 0, checksum)

	return data

class Package:
	def __init__(self, config, basedir, no_write=False):
		self.config = config.copy()
		self.basedir = basedir
		self.update_config()
		self.no_write = no_write

	def __getitem__(self, key):
		return self.config[key]

	def update_config(self):
		def merge_dicts(src, dst):
			"""
			Like dict.update(), but non-destructively (and recursively) updates values which are dicts.
			"""
			for key, value in dst.items():
				if isinstance(value, dict) and isinstance(src.get(key), dict):
					merge_dicts(src[key], value)
				else:
					src[key] = value

		adfu_info_pathname = os.path.join(self.basedir, 'adfu_info.json')
		if os.path.exists(adfu_info_pathname):
			with open(adfu_info_pathname, 'r') as h:
				adfu_info = json.load(h)

			merge_dicts(self.config, adfu_info)

	def read_bytes(self, filename):
		with open(os.path.join(self.basedir, filename), 'rb') as h:
			return bytearray(h.read())

	def exists(self, filename):
		return os.path.exists(os.path.join(self.basedir, filename))

	def read_and_pad(self, filename, amt):
		return align(self.read_bytes(filename), amt)

	def upload_file_to_ram(self, usb_msc, config_key, align=0):
		section = self[config_key]
		file_bytes = self.read_and_pad(section['filename'], align)

		usb_msc.adfu_write_to_ram(section['download_address'], file_bytes)

	def dump_flash_write_to_disk(self, download_addr, data):
		filename = 'flash-write-%08x.bin' % (download_addr)
		print("Dumping Flash write to disk: %s" % (filename))

		with open(filename, 'wb') as h:
			h.write(data)

	def upgrade(self, usb_msc=None, output=None):
		"""
		usb_msc: a USB mass storage controller in DFU mode
		output: an ADFUOutput class instance
		"""
		if self.no_write:
			write_to_flash = self.dump_flash_write_to_disk
		else:
			write_to_flash = usb_msc.adfu_write_to_flash

		# Create the firmware package.
		lfi = LFI(self)

		# Switch to software ADFU ASAP.
		output.set_download_status('adfus')
		output.set_progress_percent(10)
		self.upload_file_to_ram(usb_msc, 'adfus', align=512)
		usb_msc.adfu_switch_fw(self['adfus']['download_address'])

		# Wait for device to reinitialise using software ADFU
		usb_msc.sleep(0.5)

		# Do HWSC (hardware scan): send the program...
		output.set_download_status('hwsc')
		output.set_progress_percent(20)
		self.upload_file_to_ram(usb_msc, 'hwsc', align=512)

		# ... run HSWC
		usb_msc.adfu_execute(self['hwsc']['download_address'])

		# ... read the result
		hwscaninfo = HWScanInfo(usb_msc.adfu_read_result_block(HWScanInfo.LENGTH))

		print('got hwscaninfo', hwscaninfo)

		# Use flash ID from hwscaninfo to find flash type.
		nand_id_data = self.read_bytes(self['flash_id']['filename'])
		flash_id = hwscaninfo.get_bytes('flash_id', 0, 2)
		nand_info_block = get_nand_info_block(nand_id_data, flash_id)
		#print('nand info block', nand_info_block)

		# Write the flash info to RAM at the address indicated by HW scan.
		output.set_download_status('fwsc')
		output.set_progress_percent(30)
		print('write to nafbscparaddr')
		usb_msc.adfu_write_to_ram(hwscaninfo.get_item('nafbscparaddr'), nand_info_block)

		flash_type = get_flash_type(nand_info_block)

		# Read and update BREC. We're going to set a few parameters related to BREC
		# which will be used later.
		brec = BrecWithResources(self, flash_type)

		# Download FWSC (Firmware Scan. (?))
		fwsc_filename = self['fwsc']['filename_template'] % (flash_type)
		fwsc_bytes = self.read_bytes(fwsc_filename)

		fwinfo = FWInfoBlock(fwsc_bytes) # FW info written to first few bytes of fwsc
		fwinfo['bEraseFlag'] = self['erase_flash']
		fwinfo['dBRECCap'] = brec.sector_count
		fwinfo['dLFICap'] = len(lfi) // 512
		fwinfo['flash_size'] = 0 # Not supported yet
		fwinfo['spi_nor_decrypt_mode'] = 0 # also no

		# TODO: Figure out how this works -- we somehow get an extra 4 bytes at end.
		fwsc_bytes += b'\x00\x00\x00\x00'

		usb_msc.adfu_write_to_ram(self['fwsc']['download_address'], fwsc_bytes)

		# Start FWSC
		usb_msc.adfu_execute(self['fwsc']['entrypoint'])

		# TODO: wait?
		time.sleep(2)

		# Read back result
		scan_info = ADFU_FWScanInfo_t(usb_msc.adfu_read_result_block(ADFU_FWScanInfo_t.LENGTH))

		# TODO: calculations based on this result

		# Send MBREC
		output.set_download_status('mbrec')
		mbrec = load_mbrec(self)
		write_to_flash(self['mbrec']['download_address'], mbrec)

		# Create a firmware information header.
		# This is some serious Actions-specific voodoo. "Cap" seems to mean
		# "length, in 512-byte sectors", so this is a structure about lengths
		# of things on flash.
		capinfo = DFUCapInfo_t(None)

		# This is probably hidden disk (=operating system accessible portion of
		# Flash) length in sectors, since it works out to be about 12MB, which
		# is roughly the size of the firmware.
		capinfo['vm_disk_cap']  = round_up(scan_info['Vm_Cap'], scan_info['logic_block_cap'])

		# This is probably udisk (=user-accessible portion of Flash) length in
		# sectors, since it works out to be just short of 4 GB (3956 MB) on my
		# 4 GB player.
		capinfo['udisk_cap'] = scan_info['Logical_Cap'] - (scan_info['Lfi_Cap'] * 2) - capinfo['vm_disk_cap']

		print('vm disk', capinfo['vm_disk_cap'])
		print('lfi cap', scan_info['Lfi_Cap'])
		print('logical cap', scan_info['Logical_Cap'])
		print('udisk cap', capinfo['udisk_cap'])

		# Send BREC, in 64k chunks for some reason.
		brec.set_header_data(len(lfi) // 512, capinfo.get(), 0, 0, nand_info_block)
		brec_bytes = brec.get()
		output.set_download_status('brec')
		download_address = brec.download_address
		idx = 0
		while idx < len(brec_bytes):
			amt = min(65536, len(brec_bytes) - idx)
			# Download address, when it comes to flash writes, is probably
			# actually a combination of type of thing to flash (0x40 for mbrec,
			# 0x46 for brec) and sector offset of the data within that type.
			write_to_flash(download_address + (idx // 512), brec_bytes[idx : idx + amt])
			idx += amt

		# send LFI (firmware)
		output.set_download_status('lfi')
		lfi.set_cap(capinfo['vm_disk_cap'], capinfo['udisk_cap'])
		download_address = lfi.download_address
		lfi_bytes = lfi.get()
		idx = 0
		while idx < len(lfi_bytes):
			amt = min(2 * 1024 * 1024, len(lfi_bytes) - idx)
			write_to_flash(download_address + (idx // 512), lfi_bytes[idx : idx + amt])
			idx += amt

		# Send "ADFU debug buffer", aka 512 zero bytes.
		output.set_download_status('debug')
		debug_buf = bytearray(512)
		write_to_flash(0xff000000, debug_buf)

		# We're done! Reboot! Yay!
		output.set_download_status('reboot')
		usb_msc.adfu_reboot()


class TextOutput:
	def set_download_status(self, status):
		print('Download status: %s' % (status))

	def set_progress_percent(self, percent):
		print('%d%% done' % (percent))

def main():
	parser = argparse.ArgumentParser()
	parser.add_argument('-t', '--test', action='store_true', help='Verification / test run')
	parser.add_argument('--no-write', action='store_true', help="Don't write to flash; dump files to disk instead")
	parser.add_argument('dir', help='Directory containing upgrade')
	args = parser.parse_args()

	if args.test:
		msc = adfu.USBMSC(mock_device=adfu_mock_usb_device.MockUSBDevice('test_actions_adfu_upgrade/indfu%02d.bin', 56,
			skip_header=27, max_size=65535))
	else:
		msc = adfu.USBMSC(devices=adfu.ADFU_DEVICES, timeout_ms=10 * 1000)

	package = Package(CONFIG, args.dir, no_write=args.no_write)

	output = TextOutput()
	package.upgrade(msc, output)

if __name__ == '__main__':
	main()

