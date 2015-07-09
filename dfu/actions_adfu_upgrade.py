"""
The Actions ADFU upgrade script, translated from Actions scripting language
"""
import time
import struct
import argparse

import adfu

# Create a labelled struct
class TaggedStruct:
	def __init__(self, name, *args):
		self.name = name

		structbits = ['<']
		parts = {} # maps name to (index, length)
		index = 0
		for name, typ, count in args:
			structbits.append(typ * count)
			parts[name] = index
			index += 1

		self.structbits = ''.join(structbits)
		self.parts = parts

		self.length = struct.calcsize(self.structbits)

	def __len__(self):
		return self.length

	def get(self, unpacked, name, index=0):
		return unpacked[self.parts[name] + index]

# Types of command
ADFU_COMMAND_RAM = 19 # Write data to RAM
ADFU_COMMAND_STORAGE = 16 # NAND-related commands
ADFU_COMMAND_SWIT = 32 # Switch from HW ADFU to SW ADFU, unclear how this differs from CALL_ENTRY
ADFU_COMMAND_CALL_ENTRY = 33 # Run code on device
ADFU_COMMAND_GET_STATUS = 35 # Read a block of memory from a predefined location

# Parameters for this particular ADFU
CONFIG = {
	'adfus': {
		# Software ADFU, called ADFUS in original script
		'filename': 'ADFUS.BIN',
		'download_address': 0xbfc18000,
	},
	'hwsc': {
		# HWSC, which returns NAND parameter info
		'filename': 'nandhwsc.bin',
		'download_address': 0xbfc1e000,
	}
}

# What we get back from nandhwsc.bin
HWScanInfo = TaggedStruct('HWScanInfo', 
	('Frametype', 'B', 2),
	('HwscFlag', 'B', 14),
	('flash_id', 'I', 2),
	('NafBscParAddr', 'I', 1),
	('reserved', 'B', 128))

def _read_file(pathname):
	with open(pathname, 'rb') as h:
		return h.read()

def upload_file_to_ram(usb_msc, config_key):
	section = CONFIG[config_key]
	file_bytes = _read_file(section['filename'])

	usb_msc.send_command(subcode=ADFU_COMMAND_RAM,
			transfer_length=len(file_bytes),
			param3=section['download_address'])

	usb_msc.send_raw(file_bytes)

def AdfuUpgrade(usb_msc=None, output=None):
	"""
	usb_msc: a USB mass storage controller in DFU mode
	output: an ADFUOutput class instance
	"""
	# Switch to software ADFU ASAP.
	output.set_download_status('adfus')
	output.set_progress_percent(10)
	upload_file_to_ram(usb_msc, 'adfus')
	usb_msc_send_command(subcode=ADFU_COMMAND_SWIT,
			param3=CONFIG['adfus_download_address'])


	# Wait for device to reinitialise using software ADFU
	time.sleep(1)

	# Do HWSC (hardware scan): send the program...
	output.set_download_status('hwsc')
	output.set_progress_percent(20)
	upload_file_to_ram(usb_msc, 'hwsc')

	# ... run HSWC
	usb_msc.send_command(subcode=ADFU_COMMAND_CALL_ENTRY,
			param3=CONFIG['hwsc']['download_address'])

	# ... read the result
	usb_msc.send_command(subcode=ADFU_COMMAND_GET_STATUS,
			param3=len(HWScanInfo))
	hwscaninfo_bytes = usb_msc.recv_raw(len(HWScanInfo))

	print('got hwscaninfo', hwscaninfo)

