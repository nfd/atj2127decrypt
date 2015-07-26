"""
Switch from mass storage mode to DFU mode

To access this without sudo on Linux:

create a new group, "usb", and add yourself to it:

	addgroup usb
	adduser <your username> usb

Log out and log in to pick up the new group (or use newgrp)

Copy 37-clipsport.rules to /etc/udev/rules.d/

Reload the rules:

	udevadm control --reload-rules
"""
import time
import argparse
import struct
from collections import namedtuple

USBDevice = namedtuple('USBDevice', ('name', 'idVendor', 'idProduct'))

UDISK_DEVICES = {USBDevice('Sandisk Clip Sport', 0x0781, 0x74E7), USBDevice('Actions HS USB Flashdisk', 0x10d6, 0x1101)}
ADFU_DEVICES = {USBDevice('Actions Semiconductor ADFU', 0x10d6, 0x10d6)}

import usb.core
import usb.util

EP_TO_DEVICE = 0x2
EP_FROM_DEVICE = 0x81

class DeviceNotFound(Exception):
	pass

def _find_device(devices):
	for usbdevice in devices:
		print(usbdevice)
		dev = usb.core.find(idVendor=usbdevice.idVendor, idProduct=usbdevice.idProduct)
		if dev is not None:
			print("Found", usbdevice.name)
			break
	else:
		raise DeviceNotFound()

	# Choose the first (and only) configuration.
	if dev.is_kernel_driver_active(0):
		print("claimed by kernel")
		dev.detach_kernel_driver(0)
		usb.util.claim_interface(dev, 0)

	#dev.set_configuration()

	return dev

class USBMSC:
	"""
	Mass Storage Controller driver
	"""
	def __init__(self, devices=None, mock_device=None):
		if mock_device:
			self.dev = mock_device
			self.mock = True
		else:
			self.dev = _find_device(devices) # may raise DeviceNotFound
			self.mock = False
	
	def sleep(self, secs):
		if not self.mock:
			time.sleep(secs)
	
	def check_status(self, status):
		signature, tag, dataResidue, status = struct.unpack('<IIIB', status)
		assert signature == 0x53425355, signature # USBS
		assert status == 0
		return status

	def make_msc_cmd(self, size, lun, cdb, flags=0):
		return struct.pack('<IIIBBB',
				0x43425355, # 'USBC'
				0x00000000, # tag
				size, # length
				flags,
				lun, # LUN
				len(cdb)) + cdb

	def make_adfu_cmd(self, msc_size, cmd, length, start_address, flags=0):
		cdb = struct.pack('<BIIIBBB',
				0xcd,
				cmd,
				length,
				start_address,
				0, 0, 0)

		return self.make_msc_cmd(msc_size, 0, cdb, flags=flags)

	def adfu_write_to_flash(self, addr, binary):
		self.dev.write(EP_TO_DEVICE, self.make_adfu_cmd(len(binary), 0x10, len(binary) // 512, addr))
		self.dev.write(EP_TO_DEVICE, binary)
		status = self.dev.read(EP_FROM_DEVICE, 512)
		return self.check_status(status)

	def adfu_write_to_ram(self, addr, binary):
		self.dev.write(EP_TO_DEVICE, self.make_adfu_cmd(len(binary), 0x13, len(binary), addr))
		self.dev.write(EP_TO_DEVICE, binary)
		status = self.dev.read(EP_FROM_DEVICE, 512)
		return self.check_status(status)

	def adfu_switch_fw(self, addr):
		self.dev.write(EP_TO_DEVICE, self.make_adfu_cmd(0, 0x20, 0, addr))
		status = self.dev.read(EP_FROM_DEVICE, 512)
		return self.check_status(status)

	def adfu_read_result_block(self, size):
		self.dev.write(EP_TO_DEVICE, self.make_adfu_cmd(size, 0x23, size, 0, flags=0x80))
		result = self.dev.read(EP_FROM_DEVICE, size)
		status = self.dev.read(EP_FROM_DEVICE, 512)
		self.check_status(status)
		return result

	def adfu_execute(self, addr):
		self.dev.write(EP_TO_DEVICE, self.make_adfu_cmd(0, 0x21, 0, addr))
		time.sleep(0.1) # TODO
		status = self.dev.read(EP_FROM_DEVICE, 512)
		return self.check_status(status)

	def adfu_reboot(self):
		cdb = struct.pack('<BIIIBBB', 0xb0, 0, 0, 0, 0, 0, 0)
		self.dev.write(EP_TO_DEVICE, self.make_msc_cmd(0, 0, cdb, flags=0))
		status = self.dev.read(EP_FROM_DEVICE, 512)
		return self.check_status(status)

def _cmd_unknown_0():
	# Vendor-specific command 0xCC.
	return bytes([0x55, 0x53, 0x42, 0x43, # USBC
		0xa8, 0x7a, 0xa0, 0xa5, # tag
		0x0b, 0x00, 0x00, 0x00, # data transfer length
		0x80, # flags
		0x00, # LUN 0
		0x10, # CDB length
		0xcc, 0x00, 0x00, 0x00,   # data
		0x00, 0x00, 0x00, 0x0b,   # data
		0x00, 0x00, 0x00, 0x00,   # data
		0x00, 0x00, 0x00, 0x00   # data
		])

def _cmd_unknown_1():
	# Vendor-specific command 0xCB.
	return bytes([0x55, 0x53, 0x42, 0x43, # USBC
		0x38, 0x52, 0xf1, 0x86, # tag
		0x02, 0x00, 0x00, 0x00, # data transfer length
		0x80, # flags
		0x00, # LUN 0
		0x10, # CDB length
		0xcb, 0x21, 0x00, 0x00,   # data
		0x00, 0x00, 0x00, 0x02,   # data
		0x00, 0x00, 0x00, 0x00,   # data
		0x00, 0x00, 0x00, 0x00   # data
		])

def switch_to_dfu():
	dev = _find_device(UDISK_DEVICES)
	if dev is None:
		return

	dev.write(EP_TO_DEVICE, _cmd_unknown_0())

	# First reply is the text ACTIONSUSBD
	ret = dev.read(EP_FROM_DEVICE, 512)
	print(ret)

	# Second reply is USB mass storage control reply.
	ret = dev.read(EP_FROM_DEVICE, 512)
	print(ret)

	time.sleep(3) # TODO -- could just use check sense

	dev.write(EP_TO_DEVICE, _cmd_unknown_1())

	# First reply is 0xff, 0x00, indicating we're about to enter ADFU mode
	ret = dev.read(EP_FROM_DEVICE, 512)
	print(ret)

	# Second reply is USB mass storage control reply.
	ret = dev.read(EP_FROM_DEVICE, 512)
	print(ret)

def adfu_reboot():
	return bytes([0x55, 0x53, 0x42, 0x43, # USBC
		0x00, 0x00, 0x00, 0x00, # tag
		0x00, 0x00, 0x00, 0x00, # length
		0x00, # flags
		0x00, # LUN 0
		0x10, # CDB length
		0xb0, 0x00, 0x00, 0x00, # data
		0x00, 0x00, 0x00, 0x00, # data
		0x00, 0x00, 0x00, 0x00, # data
		0x00, 0x00, 0x00, 0x00, # data
		0x00, 0x00, 0x00, 0x00  # data
		])

def switch_to_udisk():
	dev = _find_device(ADFU_DEVICES)

	dev.write(EP_TO_DEVICE, adfu_reboot())
	ret = dev.read(EP_FROM_DEVICE, 512)
	print(ret)

def run_code(filename):
	# Prepare to read data
	with open('ADFUS.BIN', 'rb') as h:
		adfus = h.read()

	with open(filename, 'rb') as h:
		data = h.read()

	assert len(data) < (27 * 1024), "Code too large to fit in RAM"

	dev = USBMSC(devices=ADFU_DEVICES)

	# Switch to software ADFU
	dev.adfu_write_to_ram(0xbfc18000, adfus)
	dev.adfu_switch_fw(0xbfc18000)

	# Write the program
	dev.adfu_write_to_ram(0xbfc1e000, data)

	# Run it
	print("do exec")
	dev.adfu_execute(0xbfc1e000)

	print("read back")
	print(dev.adfu_read_result_block(156))

if __name__ == '__main__':
	parser = argparse.ArgumentParser()
	parser.add_argument('command', choices=('adfu', 'udisk', 'run_code'))
	parser.add_argument('args', nargs='*')
	args = parser.parse_args()

	if args.command == 'adfu':
		switch_to_dfu(*args.args)
	elif args.command == 'udisk':
		switch_to_udisk(*args.args)
	elif args.command == 'run_code':
		run_code(*args.args)
	else:
		raise NotImplementedError()


