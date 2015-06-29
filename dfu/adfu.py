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

UDISK_DEVICES = {'Sandisk Clip Sport': (0x0781, 0x74E7)}
ADFU_DEVICES = {'Actions Semiconductor ADFU': (0x10d6, 0x10d6)}

import usb.core
import usb.util

EP_TO_DEVICE = 0x2
EP_FROM_DEVICE = 0x81

def _find_device(devices):
	for device_name, (idvendor, idproduct) in devices.items():
		dev = usb.core.find(idVendor=idvendor, idProduct=idproduct)
		if dev is not None:
			print("Found", device_name)
			break
	else:
		print("Can't find device")
		return None

	# Choose the first (and only) configuration.
	if dev.is_kernel_driver_active(0):
		print("claimed by kernel")
		dev.detach_kernel_driver(0)
		usb.util.claim_interface(dev, 0)

	#dev.set_configuration()

	return dev

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

def adfu_write_to_ram(length, start_address):
	return struct.pack('<IIIBBBBIIIBBB',
			0x43425355, # 'USBC'
			0x00000000, # tag
			length,
			0, # flags
			0, # LUN
			0x10, # CDB length
			0xcd,
			0x00000013, # command
			length,
			start_address,
			0, 0, 0)

def adfu_prepare_exec(start_address):
	return struct.pack('<IIIBBBBIIIBBB',
			0x43425355, # 'USBC'
			0x00000000, # tag
			0, # length
			0, # flags
			0, # LUN
			0x10, # CDB length
			0xcd,
			0x00000020, # command
			0, # unused
			start_address,
			0, 0, 0)

def adfu_execute(start_address):
	return struct.pack('<IIIBBBBIIIBBB',
			0x43425355, # 'USBC'
			0x00000000, # tag
			0, # length
			0, # flags
			0, # LUN
			0x10, # CDB length
			0xcd,
			0x00000021, # command
			0, # unused
			start_address,
			0, 0, 0)

def adfu_read_result_block(size):
	return struct.pack('<IIIBBBBIIIBBB',
			0x43425355, # 'USBC'
			0x00000000, # tag
			size, # length
			0x80, # flags
			0, # LUN
			0x10, # CDB length
			0xcd,
			0x00000023, # command
			size,
			0, # unused
			0, 0, 0)

def run_code(filename):
	# Prepare to read data
	with open('ADFUS.BIN', 'rb') as h:
		adfus = h.read()

	with open(filename, 'rb') as h:
		data = h.read()

	dev = _find_device(ADFU_DEVICES)

	dev.write(EP_TO_DEVICE, adfu_write_to_ram(len(adfus), 0xbfc18000))
	dev.write(EP_TO_DEVICE, adfus)
	print(dev.read(EP_FROM_DEVICE, 512))

	dev.write(EP_TO_DEVICE, adfu_prepare_exec(0xbfc18000))
	print(dev.read(EP_FROM_DEVICE, 512))

	print("start exec")
	assert len(data) < (27 * 1024), "Code too large to fit in RAM"

	dev.write(EP_TO_DEVICE, adfu_write_to_ram(len(data), 0xbfc1e000))
	dev.write(EP_TO_DEVICE, data)

	print(dev.read(EP_FROM_DEVICE, 512))

	print("do exec")
	dev.write(EP_TO_DEVICE, adfu_execute(0xbfc1e000))
	time.sleep(0.1)
	print(dev.read(EP_FROM_DEVICE, 512))

	print("read back")
	dev.write(EP_TO_DEVICE, adfu_read_result_block(156))
	print(dev.read(EP_FROM_DEVICE, 512))
	print(dev.read(EP_FROM_DEVICE, 512))

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


