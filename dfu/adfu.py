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

DEVICES = {'Sandisk Clip Sport': (0x0781, 0x74E7)}

import usb.core
import usb.util

EP_TO_DEVICE = 0x2
EP_FROM_DEVICE = 0x81

def _find_device():
	for device_name, (idvendor, idproduct) in DEVICES.items():
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
	dev = _find_device()
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

if __name__ == '__main__':
	switch_to_dfu()

