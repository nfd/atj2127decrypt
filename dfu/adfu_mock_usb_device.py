import os
import sys
import difflib

def hexdump(b):
	for line in [b[n:n+16] for n in range(0, len(b), 16)]:
		charpart = ''.join(chr(x) if (x >= 0x20 and x <= 0x7e) else '.' for x in line)
		hexpart = ' '.join('%02x' % (x) for x in line)
		yield('%-48s %s' % (hexpart, charpart))

def hexcompare(expected, actual):
	hexpected = list(hexdump(expected))
	hactual   = list(hexdump(actual))

	# so lazy
	for line in difflib.unified_diff(hexpected, hactual, fromfile='expected', tofile='but got'):
		print(line)

class MockUSBDevice:
	def __init__(self, packet_template, num_packets, skip_header=0, max_size=None):
		self.packet_template = packet_template
		self.next_packet = 1
		self.num_packets = num_packets
		self.skip_header = skip_header
		self.max_size    = max_size # prior to skip_header

	@property
	def finished(self):
		return self.next_packet == self.num_packets + 1

	def log(self, txt):
		print(txt)

	def trim(self, data):
		if self.max_size is None:
			return data
		else:
			return data[:self.max_size - self.skip_header]

	def get_next_packet(self):
		assert not self.finished

		pathname = self.packet_template % (self.next_packet)
		self.next_packet += 1

		with open(pathname, 'rb') as h:
			return h.read()[self.skip_header:]

	def write(self, endpoint, data):
		self.log('Write, %d, %d bytes' % (endpoint, len(data)))

		expected = self.get_next_packet()

		data = self.trim(data)

		if expected == data:
			self.log('  packet %d OK' % (self.next_packet - 1))
		else:
			may_be_trimmed = self.max_size is not None and len(expected) == self.max_size - self.skip_header
			self.log('  packet %d mismatch (%s %d bytes)' % (self.next_packet - 1,
				'possibly-trimmed,' if may_be_trimmed else 'expected', len(expected)))
			hexcompare(expected, data)
			raise Exception()
	
	def read(self, endpoint, max_size):
		expected = self.get_next_packet()

		self.log('Read packet %x, max %d, actual %d' % (endpoint, max_size, len(expected)))

		if len(expected) > max_size:
			raise Exception()

		self.log('  packet %d OK' % (self.next_packet - 1))

		return expected


