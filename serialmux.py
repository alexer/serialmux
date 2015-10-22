#!/usr/bin/env python
from __future__ import division, print_function, absolute_import

import cuse, errno, stat, sys
from cuse import cuse_api as libcuse
from cuse.interface import ioctl_dict

import termios
from ctypes import *
import os, fcntl
import time
import threading, Queue as queue
import select

class PollThread(threading.Thread):
	def __init__(self, fd):
		threading.Thread.__init__(self)
		self.fd = fd
		self.r, self.w = os.pipe()
		self.queue = queue.Queue()
		self.p = select.poll()
		self.p.register(self.fd)
		self.p.register(self.r, select.POLLIN)
		self.event = queue.Queue(1)
		self.event.put(0)
		self.up = 0
		self.daemon = True

	def run(self):
		while True:
			ph = self.queue.get()
			mask = 5 & ~self.up
			print('polling', mask)
			self.p.modify(self.fd, mask)
			evs = self.p.poll()
			for fd, event in evs:
				if fd == self.fd:
					self.up = event
					print('polled', event)
					self.swap_event(event)
					libcuse.fuse_lowlevel_notify_poll(ph)
					libcuse.fuse_pollhandle_destroy(ph)
				else:
					os.read(self.r, 256)
					self.up = 0

	def add_ph(self, ph):
		try:
			while True:
				tmp = self.queue.get_nowait()
				libcuse.fuse_pollhandle_destroy(tmp)
		except queue.Empty:
			pass
		self.queue.put(ph)

	def swap_event(self, new):
		old = self.event.get()
		self.event.put(new)
		return old

	def refresh(self):
		os.write(self.w, b'\x00')

class termios_t(Structure):
	_fields_ = [
		('c_iflag', c_uint),
		('c_oflag', c_uint),
		('c_cflag', c_uint),
		('c_lflag', c_uint),
		('c_line', c_ubyte),
		('c_cc', c_ubyte * 32),
		('c_ispeed', c_uint),
		('c_ospeed', c_uint),
	]

def iovec_from_struct(addr, struct):
	return libcuse.iovec(cast(addr, c_void_p), sizeof(struct))

def phinfo(ph):
	return (ph, ph.contents, addressof(ph), addressof(ph.contents))

class Device():
	'''A very simple example filesystem'''
	flag = False
	input_buffer=""
	def __init__(self, devname):
		self.devname = devname
		self.fd = os.open('/dev/ttyS0', os.O_RDWR)
		self.pt = PollThread(self.fd)
		self.pt.start()

	def init_done(self, unk):
		print('init_done')
		path = '/dev/' + devname
		# udev or something resets this if done too soon
		time.sleep(1)
		os.chmod(path, 0666)

	def open(self, req, file_info):
		print ("open %s %s" %(req, file_info))
		for name in dir(file_info.contents):
			if not name.startswith('_'):
				print(name, getattr(file_info.contents, name))
		fcntl.fcntl(self.fd, fcntl.F_SETFL, file_info.contents.flags)
		libcuse.fuse_reply_open(req, file_info)
		self.flag = False

	def poll(self, req, file_info, ph):
		#print('poll', file_info, phinfo(ph))
		event = self.pt.swap_event(self.pt.up)
		libcuse.fuse_reply_poll(req, event)
		self.pt.add_ph(ph)

	def write(self, req, buf, length, offset, file_info):
		print ("write %s %s %s %s" %(req, buf, length, offset))
		self.input_buffer+=buf[offset:length]
		print (self.input_buffer)
		libcuse.fuse_reply_write(req, length)
		self.pt.refresh()

	def read(self, req, size, off, file_info):
		assert off == 0
		try:
			out = os.read(self.fd, size)
		except OSError, e:
			print("read error:", e)
			libcuse.fuse_reply_err(req, e.errno)
			return
		#out = self.input_buffer[off:size]
		print ("read size: %s off: %s reply: %s buffer: %s" % (size, off, len(out), len(self.input_buffer)))
		libcuse.fuse_reply_buf(req, self.input_buffer[off:size], len(out))
		self.input_buffer=self.input_buffer[off+size+1:]
		self.pt.refresh()

	def ioctl(self, req, cmd, arg_p, file_info, uflags, in_buff_p, in_bufsz, out_bufsz):
		print ("ioctl %s(0x%08X) %r" % (ioctl_dict[cmd], cmd, (arg_p, file_info, uflags, in_buff_p, in_bufsz, out_bufsz)))
		args = (req, cmd, arg_p, file_info, uflags, in_buff_p, in_bufsz, out_bufsz)
		if cmd in (termios.TCGETS, termios.TCSETS):
			self.simple_ioctl(args, termios_t)
		elif cmd in (termios.TIOCMGET, termios.TIOCMSET):
			self.simple_ioctl(args, c_uint)
		else:
			libcuse.fuse_reply_ioctl(req, 0, None, 0)

	def simple_ioctl(self, args, c_type):
		req, cmd, arg_p, file_info, uflags, in_buff_p, in_bufsz, out_bufsz = args
		if not in_buff_p:
			type_iovec = iovec_from_struct(arg_p, c_type)
			libcuse.fuse_reply_ioctl_retry(req, pointer(type_iovec), 1, pointer(type_iovec), 1)
		else:
			type_ptr = cast(in_buff_p, POINTER(c_type))
			fcntl.ioctl(self.fd, cmd, type_ptr.contents)
			libcuse.fuse_reply_ioctl(req, 0, type_ptr, out_bufsz)

"""
ioctl TCFLSH(0x0000540B) (2, <cuse.cuse_api.LP_fuse_file_info object at 0x7f78cd346b90>, 2L, None, 0L, 0L)
read size: 127 off: 0 reply: 0 buffer: 0
"""

if __name__ == '__main__':
		if len(sys.argv) < 2:
				raise SystemExit('Usage: %s <devname>' % sys.argv[0])

		devname = sys.argv[1]
		operations = Device(devname)

		cuse.init(operations, devname, sys.argv[2:])
		try:
				cuse.main(False)
		except Exception, err:
				print ("CUSE main ended %s" % str(err))
