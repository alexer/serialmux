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
import inspect

# How does the poll() operation work in CUSE?
# - TBH, I have no idea.
# - I'm assuming you're supposed to...
#   - Return the current readable/writable status in the reply
#   - Notify if it becomes readable/writable later

def debug(*args, **kwargs):
	t = time.time()
	ts = '[%04d-%02d-%02d %02d:%02d:%02d.%06d]:' % (time.localtime(t)[:6] + ((t % 1) * 1e6, ))
	print(ts, *args, **kwargs)

class PollThread(threading.Thread):
	def __init__(self, fd):
		threading.Thread.__init__(self)
		self.fd = fd
		self.r, self.w = os.pipe()
		self.p = select.poll()
		self.p.register(self.fd)
		self.p.register(self.r)
		self.daemon = True
		self.lock = threading.Lock()
		self.ph = queue.Queue(1)
		self.evs = queue.Queue(1)

	def run(self):
		while True:
			os.read(self.r, 1)
			ph = self.ph.get()

			# Get current events
			self.p.modify(self.r, 0)
			self.p.modify(self.fd, 5)
			evs = dict(self.p.poll(0)).get(self.fd, 0)
			self.evs.put(evs)

			# Get further events
			mask = 5 & ~evs
			self.p.modify(self.r, select.POLLIN)
			self.p.modify(self.fd, mask)
			evs = self.p.poll()
			for fd, event in evs:
				if fd == self.fd:
					debug('polled', event)
					libcuse.fuse_lowlevel_notify_poll(ph)
			libcuse.fuse_pollhandle_destroy(ph)

	def poll(self, ph):
		with self.lock:
			os.write(self.w, b'\x00')
			self.ph.put(ph)
			mask = self.evs.get()
		return mask

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
	if ph:
		phcid = '0x%08x' % id(ph.contents)
		phcaddr = '0x%08x' % addressof(ph.contents)
	else:
		phcid = phcaddr = '<--null-->'
	return '<0x%08x@0x%08x:%s@%s>' % (id(ph), addressof(ph), phcid, phcaddr)

_handle = 0
def get_new_handle():
	"""Get a new file handle / client id"""
	global _handle
	_handle += 1
	return _handle

def get_caller_info(level=2):
	frame = inspect.stack()[level][0]
	code = frame.f_code
	funcname = code.co_name
	names = code.co_varnames[:code.co_argcount]
	values = frame.f_locals
	items = []
	for name in names:
		if name in 'self req file_info'.split():
			continue
		value = values[name]
		if name == 'cmd':
			value = '%s(0x%08X)' % (ioctl_dict[value], value)
		elif name == 'ph':
			value = phinfo(value)
		else:
			value = repr(value)
		items.append((name, value))
	fh = values['file_info'].contents.fh
	return '%d %s(%s)' % (fh, funcname, ', '.join('%s=%s' % item for item in items))

class Device():
	def __init__(self, devpath='/dev/ttyS0', muxdevname=None):
		self.devpath = devpath
		self.muxdevname = muxdevname or os.path.basename(devpath) + 'mux'
		self.fd = os.open(devpath, os.O_RDWR)
		self.pt = PollThread(self.fd)
		self.pt.start()
		self.active = []
		self.states = {}
		self.block = threading.Condition()

	def pray(self, file_info):
		info = get_caller_info()
		debug('wait', info)
		#self.block.wait_for(lambda: self.active[-1] == file_info.contents.fh)
		with self.block:
			while self.active[-1] != file_info.contents.fh:
				self.block.wait()
		debug('exec', info)

	def init_done(self, unk):
		path = '/dev/' + self.muxdevname
		# udev or something resets this if done too soon
		time.sleep(1)
		os.chmod(path, 0666)

	def open(self, req, file_info):
		file_info.contents.fh = get_new_handle()
		info = get_caller_info(level=1)
		debug('exec', info)
		self.active.append(file_info.contents.fh)
		if len(self.active) > 1:
			last = self.active[-2]
			file_flags = fcntl.fcntl(self.fd, fcntl.F_GETFL)
			tty_flags = fcntl.ioctl(self.fd, termios.TCGETS, b'\x00' * sizeof(termios_t))
			self.states[last] = (file_flags, tty_flags)
		fcntl.fcntl(self.fd, fcntl.F_SETFL, file_info.contents.flags)
		libcuse.fuse_reply_open(req, file_info)

	def release(self, req, file_info):
		self.pray(file_info)
		if len(self.active) > 1:
			last = self.active[-2]
			file_flags, tty_flags = self.states.pop(last)
			fcntl.fcntl(self.fd, fcntl.F_SETFL, file_flags)
			fcntl.ioctl(self.fd, termios.TCSETS, tty_flags)
		libcuse.fuse_reply_err(req, 0)
		self.active.remove(file_info.contents.fh)
		with self.block:
			self.block.notify_all()

	def poll(self, req, file_info, ph):
		self.pray(file_info)
		event = self.pt.poll(ph)
		debug('-> current:', event)
		libcuse.fuse_reply_poll(req, event)

	def write(self, req, buf, length, offset, file_info):
		self.pray(file_info)
		assert offset == 0
		os.write(self.fd, buf[:length])
		libcuse.fuse_reply_write(req, length)

	def read(self, req, size, off, file_info):
		self.pray(file_info)
		assert off == 0
		try:
			out = os.read(self.fd, size)
		except OSError, e:
			debug('-> error:', e)
			libcuse.fuse_reply_err(req, e.errno)
			return
		else:
			debug('-> data:', repr(out))
		libcuse.fuse_reply_buf(req, out, len(out))

	def ioctl(self, req, cmd, arg_p, file_info, uflags, in_buff_p, in_bufsz, out_bufsz):
		self.pray(file_info)
		args = (req, cmd, arg_p, file_info, uflags, in_buff_p, in_bufsz, out_bufsz)
		if cmd in (termios.TCGETS, termios.TCSETS):
			self.simple_ioctl(args, termios_t)
		elif cmd in (termios.TIOCMGET, termios.TIOCMSET):
			self.simple_ioctl(args, c_uint)
		elif cmd == termios.TCFLSH:
			fcntl.ioctl(self.fd, cmd, arg_p or 0)
			libcuse.fuse_reply_ioctl(req, 0, None, 0)
		else:
			debug("-> unknown")
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

if __name__ == '__main__':
		# Usage: serialmux.py [<devpath> [<muxdevname>]]

		devpath = sys.argv[1] if len(sys.argv) > 1 else None
		muxdevname = sys.argv[2] if len(sys.argv) > 2 else None
		operations = Device(devpath, muxdevname)

		cuse.init(operations, operations.muxdevname, sys.argv[3:])
		try:
			cuse.main(False)
		except Exception, err:
			print("CUSE main ended %s" % str(err))

