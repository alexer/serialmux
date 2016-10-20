#! /usr/bin/env python
from distutils.core import setup

setup(
	name = 'serialmux',
	version = '0.0.1',
	description = 'Serial port multiplexer',
	author = 'Aleksi Torhamo',
	author_email = 'aleksi@torhamo.net',
	url = 'http://github.com/alexer/serialmux',
	py_modules = ['serialmux'],
	entry_points = {
		'console_scripts': [
			'serialmux = serialmux:main'
		],
	},
)
