#!/usr/bin/env python3

import sys
import argparse
import threading
import ntpath
import re
import queue
import socket
import struct
import time

import socks

from rw import *

lock = threading.Lock()

def Run( in_path, out_path, max_threads ):
	pattern = re.compile( r"""^\s*(\d+)\.(\d+)\.(\d+)\.(\d+)\s*(?:-\s*(\d+)(?:\.(\d+))?\s*)?$""", re.VERBOSE )

	with open( in_path, 'r' ) as in_file:
		in_path = ntpath.basename( in_path )

		i = 0

		q = queue.Queue()

		for line in in_file:
			i = i + 1

			line = line.strip()
			if len( line ) == 0:
				continue

			m = pattern.match( line )
			if m == None:
				sys.exit( "ERR: %s(%u): syntax error" % (in_path, i) )

			a = int( m[1] )
			b = int( m[2] )
			c1 = int( m[3] )
			d1 = int( m[4] )

			c2 = None if m[5] == None else int( m[5] )
			d2 = None if m[6] == None else int( m[6] )

			if c2 == None:
				c2 = c1
				d2 = d1
			elif d2 == None:
				d2 = c2
				c2 = c1

			if (a < 0 or a > 255) or (b < 0 or b > 255) or (c1 < 0 or c1 > 255) or (c2 < 0 or c2 > 255) or (d1 < 0 or d1 > 255) or (d2 < 0 or d2 > 255):
				sys.exit( "ERR: %s(%u): invalid IP address" % (in_path, i) )
			
			ip = a << 24
			ip += b << 16

			ip1 = ip
			ip1 += c1 << 8
			ip1 += d1

			ip2 = ip
			ip2 += c2 << 8
			ip2 += d2

			if ip1 > ip2:
				sys.exit( "ERR: %s(%u): invalid IP range" % (in_path, i) )

			for ip in range( ip1, ip2 + 1 ):
				q.put( socket.ntohl( ip ) )

	total = q.qsize()
	checked = 0
	valid = 0

	def ThreadFunc( tid, q, out_file ):
		nonlocal total, checked, valid

		while True:
			try:
				ip = q.get_nowait()
				left = q.qsize()
			except queue.Empty:
				break

			ip_str = socket.inet_ntoa( struct.pack( '<I', ip ) )

			s = IsTargetVulnerable( ip_str, 445 )

			if s == None:
				continue

			with lock:
				checked += 1

				if s:
					valid += 1

					print( "[+] %s is vulnerable (%u/%u checked, %u left)" % (ip_str, valid, total, left) )

					out_file.write( ip_str + '\n' )
					out_file.flush()
			
	if max_threads > total:
		max_threads = total

	with open( out_path, 'w' ) as out_file:
		tlist = []

		while len( tlist ) < max_threads:
			try:
				t = threading.Thread( target = ThreadFunc, args = [len( tlist ), q, out_file] )
				t.start()
			except Exception as e:
				print( "failed to start %s thread #%u" % ("domain resolver", i) )
				break

			tlist.append( t )

		if len( tlist ) == 0:
			raise Exception( "can't create threads!" );

		for t in tlist:
			t.join()

		if checked == 0:
			sys.exit( "ERR: no machines in the network detected (check your connection)" )

		print( "finished - %u machines in the network, %u vulnerable" % (checked, valid) )

if __name__ == "__main__":
	parser = argparse.ArgumentParser()
	parser.add_argument( "-in", help = "input file", required = False, default = "scanner_input.txt" )
	parser.add_argument( "-out", help = "output file", required = False, default = "scanner_output.txt" )
	parser.add_argument( "-threads", help = "maximum number of threads to use", type = int, required = False, default = 800 )
	parser.add_argument( "-timeout", help = "connect/read timeout in seconds (default is 7)", type = int, required = False, default = 7 )
	parser.add_argument( "-proxy", help = "SOCKS5 proxy to use", required = False, default = "" )

	args = parser.parse_args()

	proxy = args.proxy
	if proxy != '':
		proxy_parts = proxy.split( ':' )

		if len( proxy_parts ) != 2:
			sys.exit( "invalid proxy string: '%s'" % proxy )

		host = proxy_parts[0]
		port = int( proxy_parts[1] )

#		socks.set_default_proxy( socks.PROXY_TYPE_SOCKS5, host, port )

		vars.proxy_host = host
		vars.proxy_port = port

		print( "# using proxy %s:%u" % (host, port) )

	vars.socket_timeout = args.timeout

	Run( getattr( args, 'in' ), getattr( args, 'out' ), args.threads )
