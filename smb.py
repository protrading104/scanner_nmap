#!/usr/bin/env python

import struct
import socket
import socks

from cfg import *
from smb_ntlm import *

import vars

SMB2_PACKET_HEADER_SIZE								= 0x40
SMB2_SESSION_SETUP_PACKET_HEADER_SIZE				= SMB2_PACKET_HEADER_SIZE + 0x18

SMB2_COMPRESSION_HEADER_SIZE						= 0x10

SMB2_NEGOTIATE_COMPRESSED_REQUEST_SIZE				= 0x90
SMB2_NEGOTIATE_COMPRESSED_RESPONSE_SIZE				= 0x206

SMB2_NEGOTIATE_UNCOMPRESSED_REQUEST_SIZE			= 0x78

SMB2_NEGOTIATE_SALT_SIZE							= 0x1100 - SMB2_NEGOTIATE_COMPRESSED_REQUEST_SIZE + 4

SMB2_CMD_NEGOTIATE									= 0x0000
SMB2_CMD_SESSION_SETUP								= 0x0001
SMB2_CMD_LOGOFF										= 0x0002
SMB2_CMD_TREE_CONNECT								= 0x0003
SMB2_CMD_TREE_DISCONNECT							= 0x0004
SMB2_CMD_CREATE										= 0x0005
SMB2_CMD_CLOSE										= 0x0006
SMB2_CMD_FLUSH										= 0x0007
SMB2_CMD_READ										= 0x0008
SMB2_CMD_WRITE										= 0x0009
SMB2_CMD_LOCK										= 0x000A
SMB2_CMD_IOCTL										= 0x000B
SMB2_CMD_CANCEL										= 0x000C
SMB2_CMD_ECHO										= 0x000D
SMB2_CMD_QUERY_DIRECTORY							= 0x000E
SMB2_CMD_CHANGE_NOTIFY								= 0x000F
SMB2_CMD_QUERY_INFO									= 0x0010
SMB2_CMD_SET_INFO									= 0x0011

SMB2_NEGOTIATE_SIGNING_ENABLED						= 0x0001
SMB2_NEGOTIATE_SIGNING_REQUIRED						= 0x0002

SMB2_GLOBAL_CAP_DFS									= 0x00000001
SMB2_GLOBAL_CAP_LEASING								= 0x00000002
SMB2_GLOBAL_CAP_LARGE_MTU							= 0x00000004
SMB2_GLOBAL_CAP_MULTI_CHANNEL						= 0x00000008
SMB2_GLOBAL_CAP_PERSISTENT_HANDLES					= 0x00000010
SMB2_GLOBAL_CAP_DIRECTORY_LEASING					= 0x00000020
SMB2_GLOBAL_CAP_ENCRYPTION							= 0x00000040

SMB2_NEGCTX_PREAUTH_INTEGRITY_CAPABILITIES			= 0x0001
SMB2_NEGCTX_ENCRYPTION_CAPABILITIES					= 0x0002
SMB2_NEGCTX_COMPRESSION_CAPABILITIES				= 0x0003
SMB2_NEGCTX_NETNAME_NEGOTIATE_CONTEXT_ID			= 0x0005

SMB2_HASH_ALG_SHA_512 								= 0x0001

SMB2_COMPRESSION_CAPABILITIES_FLAG_CHAINED			= 0x00000001

SMB2_COMPRESSION_ALG_NONE							= 0x0000
SMB2_COMPRESSION_ALG_LZNT1							= 0x0001
SMB2_COMPRESSION_ALG_LZ77							= 0x0002
SMB2_COMPRESSION_ALG_LZ77_HUFFMAN					= 0x0003
SMB2_COMPRESSION_ALG_PATTERN_V1						= 0x0004

SMB2_CHANNEL_NONE									= 0x00000000
SMB2_CHANNEL_RDMA_V1								= 0x00000001
SMB2_CHANNEL_RDMA_V1_INVALIDATE						= 0x00000002

SMB2_SESSION_FLAG_BINDING							= 0x01

SMB2_WRITEFLAG_WRITE_THROUGH						= 0x00000001
SMB2_WRITEFLAG_WRITE_UNBUFFERED						= 0x00000002

def SMB2_BuildPacketHeader( cmd, message_id = 0, session_id = 0, next_offset = 0 ):
	# ProtocolId (4 bytes)
	s = b'\xfeSMB'
	# StructureSize (2 bytes)
	s += struct.pack( "<H", 0x40 )
	# CreditCharge (2 bytes)
	s += struct.pack( "<H", 0 )
	# ChannelSequence (2 bytes)
	s += struct.pack( "<H", 0 )
	# Reserved (2 bytes)
	s += struct.pack( "<H", 0 )
	# Command (2 bytes)
	s += struct.pack( "<H", cmd )
	# CreditRequest (2 bytes)
	s += struct.pack( "<H", 0 )
	# Flags (4 bytes)
	s += struct.pack( "<L", 0 )
	# NextCommand (4 bytes)
	s += struct.pack( "<L", next_offset )
	# MessageId (8 bytes)
	s += struct.pack( "<Q", message_id )
	# Reserved (4 bytes)
	s += struct.pack( "<L", 0 )
	# TreeId (4 bytes)
	s += struct.pack( "<L", 0 )
	# SessionId (8 bytes)
	s += struct.pack( "<Q", session_id )
	# Signature (16 bytes)
	s += b"\x00" * 0x10

	assert len( s ) == SMB2_PACKET_HEADER_SIZE

	return s

def SMB2_BuildNegotiateContext( ctx_type, ctx_data ):
	# ContextType (2 bytes)
	s = struct.pack( "<H", ctx_type )
	# DataLength (2 bytes)
	s += struct.pack( "<H", len( ctx_data ) )
	# Reserved (4 bytes)
	s += struct.pack( "<L", 0 )
	# Data (variable)
	s += ctx_data

	return SMB2_Pad( s )

def SMB2_BuildPreauthIntegrityCapabilitiesNegotiateContext( salt ):
	# HashAlgorithmCount (2 bytes)
	s = struct.pack( "<H", 1 )
	# SaltLength (2 bytes)
	s += struct.pack( "<H", len( salt ) )
	# HashAlgorithms (variable)
	s += struct.pack( "<H", SMB2_HASH_ALG_SHA_512 )
	# Salt (variable)
	s += salt

	return SMB2_BuildNegotiateContext( SMB2_NEGCTX_PREAUTH_INTEGRITY_CAPABILITIES, s )

def SMB2_BuildCompressionCapabilitiesNegotiateContext():
	# CompressionAlgorithmCount (2 bytes)
	s = struct.pack( "<H", 1 )
	# Padding (2 bytes)
	s += struct.pack( "<H", 0 )
	# Flags (4 bytes)
	s += struct.pack( "<L", 0 )
	# CompressionAlgorithms (variable)	
	s += struct.pack( "<H", SMB2_COMPRESSION_ALG_LZNT1 )

	return SMB2_BuildNegotiateContext( SMB2_NEGCTX_COMPRESSION_CAPABILITIES, s )

def SMB2_BuildNegotiatePacket( compressed, salt_size = 0, next_offset = 0 ):
	s = SMB2_BuildPacketHeader( SMB2_CMD_NEGOTIATE, next_offset = next_offset )

	# StructureSize (2 bytes)
	s += struct.pack( "<H", 0x24 )
	# DialectCount (2 bytes)
	s += struct.pack( "<H", 1 )
	# SecurityMode (2 bytes)
	s += struct.pack( "<H", SMB2_NEGOTIATE_SIGNING_ENABLED )
#	s += struct.pack( "<H", 0 )
	# Reserved (2 bytes)
	s += struct.pack( "<H", 0 )
	# Capabilities (4 bytes)
	s += struct.pack( "<L", 0x00 )
	# ClientGuid (16 bytes)
	s += b'\x01\x02\x03\x04\x05\x06\x07\x08\x01\x02\x03\x04\x05\x06\x07\x08'

	l = len( s ) + 4 + 2 + 2 + 2
	ll = (-l & 7)

	# NegotiateContextOffset (4 bytes):
	s += struct.pack( "<L", l + ll )
	# NegotiateContextCount (2 bytes)
	s += struct.pack( "<H", 2 if compressed else 1 )
	# Reserved (2 bytes)
	s += struct.pack( "<H", 0 )
	# Dialects (2 * DialectCount)
	s += b"\x11\x03"

	# Padding for 8-byte alignment
	s += b"\x00" * ll

	salt = b''

	for i in range( 0, salt_size // 2):
		salt += struct.pack( '<H', i )

	if salt_size & 1:
		salt += b'*'

	# SMB2_NEGCTX_PREAUTH_INTEGRITY_CAPABILITIES
	s += SMB2_BuildPreauthIntegrityCapabilitiesNegotiateContext( salt = salt )
	
	if compressed:
		# SMB2_NEGCTX_COMPRESSION_CAPABILITIES
		s += SMB2_BuildCompressionCapabilitiesNegotiateContext()

	return s

def SMB2_BuildSessionSetupPacket( message_id, sec_buf = b'', session_id = 0, pad = b'', pad_size_extra = 0, sec_buf_extra_len = 0, next_offset = 0 ):
	s = SMB2_BuildPacketHeader( SMB2_CMD_SESSION_SETUP, message_id = message_id, session_id = session_id, next_offset = next_offset )

	# StructureSize (2 bytes)
	s += struct.pack( "<H", 0x19 )
	# Flags (1 byte)
	s += struct.pack( "<B", 0x00 )
	# SecurityMode (1 byte)
	s += struct.pack( "<B", SMB2_NEGOTIATE_SIGNING_ENABLED )
#	s += struct.pack( "<B", 0 )
	# Capabilities (4 bytes)
	s += struct.pack( "<L", 0 )
	# Channel (4 bytes)
	s += struct.pack( "<L", 0 )
	# SecurityBufferOffset (2 bytes)
	s += struct.pack( "<H", SMB2_SESSION_SETUP_PACKET_HEADER_SIZE + len( pad ) + pad_size_extra )
	# SecurityBufferLength (2 bytes)
	s += struct.pack( "<H", len( sec_buf ) + sec_buf_extra_len )
	# PreviousSessionId (8 bytes)
	s += struct.pack( "<Q", 0 )

	assert len( s ) == SMB2_SESSION_SETUP_PACKET_HEADER_SIZE

	# Padding
	s += pad

	# Buffer (variable)
	s += sec_buf

	return s;

def SMB2_BuildNtlmSessionSetupPacket( message_id, session_id = 0, extra_data = b'', extra_len = 0, pad = b'', pad_size_extra = 0, next_offset = 0 ):
	sec_buf = Smb2NtlmNegotiate( workstation = extra_data, workstation_extra_len = extra_len ).get_packet()

	return SMB2_BuildSessionSetupPacket( 1, sec_buf, sec_buf_extra_len = len( extra_data ) + extra_len, pad = pad, pad_size_extra = pad_size_extra, next_offset = next_offset )

def SMB2_BuildCompressedPacket( raw_part, compressed_part, compressed_part_original_size ):
	# Build header
	s = SMB2_BuildCompressedPacketHeader( raw_part, len( raw_part ), compressed_part_original_size )
	# append compressed part
	s += compressed_part

	return s

def SMB2_BuildCompressedPacketHeader( raw_part, compressed_part_offset, compressed_part_original_size ):
	# ProtocolId (4 bytes)
	s = b'\xfcSMB'
	# OriginalCompressedSegmentSize (4 bytes)
	s += struct.pack( "<L", compressed_part_original_size )
	# CompressionAlgorithm (2 bytes)
	s += struct.pack( "<H", SMB2_COMPRESSION_ALG_LZNT1 )
	# Flags (2 bytes)
	s += struct.pack( "<H", 0 )
	# Offset/Length (4 bytes)
	s += struct.pack( "<L", compressed_part_offset )

	assert len( s ) == SMB2_COMPRESSION_HEADER_SIZE

	# append RAW part
	s += raw_part

	return s

def SMB2_Pad( s ):
	return s + b"\x00" * (-len( s ) & 7)

def SMB2_TcpWrapPacket( pkt ):
	assert len( pkt ) <= 0x00ffffff

	return struct.pack( ">L", len( pkt ) ) + pkt

def SMB2_Negotiate( ip, port, compressed, salt_size = 0 ):
	sock = SMB2_Connect( ip, port )
	
	buf = SMB2_NegotiateEx( sock, salt_size = salt_size, compressed = compressed )

#	sock.shutdown( socket.SHUT_RDWR )
	sock.close()

	return buf

def SMB2_NegotiateEx( sock, compressed = True, salt_size = 0 ):
	s = SMB2_BuildNegotiatePacket( compressed, salt_size = salt_size )

	s = SMB2_TcpWrapPacket( s )

	sock.send( s )

	buf = sock.recv( 0x1000 )

	return buf

def SMB2_Connect( ip, port = 445 ):
	if vars.proxy_host == None:
		sock = socket.socket( socket.AF_INET )
	else:
		sock = socks.socksocket( socket.AF_INET )
		sock.set_proxy( socks.PROXY_TYPE_SOCKS5, vars.proxy_host, vars.proxy_port )

	sock.settimeout( vars.socket_timeout )

	sock.connect( (ip, port) )

	return sock

def SMB2_Read( sock, size ):
	buf = b''

	while size > 0:
		s = sock.recv( size )

		buf += s

		size -= len( s )

	return buf
