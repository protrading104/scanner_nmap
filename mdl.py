import struct

MDL_MAPPED_TO_SYSTEM_VA						= 0x0001
MDL_PAGES_LOCKED							= 0x0002
MDL_SOURCE_IS_NONPAGED_POOL					= 0x0004
MDL_ALLOCATED_FIXED_SIZE					= 0x0008
MDL_PARTIAL									= 0x0010
MDL_PARTIAL_HAS_BEEN_MAPPED					= 0x0020
MDL_IO_PAGE_READ							= 0x0040
MDL_WRITE_OPERATION							= 0x0080
MDL_PARENT_MAPPED_SYSTEM_VA					= 0x0100
MDL_LOCK_HELD								= 0x0200
MDL_PHYSICAL_VIEW							= 0x0400
MDL_IO_SPACE								= 0x0800
MDL_NETWORK_HEADER							= 0x1000
MDL_MAPPING_CAN_FAIL						= 0x2000
MDL_ALLOCATED_MUST_SUCCEED					= 0x4000

ofs_MDL_Size								= 0x08
ofs_MDL_Flags								= 0x0A
ofs_MDL_Reserved							= 0x0C
ofs_MDL_Process								= 0x10
ofs_MDL_MappedSystemVa						= 0x18
ofs_MDL_StartVa								= 0x20
ofs_MDL_ByteCount							= 0x28
ofs_MDL_ByteOffset							= 0x2C

sizeof_MDL									= 0x30

def BuildMDL( map_va, phys_addr, buf_size ):
	s = BuildMDLHeader( map_va, phys_addr & 0xFFF, buf_size )

	phys_addr >>= 12

	for i in range( NUM_MDL_PAGES ):
		s += struct.pack( '<Q', phys_addr + i )

	return s

def BuildMDLHeader( map_va, buf_ofs, buf_size ):
	assert buf_ofs < buf_size

	num_pages = ((buf_size - 1) >> 12) + 1

	s = b''

	# Next
	s += struct.pack( '<Q', 0 )
	# Size
	s += struct.pack( '<H', sizeof_MDL + 8*num_pages )
	# Flags
	s += struct.pack( '<H', MDL_ALLOCATED_FIXED_SIZE | MDL_PARTIAL | MDL_ALLOCATED_MUST_SUCCEED | MDL_NETWORK_HEADER )
	# Reserved
	s += struct.pack( '<L', 0 )
	# Process
	s += struct.pack( '<Q', 0 )
	# SystemMappedVa
	s += struct.pack( '<Q', map_va )
	# StartVa
	s += struct.pack( '<Q', (map_va & ~0xfff) - (buf_ofs & ~0xfff) )
	# ByteCount
	s += struct.pack( '<L', buf_size - buf_ofs )
	# ByteOffset
	s += struct.pack( '<L', buf_ofs )

	return s
