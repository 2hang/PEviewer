//////// 유틸리티 필요함


//IMAGE_FILE_HEADER.Machine
#define IMAGE_FILE_MACHINE_UNKNOWN 0
#define IMAGE_FILE_MACHINE_I386 0x014C
#define IMAGE_FILE_MACHINE_R3000 0x0162
#define IMAGE_FILE_MACHINE_R4000 0x0166
#define IMAGE_FILE_MACHINE_R10000 0x168
#define IMAGE_FILE_MACHINE_WCEMIPSV2 0x169
#define IMAGE_FILE_MACHINE_ALPHA 0x184
#define IMAGE_FILE_MACHINE_POWERPC 0x1F0
#define IMAGE_FILE_MACHINE_SH3 0x01A2
#define IMAGE_FILE_MACHINE_SH3E 0x01A4
#define IMAGE_FILE_MACHINE_SH4 0x01A6
#define IMAGE_FILE_MACHINE_ARM 0x01C0
#define IMAGE_FILE_MACHINE_THUMB 0x01C2
#define IMAGE_FILE_MACHINE_IA64 0x0200
#define IMAGE_FILE_MACHINE_MIPS16 0x0266
#define IMAGE_FILE_MACHINE_MIPSFPU 0x366
#define IMAGE_FILE_MACHINE_MIPSFPU16 0x466
#define IMAGE_FILE_MACHINE_ALPHA64 0x284
#define IMAGE_FILE_MACHINE_AXP64 IMAGE_FILE_MACHINE_ALPHA64

////IMAGE_FILE_HEADER.Characteristics
#define IMAGE_FILE_RELOCS_STRIPPED 0x0001
#define IMAGE_FILE_EXECUTABLE_IMAGE 0x0002
#define IMAGE_FILE_LINE_NUMS_STRIPPED 0x0004
#define IMAGE_FILE_LOCAL_SYMS_STRIPPED 0x0008
#define IMAGE_FILE_AGGRESIVE_WS_TRIM 0x0010
#define IMAGE_FILE_LARGE_ADDRESS_AWARE 0x0020
#define IMAGE_FILE_BYTES_REVERSED_LO 0x0080
#define IMAGE_FILE_32BIT_MACHINE 0x0100
#define IMAGE_FILE_DEBUG_STRIPPED 0x0200
#define IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP 0x0400
#define IMAGE_FILE_NET_RUN_FROM_SWAP 0x0800
#define IMAGE_FILE_SYSTEM 0x1000
#define IMAGE_FILE_DLL 0x2000
#define IMAGE_FILE_UP_SYSTEM_ONLY 0x4000
#define IMAGE_FILE_BYTES_REVERSED_HI 0x8000

//IMAGE_SECTION_HEADER.Characteristics
#define IMAGE_SCN_CNT_CODE 0x00000020
#define IMAGE_SCN_CNT_INITIALIZED_DATA 0x00000040
#define IMAGE_SCN_CNT_UNINITIALIZED_DATA 0x00000080
#define IMAGE_SCN_MEM_EXECUTE 0x20000000
#define IMAGE_SCN_MEM_READ 0x40000000
#define IMAGEJ_SCN_MEM_WRITE 0x80000000