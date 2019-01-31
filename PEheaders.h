#include <stdint.h>
typedef uint8_t BYTE;
typedef uint16_t WORD;
typedef uint32_t DWORD;
typedef uint32_t LONG;

struct DirectoryInfo {
	DWORD Rva;
	DWORD Raw;
	DWORD Size;
};

/*
	Commented members are essential to execute PE file.
*/

/*** Dos Header ***/
typedef struct _IMAGE_DOS_HEADER {
	WORD e_magic; //  MZ  //
	WORD e_cblp;
	WORD e_cp;
	WORD e_crlc;
	WORD e_cparhdr;
	WORD e_minalloc;
	WORD e_maxalloc;
	WORD e_ss;
	WORD e_sp;
	WORD e_csum;
	WORD e_ip;
	WORD e_cs;
	WORD e_lfarlc;
	WORD e_ovno;
	WORD e_res[4];
	WORD e_oemid;
	WORD e_oeminfo;
	WORD e_res2[10];
	LONG e_lfanew; // NTheader offset //
} IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

/*** NT Header ***/
typedef struct _IMAGE_FILE_HEADER {
	WORD Machine; // MACRO - 32bit Intel x86 : 0x014C //
	WORD NumberOfSections; // num of sections //
	DWORD TimeDateStamp;
	DWORD PointerToSymbolTable;
	DWORD NumberOfSymbols;
	WORD SizeOfOptionalHeader; // IMAGE_OPTIONAL_HEADER size //
	WORD Characteristics; // MACRO //
}IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

typedef struct _IMAGE_DATA_DIRECTORY {
	DWORD VirtualAddress;
	DWORD Size;
}IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

typedef struct _IMAGE_OPTIONAL_HEADER {
	WORD Magic; // 0x10b - optional_header32 // 0x20b - optional_header64
	BYTE MajorLinkerVersion;
	BYTE MinorLinkerVersion;
	DWORD SizeOfCode;
	DWORD SizeOfInitializedData;
	DWORD SizeOfUninitializedData;
	DWORD AddressOfEntryPoint; // EP RVA //
	DWORD BaseOfCode;
	DWORD BaseOfData;
	DWORD ImageBase; // Image Base//
	DWORD SectionAlignment; // Memory section alignment //
	DWORD FileAlignment; // File section alignment //
	WORD MajorOperatingSystemVersion;
	WORD MinorOperatingSystemVersion;
	WORD MajorImageVersion;
	WORD MinorImageVersion;
	WORD MajorSubsystemVersion;
	WORD MinorSubsystemVersion;
	DWORD Win32VersionValue;
	DWORD SizeOfImage; // On memory //
	DWORD SizeOfHeaders; // PE header total size //
	DWORD CheckSum;
	WORD Subsystem; // Driver file or GUI or CUI //
	WORD DllCharacteristics;
	DWORD SizeOfStackReserve;
	DWORD SizeOfStackCommit;
	DWORD SizeOfHeapReserve;
	DWORD SizeOfHeapCommit;
	DWORD LoaderFlags;
	DWORD NumberOfRvaAndSizes; // Number of DataDirectory array //
	// export, import, resource, TLS !! //
	IMAGE_DATA_DIRECTORY DataDirectory[16];
}IMAGE_OPTIONAL_HEADER32, *PIMAGE_OPTIONAL_HEADER32;

typedef struct _IMAGE_NT_HEADERS {
	DWORD Signature; // PE //
	IMAGE_FILE_HEADER FileHeader;
	IMAGE_OPTIONAL_HEADER32 OptionalHeader;
}IMAGE_NT_HEADERS32, *PIMAGE_NT_HEADERS32;

/*** Section Header ***/
typedef struct _IMAGE_SECTION_HEADER {
	BYTE Name[8];
	DWORD VirualSize; // Section size on memory //
	DWORD VirtualAddress; // Section RVA //
	DWORD SizeOfRawData; // Section size in file //
	DWORD PointerToRawData; // Section RAW //
	DWORD PointerToRelocations;
	DWORD PointerToLinenumbers;
	WORD NumberOfRelocations;
	WORD NumberOfLinenumbers;
	DWORD Characteristics; // Characteristics of section //
}IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;

typedef struct _IMAGE_IMPORT_DESCRIPTOR {
	DWORD OriginalFirstThunk; // RVA of INT
	DWORD TimeDateStamp;
	DWORD ForwarderChain;
	DWORD Name; // RVA
	DWORD FirstThunk; // RVA of IAT
}IMAGE_IMPORT_DESCRIPTOR, *PIDT;
