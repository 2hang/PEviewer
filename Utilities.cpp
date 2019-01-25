#include "Utilities.h"

/*
// Print All Binary Data
while ((ch = fgetc(in)) != EOF) {
printf("%02X ", ch);
if (count == 14) {
printf("\n");
}
count = (count + 1) % 15;

}
*/

BYTE parseAndStoreBYTE(FILE *_in) {
	BYTE _byte;
	_byte = fgetc(_in);
	return _byte;
	//printf("%02X\n", *_byte);
}

WORD parseAndStoreWORD(FILE *_in) {
	WORD _word;
	BYTE *ptr = (BYTE *)&_word;
	BYTE byte;
	for (int i = 0; i < 2; i++) {
		byte = fgetc(_in);
		*ptr = byte;
		ptr++;
		//printf("%02X ", byte);
	}
	//printf("\n");
	return _word;
}

DWORD parseAndStoreDWORD(FILE *_in) {
	DWORD _dword;
	BYTE *ptr = (BYTE *)&_dword;
	BYTE byte;
	for (int i = 0; i < 4; i++) {
		byte = fgetc(_in);
		*ptr = byte;
		ptr++;
		//printf("%02X ", byte);
	}
	return _dword;
	//printf("\n");
}

LONG parseAndStoreLONG(FILE *_in) {
	LONG _long;
	BYTE *ptr = (BYTE *)&_long;
	BYTE byte;
	for (int i = 0; i < 4; i++) {
		byte = fgetc(_in);
		*ptr = byte;
		ptr++;
		//printf("%02X ", byte);
	}
	return _long;
	//printf("\n");
}

IMAGE_SECTION_HEADER *allocSectionHeaders(int _num) {
	IMAGE_SECTION_HEADER *headers = (IMAGE_SECTION_HEADER *)malloc(sizeof(IMAGE_SECTION_HEADER)*_num);
	return headers;
}

int whichSectionRVA(IMAGE_SECTION_HEADER *_sectionsHeaders, int _numOfSections, DWORD _rva) {
	/*
		Headers : return -1
		Section x : return x (0 ~ ) section header index
	*/

	DWORD sectionOff;
	for (int i = _numOfSections-1; i >= 0; i--) {
		sectionOff = _sectionsHeaders[i].VirtualAddress;
		if (_rva >= sectionOff) {
			return i;
		}
	}
	return -1;
}

DWORD RVAtoRAW(IMAGE_NT_HEADERS32 *_ntHeader, 
	IMAGE_SECTION_HEADER *_sectionsHeaders, 
	int _whichSection, DWORD _rva) {
	
	if (_whichSection == -1) {
		return _rva;
	}
	
	DWORD virtualOffset = _sectionsHeaders[_whichSection].VirtualAddress;
	DWORD fileAlignment = _ntHeader->OptionalHeader.FileAlignment;
	DWORD rawOffset = _sectionsHeaders[_whichSection].PointerToRawData;
	rawOffset /= fileAlignment;
	rawOffset *= fileAlignment;

	return _rva - virtualOffset + rawOffset;
}

void printMachineType(WORD _machine) {
	printf("Machine type : ");
	switch (_machine)
	{
	case IMAGE_FILE_MACHINE_UNKNOWN:
		printf("UNKNOWN");
		break;
	case IMAGE_FILE_MACHINE_I386:
		printf("I386");
		break;
	case IMAGE_FILE_MACHINE_R3000:
		printf("R3000");
		break;
	case IMAGE_FILE_MACHINE_R4000:
		printf("R4000");
		break;
	case IMAGE_FILE_MACHINE_R10000:
		printf("R10000");
		break;
	case IMAGE_FILE_MACHINE_WCEMIPSV2:
		printf("WCEMIPSV2");
		break;
	case IMAGE_FILE_MACHINE_ALPHA:
		printf("ALPHA");
		break;
	case IMAGE_FILE_MACHINE_POWERPC:
		printf("POWERPC");
		break;
	case IMAGE_FILE_MACHINE_SH3:
		printf("SH3");
		break;
	case IMAGE_FILE_MACHINE_SH3E:
		printf("SH3E");
		break;
	case IMAGE_FILE_MACHINE_SH4:
		printf("SH4");
		break;
	case IMAGE_FILE_MACHINE_ARM:
		printf("ARM");
		break;
	case IMAGE_FILE_MACHINE_THUMB:
		printf("THUMB");
		break;
	case IMAGE_FILE_MACHINE_IA64:
		printf("IA64");
		break;
	case IMAGE_FILE_MACHINE_MIPS16:
		printf("MIPS16");
		break;
	case IMAGE_FILE_MACHINE_MIPSFPU:
		printf("MIPSFPU");
		break;
	case IMAGE_FILE_MACHINE_MIPSFPU16:
		printf("MIPSFPU16");
		break;
	case IMAGE_FILE_MACHINE_ALPHA64:
		printf("ALPHA64");
		break;
	default:
		printf("error");
	}
	printf(" (0x%04X)\n", _machine);
}

void printFileCharacteristics(WORD _ch) {
	printf("File Characteristics : 0x%04X\n",_ch);
	if (IMAGE_FILE_RELOCS_STRIPPED & _ch) {
		printf("	IMAGE_FILE_RELOCS_STRIPPED\n");
	}
	if (IMAGE_FILE_EXECUTABLE_IMAGE & _ch) {
		printf("	IMAGE_FILE_EXECUTABLE_IMAGE\n");
	}
	if (IMAGE_FILE_LINE_NUMS_STRIPPED & _ch) {
		printf("	IMAGE_FILE_LINE_NUMS_STRIPPED\n");
	}
	if (IMAGE_FILE_LOCAL_SYMS_STRIPPED & _ch) {
		printf("	IMAGE_FILE_LOCAL_SYMS_STRIPPED\n");
	}
	if (IMAGE_FILE_AGGRESIVE_WS_TRIM & _ch) {
		printf("	IMAGE_FILE_AGGRESIVE_WS_TRIM\n");
	}
	if (IMAGE_FILE_LARGE_ADDRESS_AWARE & _ch) {
		printf("	IMAGE_FILE_LARGE_ADDRESS_AWARE\n");
	}
	if (IMAGE_FILE_BYTES_REVERSED_LO & _ch) {
		printf("	IMAGE_FILE_BYTES_REVERSED_LO\n");
	}
	if (IMAGE_FILE_32BIT_MACHINE & _ch) {
		printf("	IMAGE_FILE_32BIT_MACHINE\n");
	}
	if (IMAGE_FILE_DEBUG_STRIPPED & _ch) {
		printf("	IMAGE_FILE_DEBUG_STRIPPED\n");
	}
	if (IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP & _ch) {
		printf("	IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP\n");
	}
	if (IMAGE_FILE_NET_RUN_FROM_SWAP & _ch) {
		printf("	IMAGE_FILE_NET_RUN_FROM_SWAP\n");
	}
	if (IMAGE_FILE_SYSTEM & _ch) {
		printf("	IMAGE_FILE_SYSTEM\n");
	}
	if (IMAGE_FILE_DLL & _ch) {
		printf("	IMAGE_FILE_DLL\n");
	}
	if (IMAGE_FILE_UP_SYSTEM_ONLY & _ch) {
		printf("	IMAGE_FILE_UP_SYSTEM_ONLY\n");
	}
	if (IMAGE_FILE_BYTES_REVERSED_HI & _ch) {
		printf("	IMAGE_FILE_BYTES_REVERSED_HI\n");
	}
}

void printSectionCharacteristics(DWORD _ch) {
	printf("Section Characteristics : 0x%04X\n", _ch);
	if (IMAGE_SCN_CNT_CODE & _ch) {
		printf("	IMAGE_SCN_CNT_CODE\n");
	}
	if (IMAGE_SCN_CNT_INITIALIZED_DATA & _ch) {
		printf("	IMAGE_SCN_CNT_INITIALIZED_DATA\n");
	}
	if (IMAGE_SCN_CNT_UNINITIALIZED_DATA & _ch) {
		printf("	IMAGE_SCN_CNT_UNINITIALIZED_DATA\n");
	}
	if (IMAGE_SCN_MEM_EXECUTE & _ch) {
		printf("	IMAGE_SCN_MEM_EXECUTE\n");
	}
	if (IMAGE_SCN_MEM_READ & _ch) {
		printf("	IMAGE_SCN_MEM_READ\n");
	}
	if (IMAGEJ_SCN_MEM_WRITE & _ch) {
		printf("	IMAGEJ_SCN_MEM_WRITE\n");
	}
}