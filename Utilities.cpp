#include "Utilities.h"

/*
while ((ch = fgetc(in)) != EOF) {

// 프린트하기
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
/*
void parseAndStoreWORD(FILE *_in, WORD *_word) {
	BYTE *ptr = (BYTE *)_word;
	BYTE byte;
	for (int i = 0; i < 2; i++) {
		byte = fgetc(_in);
		*ptr = byte;
		ptr++;
		//printf("%02X ", byte);
	}
	//printf("\n");
}
*/
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
	//printf("virtualOffset : %08X\n", virtualOffset);
	DWORD fileAlignment = _ntHeader->OptionalHeader.FileAlignment;
	//printf("fileAlignment : %08X\n", fileAlignment);
	DWORD rawOffset = _sectionsHeaders[_whichSection].PointerToRawData;
	//printf("rawOffset : %08X\n", rawOffset);
	rawOffset /= fileAlignment;
	rawOffset *= fileAlignment;
	//printf("rawOffset : %08X\n", rawOffset);

	return _rva - virtualOffset + rawOffset;
}