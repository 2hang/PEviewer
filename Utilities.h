#include "PEheaders.h"
#include "Codes.h"
#include <stdio.h>
#include <stdlib.h>

BYTE parseAndStoreBYTE(FILE *_in);
WORD parseAndStoreWORD(FILE *_in);
DWORD parseAndStoreDWORD(FILE *_in);
LONG parseAndStoreLONG(FILE *_in);
IMAGE_SECTION_HEADER *allocSectionHeaders(int _num);
int whichSectionRVA(IMAGE_SECTION_HEADER *_sectionsHeaders, int _numOfSections, DWORD _rva); // 섹션 구분
DWORD RVAtoRAW(IMAGE_NT_HEADERS32 *_ntHeader, IMAGE_SECTION_HEADER *_sectionsHeaders, int _whichSection, DWORD _rva);
//보여줄 정보들에 관한 유틸리티