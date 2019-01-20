#include "PEheaders.h"
#include "Codes.h"
#include <stdio.h>
#include <stdlib.h>

BYTE parseAndStoreBYTE(FILE *_in);
WORD parseAndStoreWORD(FILE *_in);
DWORD parseAndStoreDWORD(FILE *_in);
LONG parseAndStoreLONG(FILE *_in);
IMAGE_SECTION_HEADER *allocSectionHeaders(int _num);
//섹션 구분 유틸리티
//rva->raw 유틸리티
//보여줄 정보들에 관한 유틸리티