#include "PEheaders.h"
#include "Codes.h"
#include <stdio.h>
#include <stdlib.h>

BYTE parseAndStoreBYTE(FILE *_in);
WORD parseAndStoreWORD(FILE *_in);
DWORD parseAndStoreDWORD(FILE *_in);
LONG parseAndStoreLONG(FILE *_in);
IMAGE_SECTION_HEADER *allocSectionHeaders(int _num);
//���� ���� ��ƿ��Ƽ
//rva->raw ��ƿ��Ƽ
//������ �����鿡 ���� ��ƿ��Ƽ