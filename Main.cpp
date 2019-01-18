#include "Utilities.h"

#define PATH "C:/Users/HY/Desktop/01_기초_리버싱/02_Hello_World!_리버싱/bin/HelloWorld.exe"

int main() {
	FILE *in;
	IMAGE_DOS_HEADER dosHeader;

	// 읽기 전용으로 열기 //
	if ((in = fopen(PATH, "rb")) == NULL) {
		fputs("FOPEN ERROR\n", stderr);
		exit(999);
	}

	////////// Parsing the DOS header //////////
	dosHeader.e_magic = parseAndStoreWORD(in);
	dosHeader.e_cblp = parseAndStoreWORD(in);
	dosHeader.e_cp = parseAndStoreWORD(in);
	dosHeader.e_crlc = parseAndStoreWORD(in);
	dosHeader.e_cparhdr = parseAndStoreWORD(in);
	dosHeader.e_minalloc = parseAndStoreWORD(in);
	dosHeader.e_maxalloc = parseAndStoreWORD(in);
	dosHeader.e_ss = parseAndStoreWORD(in);
	dosHeader.e_sp = parseAndStoreWORD(in);
	dosHeader.e_csum = parseAndStoreWORD(in);
	dosHeader.e_ip = parseAndStoreWORD(in);
	dosHeader.e_cs = parseAndStoreWORD(in);
	dosHeader.e_lfarlc = parseAndStoreWORD(in);
	dosHeader.e_ovno = parseAndStoreWORD(in);
	for (int i = 0; i < 4; i++) {
		dosHeader.e_res[i] = parseAndStoreWORD(in);
	}
	dosHeader.e_oemid = parseAndStoreWORD(in);
	dosHeader.e_oeminfo = parseAndStoreWORD(in);
	for (int i = 0; i < 10; i++) {
		dosHeader.e_res2[i] = parseAndStoreWORD(in);
	}
	dosHeader.e_lfanew = parseAndStoreLONG(in);
	////////////////////////////////////////////////
	
	fclose(in);
	return 0;
}