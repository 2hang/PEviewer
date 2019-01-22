#include "Utilities.h"

#define PATH "C:/Users/HY/Desktop/01_扁檬_府滚教/02_Hello_World!_府滚教/bin/HelloWorld.exe"

int main() {
	FILE *in;
	IMAGE_DOS_HEADER dosHeader;
	IMAGE_NT_HEADERS32 ntHeader;

	// File open READ ONLY
	if ((in = fopen(PATH, "rb")) == NULL) {
		fputs("FOPEN ERROR\n", stderr);
		exit(999);
	}

	// Parsing the DOS header from file
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
	
	// Parsing the NT Header from file
	fseek(in, dosHeader.e_lfanew, SEEK_SET);
	ntHeader.Signature = parseAndStoreDWORD(in);

	// Parsing the File Header in NT Header from file
	ntHeader.FileHeader.Machine = parseAndStoreWORD(in);
	ntHeader.FileHeader.NumberOfSections = parseAndStoreWORD(in);
	ntHeader.FileHeader.TimeDateStamp = parseAndStoreDWORD(in);
	ntHeader.FileHeader.PointerToSymbolTable = parseAndStoreDWORD(in);
	ntHeader.FileHeader.NumberOfSymbols = parseAndStoreDWORD(in);
	ntHeader.FileHeader.SizeOfOptionalHeader = parseAndStoreWORD(in);
	ntHeader.FileHeader.Characteristics = parseAndStoreWORD(in);
	
	// Parsing the Optional Header in NT Header from file
	ntHeader.OptionalHeader.Magic = parseAndStoreWORD(in);
	ntHeader.OptionalHeader.MajorLinkerVersion = parseAndStoreBYTE(in);
	ntHeader.OptionalHeader.MinorLinkerVersion = parseAndStoreBYTE(in);
	ntHeader.OptionalHeader.SizeOfCode = parseAndStoreDWORD(in);
	ntHeader.OptionalHeader.SizeOfInitializedData = parseAndStoreDWORD(in);
	ntHeader.OptionalHeader.SizeOfUninitializedData = parseAndStoreDWORD(in);
	ntHeader.OptionalHeader.AddressOfEntryPoint = parseAndStoreDWORD(in);
	ntHeader.OptionalHeader.BaseOfCode = parseAndStoreDWORD(in);
	ntHeader.OptionalHeader.BaseOfData = parseAndStoreDWORD(in);
	ntHeader.OptionalHeader.ImageBase = parseAndStoreDWORD(in);
	ntHeader.OptionalHeader.SectionAlignment = parseAndStoreDWORD(in);
	ntHeader.OptionalHeader.FileAlignment = parseAndStoreDWORD(in);
	ntHeader.OptionalHeader.MajorOperatingSystemVersion = parseAndStoreWORD(in);
	ntHeader.OptionalHeader.MinorOperatingSystemVersion = parseAndStoreWORD(in);
	ntHeader.OptionalHeader.MajorImageVersion = parseAndStoreWORD(in);
	ntHeader.OptionalHeader.MinorImageVersion = parseAndStoreWORD(in);
	ntHeader.OptionalHeader.MajorSubsystemVersion = parseAndStoreWORD(in);
	ntHeader.OptionalHeader.MinorSubsystemVersion = parseAndStoreWORD(in);
	ntHeader.OptionalHeader.Win32VersionValue = parseAndStoreDWORD(in);
	ntHeader.OptionalHeader.SizeOfImage = parseAndStoreDWORD(in);
	ntHeader.OptionalHeader.SizeOfHeaders = parseAndStoreDWORD(in);
	ntHeader.OptionalHeader.CheckSum = parseAndStoreDWORD(in);
	ntHeader.OptionalHeader.Subsystem = parseAndStoreWORD(in);
	ntHeader.OptionalHeader.DllCharacteristics = parseAndStoreWORD(in);
	ntHeader.OptionalHeader.SizeOfStackReserve = parseAndStoreDWORD(in);
	ntHeader.OptionalHeader.SizeOfStackCommit = parseAndStoreDWORD(in);
	ntHeader.OptionalHeader.SizeOfHeapReserve = parseAndStoreDWORD(in);
	ntHeader.OptionalHeader.SizeOfHeapCommit = parseAndStoreDWORD(in);
	ntHeader.OptionalHeader.LoaderFlags = parseAndStoreDWORD(in);
	ntHeader.OptionalHeader.NumberOfRvaAndSizes = parseAndStoreDWORD(in);
	
	// Parsing Data Directory from file.
	for (int i = 0; i < 16; i++) {
		ntHeader.OptionalHeader.DataDirectory[i].VirtualAddress = parseAndStoreDWORD(in);
		ntHeader.OptionalHeader.DataDirectory[i].Size = parseAndStoreDWORD(in);
	}

	// Make Section Headers
	int numOfSections = ntHeader.FileHeader.NumberOfSections;
	IMAGE_SECTION_HEADER *sectionHeaders = allocSectionHeaders(numOfSections);
	
	// Parsing Section Headers from file
	for (int k = 0; k < numOfSections; k++) {
		for (int i = 0; i < 8; i++) {
			sectionHeaders[k].Name[i] = parseAndStoreBYTE(in);
			//printf("%c", sectionHeaders[k].Name[i]);
		}
		sectionHeaders[k].VirualSize = parseAndStoreDWORD(in);
		sectionHeaders[k].VirtualAddress = parseAndStoreDWORD(in);
		sectionHeaders[k].SizeOfRawData = parseAndStoreDWORD(in);
		sectionHeaders[k].PointerToRawData = parseAndStoreDWORD(in);
		sectionHeaders[k].PointerToRelocations = parseAndStoreDWORD(in);
		sectionHeaders[k].PointerToLinenumbers = parseAndStoreDWORD(in);
		sectionHeaders[k].NumberOfRelocations = parseAndStoreWORD(in);
		sectionHeaders[k].NumberOfLinenumbers = parseAndStoreWORD(in);
		sectionHeaders[k].Characteristics = parseAndStoreDWORD(in);
	}

	//test
	DWORD tmpRVA = 0x00008000;
	int tmp = whichSectionRVA(sectionHeaders, numOfSections, tmpRVA);
	printf("%d\n", tmp);
	DWORD tmpRAW = RVAtoRAW(&ntHeader, sectionHeaders, tmp, tmpRVA);
	printf("%08X\n",tmpRAW);
	//////
	fclose(in);
	free(sectionHeaders);
	return 0;
}