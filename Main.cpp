#include "Utilities.h"

int main(int argc,char *argv[]) {
	FILE *in;
	IMAGE_DOS_HEADER dosHeader;
	IMAGE_NT_HEADERS32 ntHeader;

	// Members to display info.
	DWORD imageBase;
	DWORD entryPointRVA;
	DWORD entryPointRAW;
	DWORD sizeOfImage;
	DWORD sectionAlignment;
	DWORD fileAlignment;
	WORD numberOfSections;
	WORD characteristics;
	DWORD sizeOfHeaders;
	WORD machine;
	WORD dllCharacteristics;
	struct DirectoryInfo importTable;
	struct DirectoryInfo exportTable;

	if (argc != 2) {
		printf("USAGE : PEVIEWER.exe [Name of PE File]");
		return -1;
	}

	// File open READ ONLY
	if ((in = fopen(argv[1], "rb")) == NULL) {
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
	numberOfSections = ntHeader.FileHeader.NumberOfSections;
	IMAGE_SECTION_HEADER *sectionHeaders = allocSectionHeaders((int)numberOfSections);
	
	DWORD OptionalStartOffset = dosHeader.e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);
	fseek(in, OptionalStartOffset+(DWORD)ntHeader.FileHeader.SizeOfOptionalHeader, SEEK_SET);

	// Parsing Section Headers from file
	for (int k = 0; k < (int)numberOfSections; k++) {
		for (int i = 0; i < 8; i++) {
			sectionHeaders[k].Name[i] = parseAndStoreBYTE(in);
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

	// Arrange the Infos
	imageBase = ntHeader.OptionalHeader.ImageBase;
	printf("ImageBase : 0x%08X\n\n",imageBase);

	entryPointRVA =ntHeader.OptionalHeader.AddressOfEntryPoint;
	printf("Entry Point (RVA) : 0x%08X\n\n", entryPointRVA);

	int which = whichSectionRVA(sectionHeaders, numberOfSections, entryPointRVA);
	entryPointRAW = RVAtoRAW(&ntHeader, sectionHeaders, which, entryPointRVA);
	printf("Entry Point (RAW) : 0x%08X\n\n", entryPointRAW);

	sizeOfImage = ntHeader.OptionalHeader.SizeOfImage;
	printf("Size of Image : 0x%08X\n\n", sizeOfImage);

	sectionAlignment = ntHeader.OptionalHeader.SectionAlignment;
	printf("Section Alignment : 0x%08X\n\n", sectionAlignment);
	
	fileAlignment = ntHeader.OptionalHeader.FileAlignment;
	printf("File Alignment : 0x%08X\n\n", fileAlignment);
	
	printf("Number of Sections : 0x%04X\n\n", numberOfSections);

	characteristics = ntHeader.FileHeader.Characteristics;
	printFileCharacteristics(characteristics);
	
	sizeOfHeaders = ntHeader.OptionalHeader.SizeOfHeaders;
	printf("\nTotal size of PE Header : 0x%08X\n\n", fileAlignment);
	
	machine = ntHeader.FileHeader.Machine;
	printMachineType(machine);
	
	dllCharacteristics = ntHeader.OptionalHeader.DllCharacteristics;
	printf("\nDLL Charateristics : 0x%04X\n\n", dllCharacteristics);

	exportTable.Rva = ntHeader.OptionalHeader.DataDirectory[0].VirtualAddress;
	which = whichSectionRVA(sectionHeaders, numberOfSections, exportTable.Rva);
	exportTable.Raw = RVAtoRAW(&ntHeader, sectionHeaders, which, exportTable.Rva);
	exportTable.Size = ntHeader.OptionalHeader.DataDirectory[0].Size;

	printf("\n------Export Table------\n");
	printf("RVA : 0x%08X\n", exportTable.Rva);
	printf("RAW : 0x%08X\n", exportTable.Raw);
	printf("Size : 0x%08X\n", exportTable.Size);

	importTable.Rva = ntHeader.OptionalHeader.DataDirectory[1].VirtualAddress;
	which = whichSectionRVA(sectionHeaders, numberOfSections, importTable.Rva);
	importTable.Raw = RVAtoRAW(&ntHeader, sectionHeaders, which, importTable.Rva);
	importTable.Size = ntHeader.OptionalHeader.DataDirectory[1].Size;

	printf("\n------Import Table------\n");
	printf("RVA : 0x%08X\n", importTable.Rva);
	printf("RAW : 0x%08X\n", importTable.Raw);
	printf("Size : 0x%08X\n", importTable.Size);

	fseek(in, importTable.Raw, SEEK_SET);
	PIDT idt = (PIDT)malloc(importTable.Size);
	
	for (int i = 0; i < (importTable.Size / sizeof(IMAGE_IMPORT_DESCRIPTOR)); i++) {
		idt[i].OriginalFirstThunk = parseAndStoreDWORD(in);
		idt[i].TimeDateStamp = parseAndStoreDWORD(in);
		idt[i].ForwarderChain = parseAndStoreDWORD(in);
		idt[i].Name = parseAndStoreDWORD(in);
		idt[i].FirstThunk = parseAndStoreDWORD(in);
	}

	printf("\nImport DLLs :\n");
	for (int i = 0; i < (importTable.Size / sizeof(IMAGE_IMPORT_DESCRIPTOR)) - 1; i++) {
		DWORD off = RVAtoRAW(&ntHeader, sectionHeaders, whichSectionRVA(sectionHeaders, numberOfSections, idt[i].Name), idt[i].Name);
		printf("	");
		fseek(in, off, SEEK_SET);
		BYTE c;
		while (1) {
			c = parseAndStoreBYTE(in);
			if (c == NULL) {
				printf("\n");
				break;
			}
			printf("%c", c);
		}
	}

	for (int i = 0; i < numberOfSections; i++) {
		printf("\nSection : ");
		for (int j = 0; j < 8; j++) {
			printf("%c", sectionHeaders[i].Name[j]);
		}
		printf("\n");
		printf("Virtual Size : 0x%08X\n", sectionHeaders[i].VirualSize);
		printf("Virtual Offset : 0x%08X\n", sectionHeaders[i].VirtualAddress);
		printf("Raw Size : 0x%08X\n", sectionHeaders[i].SizeOfRawData);
		printf("Raw Offset : 0x%08X\n", sectionHeaders[i].PointerToRawData);
		printSectionCharacteristics(sectionHeaders[i].Characteristics);
	}
	

	fclose(in);
	free(sectionHeaders);
	return 0;
}
