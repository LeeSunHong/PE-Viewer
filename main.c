#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<conio.h>
#include<windows.h>

#include"PEHeaders.h"

int main(int argc, char* argv[])
{
	if (argc < 2) {
		printf("Can not find the file.\n");
		_getch();
		return EXIT_FAILURE;
	}

	SetConsoleTitleA(argv[1]);
	char* filePath = argv[1];
	FILE* file = fopen(filePath, "rb");
	long fileSize = 0;
	char* dataBuffer;

	if (file == NULL) {
		fprintf(stderr, "Failed to open file.\n");
		_getch();
		return EXIT_FAILURE;
	}
	
	fseek(file, 0, SEEK_END); //file end pointer
	fileSize = ftell(file); //get a size
	rewind(file);

	dataBuffer = (char*)malloc(fileSize * sizeof(char));
	int readCheck = fread(dataBuffer, sizeof(char), fileSize, file);

	if (readCheck < fileSize) {
		fprintf(stderr, "Failed to read file.\n");
		_getch();
		return EXIT_SUCCESS;
	}

	char PE_Dos_Sig[3] = { dataBuffer[0], dataBuffer[1] };

	if (strcmp(PE_Dos_Sig, "MZ") != 0) {
		fprintf(stderr, "Not a valid PE file\n");
		_getch();
		return EXIT_SUCCESS;
	}

	union {
		char* e_lfanew;
		int* num;
	}Dos_Head;
	Dos_Head.e_lfanew = &dataBuffer[60];

	union {
		PE_FILE_HEADER* PeHeader;
		char* ntData;
	}Pe_NtHeader;

	Pe_NtHeader.ntData = &dataBuffer[*Dos_Head.num];

	if (strcmp(Pe_NtHeader.ntData, "PE") != 0) {
		fprintf(stderr, "Not a valid PE file\n");
		_getch();
		return EXIT_SUCCESS;
	}

	char* machineType = (char*)malloc(sizeof(char)*IMAGE_FILE_LEN);
	read_Machine_Type(Pe_NtHeader.PeHeader, machineType);
	
	int* characteristics = (int *)malloc(sizeof(DWORD) * 16);
	read_Characteristics(Pe_NtHeader.PeHeader, characteristics);

	time_t TimeDateStamp = (time_t)Pe_NtHeader.PeHeader->TimeDateStamp;

	printf("IMAGE_NT_HEADERS \n");
	printf("\t Signature:%s \n\n", Pe_NtHeader.ntData);
	printf("IMAGE_FILE_HEADER\n");
	printf("\t Machine:%s \n", machineType);
	printf("\t NumberOfSections:%d \n", Pe_NtHeader.PeHeader->NumberOfSections);
	printf("\t TimeDateStamp:%s", ctime(&TimeDateStamp));
	printf("\t SizeOfOptionalHeader:%d \n", Pe_NtHeader.PeHeader->SizeOfOptionalHeader);
	printf("\t Characteristics:\n");
	int machineResult = print_Characteristics(characteristics);

	printf("IMAGE_OPTIONAL_HEADER\n");
	if (machineResult == 1) //32bit
	{
		union 
		{
			PE_OPTIONAL_HEADER* PeOpHeader;
			char* ntData;
		}Pe_Optional;

		Pe_Optional.ntData = &dataBuffer[*Dos_Head.num + (24 * sizeof(char))];
		
		int* dllCharacteristics = (int*)malloc(sizeof(int) * 15);
		read_DllCharacteristics(Pe_Optional.PeOpHeader, dllCharacteristics);

		printf("\t Magic:IMAGE_NT_OPTIONAL_HDR32_MAGIC\n");
		printf("\t MajorLinkerVersion:%x\n", Pe_Optional.PeOpHeader->MajorLinkerVersion);
		printf("\t MinorLinkerVersion:%x\n", Pe_Optional.PeOpHeader->MinorLinkerVersion);
		printf("\t SizeOfCode:%d\n", Pe_Optional.PeOpHeader->SizeOfCode);
		printf("\t SizeOfInitializedData:%d\n", Pe_Optional.PeOpHeader->SizeOfInitializedData);
		printf("\t SizeOfUninitializedData:%d\n", Pe_Optional.PeOpHeader->SizeOfUninitializedData);
		printf("\t AddressOfEntryPoint:%x\n", Pe_Optional.PeOpHeader->AddressOfEntryPoint);
		printf("\t BaseOfCode:%#x\n", Pe_Optional.PeOpHeader->BaseOfCode);
		printf("\t BaseOfData:%#x\n", Pe_Optional.PeOpHeader->BaseOfData);
		printf("\t ImageBase:%#x\n", Pe_Optional.PeOpHeader->ImageBase);
		printf("\t SectionAlignment:%d\n", Pe_Optional.PeOpHeader->SectionAlignment);
		printf("\t FileAlignment:%d\n", Pe_Optional.PeOpHeader->FileAlignment);
		printf("\t MajorOperatingSystemVersion:%d\n", Pe_Optional.PeOpHeader->MajorOperatingSystemVersion);
		printf("\t MinorOperatingSystemVersion:%d\n", Pe_Optional.PeOpHeader->MinorOperatingSystemVersion);
		printf("\t MajorImageVersion:%d\n", Pe_Optional.PeOpHeader->MajorImageVersion);
		printf("\t MajorSubsystemVersion:%d\n", Pe_Optional.PeOpHeader->MajorSubsystemVersion);
		printf("\t MinorSubsystemVersion:%d\n", Pe_Optional.PeOpHeader->MinorSubsystemVersion);
		printf("\t Win32VersionValue:%d\n", Pe_Optional.PeOpHeader->Win32VersionValue);
		printf("\t SizeOfImage:%d\n", Pe_Optional.PeOpHeader->SizeOfImage);
		printf("\t SizeOfHeaders:%d\n", Pe_Optional.PeOpHeader->SizeOfHeaders);
		printf("\t CheckSum:%d\n", Pe_Optional.PeOpHeader->CheckSum);
		print_SubSystem(Pe_Optional.PeOpHeader);
		print_DllCharacteristics(dllCharacteristics);
		printf("\t SizeOfStackReserve:%d\n", Pe_Optional.PeOpHeader->SizeOfStackReserve);
		printf("\t SizeOfStackCommit:%d\n", Pe_Optional.PeOpHeader->SizeOfStackCommit);
		printf("\t SizeOfHeapReserve:%d\n", Pe_Optional.PeOpHeader->SizeOfHeapReserve);
		printf("\t SizeOfHeapCommit:%d\n", Pe_Optional.PeOpHeader->SizeOfHeapCommit);
		printf("\t LoaderFlags:%X\n", Pe_Optional.PeOpHeader->LoaderFlags);
		printf("\t NumberOfRvaAndSizes:%d\n", Pe_Optional.PeOpHeader->NumberOfRvaAndSizes);
		printf("\t DataDirectory:\n");
		printf("\t   ExportTable:\n");
		printf("\t     RVA:%#x\n", Pe_Optional.PeOpHeader->ExportTable.RVA);
		printf("\t     Size:%d\n", Pe_Optional.PeOpHeader->ExportTable.Size);
		printf("\t   Import Table:\n");
		printf("\t     RVA:%#x\n", Pe_Optional.PeOpHeader->ImportTable.RVA);
		printf("\t     Size:%d\n", Pe_Optional.PeOpHeader->ImportTable.Size);
		printf("\t   RESOURCE Table:\n");
		printf("\t     RVA:%#x\n", Pe_Optional.PeOpHeader->ResourceTable.RVA);
		printf("\t     Size:%d\n", Pe_Optional.PeOpHeader->ResourceTable.Size);
		printf("\t   EXCEPTION Table:\n");
		printf("\t     RVA:%#x\n", Pe_Optional.PeOpHeader->ExceptionTable.RVA);
		printf("\t     Size:%d\n", Pe_Optional.PeOpHeader->ExceptionTable.Size);
		printf("\t   CERTIFICATE Table:\n");
		printf("\t     RVA:%#x\n", Pe_Optional.PeOpHeader->CertificateTable.RVA);
		printf("\t     Size:%d\n", Pe_Optional.PeOpHeader->CertificateTable.Size);
		printf("\t   BASE RELOCATION Table:\n");
		printf("\t     RVA:%#x\n", Pe_Optional.PeOpHeader->BaseRelocationTable.RVA);
		printf("\t     Size:%d\n", Pe_Optional.PeOpHeader->BaseRelocationTable.Size);
		printf("\t   DEBUG Directory:\n");
		printf("\t     RVA:%#x\n", Pe_Optional.PeOpHeader->DebugTable.RVA);
		printf("\t     Size:%d\n", Pe_Optional.PeOpHeader->DebugTable.Size);
		printf("\t   Architecture Specific Data:\n");
		printf("\t     RVA:%#x\n", Pe_Optional.PeOpHeader->ArchitectureTable.RVA);
		printf("\t     Size:%d\n", Pe_Optional.PeOpHeader->ArchitectureTable.Size);
		printf("\t   GLOBAL POINTER Register:\n");
		printf("\t     RVA:%#x\n", Pe_Optional.PeOpHeader->GlobalTable.RVA);
		printf("\t     Size:%d\n", Pe_Optional.PeOpHeader->GlobalTable.Size);
		printf("\t   TLS Table:\n");
		printf("\t     RVA:%#x\n", Pe_Optional.PeOpHeader->ThreadTable.RVA);
		printf("\t     Size:%d\n", Pe_Optional.PeOpHeader->ThreadTable.Size);
		printf("\t   LOAD CONFIGURATION Table:\n");
		printf("\t     RVA:%#x\n", Pe_Optional.PeOpHeader->LoadTable.RVA);
		printf("\t     Size:%d\n", Pe_Optional.PeOpHeader->LoadTable.Size);
		printf("\t   BOUND IMPORT Table:\n");
		printf("\t     RVA:%#x\n", Pe_Optional.PeOpHeader->BoundTable.RVA);
		printf("\t     Size:%d\n", Pe_Optional.PeOpHeader->BoundTable.Size);
		printf("\t   IMPORT Address Table:\n");
		printf("\t     RVA:%#x\n", Pe_Optional.PeOpHeader->ImportAddressTable.RVA);
		printf("\t     Size:%d\n", Pe_Optional.PeOpHeader->ImportAddressTable.Size);
		printf("\t   DELAY IMPORT Descriptors:\n");
		printf("\t     RVA:%#x\n", Pe_Optional.PeOpHeader->DelayTable.RVA);
		printf("\t     Size:%d\n", Pe_Optional.PeOpHeader->DelayTable.Size);
		printf("\t   CLI Header:\n");
		printf("\t     RVA:%#x\n", Pe_Optional.PeOpHeader->CLRTable.RVA);
		printf("\t     Size:%d\n", Pe_Optional.PeOpHeader->CLRTable.Size);
		printf("\t   Reserved:\n");
		printf("\t     RVA:%#x\n", Pe_Optional.PeOpHeader->Reserved.RVA);
		printf("\t     Size:%d\n", Pe_Optional.PeOpHeader->Reserved.Size);
	}
	else if (machineResult == 0) //32bit Plus
	{
		union
		{
			PE_OPTIONAL_HEADER64* PeOpHeader64;
			char* ntData;
		}Pe_Optional;

		Pe_Optional.ntData = &dataBuffer[*Dos_Head.num + (24 * sizeof(char))];

		int* dllCharacteristics = (int*)malloc(sizeof(int) * 15);
		read_DllCharacteristicsPlus(Pe_Optional.PeOpHeader64, dllCharacteristics);

		printf("\t Magic:IMAGE_NT_OPTIONAL_HDR64_MAGIC\n");
		printf("\t MajorLinkerVersion:%x\n", Pe_Optional.PeOpHeader64->MajorLinkerVersion);
		printf("\t MinorLinkerVersion:%x\n", Pe_Optional.PeOpHeader64->MinorLinkerVersion);
		printf("\t SizeOfCode:%d\n", Pe_Optional.PeOpHeader64->SizeOfCode);
		printf("\t SizeOfInitializedData:%d\n", Pe_Optional.PeOpHeader64->SizeOfInitializedData);
		printf("\t SizeOfUninitializedData:%d\n", Pe_Optional.PeOpHeader64->SizeOfUninitializedData);
		printf("\t AddressOfEntryPoint:%x\n", Pe_Optional.PeOpHeader64->AddressOfEntryPoint);
		printf("\t BaseOfCode:%#x\n", Pe_Optional.PeOpHeader64->BaseOfCode);
		printf("\t BaseOfData:%#x\n", Pe_Optional.PeOpHeader64->BaseOfData);
		printf("\t ImageBase:%#x\n", Pe_Optional.PeOpHeader64->ImageBase);
		printf("\t SectionAlignment:%d\n", Pe_Optional.PeOpHeader64->SectionAlignment);
		printf("\t FileAlignment:%d\n", Pe_Optional.PeOpHeader64->FileAlignment);
		printf("\t MajorOperatingSystemVersion:%d\n", Pe_Optional.PeOpHeader64->MajorOperatingSystemVersion);
		printf("\t MinorOperatingSystemVersion:%d\n", Pe_Optional.PeOpHeader64->MinorOperatingSystemVersion);
		printf("\t MajorImageVersion:%d\n", Pe_Optional.PeOpHeader64->MajorImageVersion);
		printf("\t MajorSubsystemVersion:%d\n", Pe_Optional.PeOpHeader64->MajorSubsystemVersion);
		printf("\t MinorSubsystemVersion:%d\n", Pe_Optional.PeOpHeader64->MinorSubsystemVersion);
		printf("\t Win32VersionValue:%d\n", Pe_Optional.PeOpHeader64->Win32VersionValue);
		printf("\t SizeOfImage:%d\n", Pe_Optional.PeOpHeader64->SizeOfImage);
		printf("\t SizeOfHeaders:%d\n", Pe_Optional.PeOpHeader64->SizeOfHeaders);
		printf("\t CheckSum:%d\n", Pe_Optional.PeOpHeader64->CheckSum);
		print_SubSystemPlus(Pe_Optional.PeOpHeader64);
		print_DllCharacteristics(dllCharacteristics);
		printf("\t SizeOfStackReserve:%d\n", Pe_Optional.PeOpHeader64->SizeOfStackReserve);
		printf("\t SizeOfStackCommit:%d\n", Pe_Optional.PeOpHeader64->SizeOfStackCommit);
		printf("\t SizeOfHeapReserve:%d\n", Pe_Optional.PeOpHeader64->SizeOfHeapReserve);
		printf("\t SizeOfHeapCommit:%d\n", Pe_Optional.PeOpHeader64->SizeOfHeapCommit);
		printf("\t LoaderFlags:%X\n", Pe_Optional.PeOpHeader64->LoaderFlags);
		printf("\t NumberOfRvaAndSizes:%d\n", Pe_Optional.PeOpHeader64->NumberOfRvaAndSizes);
		printf("\t DataDirectory:\n");
		printf("\t   ExportTable:\n");
		printf("\t     RVA:%#x\n", Pe_Optional.PeOpHeader64->ExportTable.RVA);
		printf("\t     Size:%d\n", Pe_Optional.PeOpHeader64->ExportTable.Size);
		printf("\t   Import Table:\n");
		printf("\t     RVA:%#x\n", Pe_Optional.PeOpHeader64->ImportTable.RVA);
		printf("\t     Size:%d\n", Pe_Optional.PeOpHeader64->ImportTable.Size);
		printf("\t   RESOURCE Table:\n");
		printf("\t     RVA:%#x\n", Pe_Optional.PeOpHeader64->ResourceTable.RVA);
		printf("\t     Size:%d\n", Pe_Optional.PeOpHeader64->ResourceTable.Size);
		printf("\t   EXCEPTION Table:\n");
		printf("\t     RVA:%#x\n", Pe_Optional.PeOpHeader64->ExceptionTable.RVA);
		printf("\t     Size:%d\n", Pe_Optional.PeOpHeader64->ExceptionTable.Size);
		printf("\t   CERTIFICATE Table:\n");
		printf("\t     RVA:%#x\n", Pe_Optional.PeOpHeader64->CertificateTable.RVA);
		printf("\t     Size:%d\n", Pe_Optional.PeOpHeader64->CertificateTable.Size);
		printf("\t   BASE RELOCATION Table:\n");
		printf("\t     RVA:%#x\n", Pe_Optional.PeOpHeader64->BaseRelocationTable.RVA);
		printf("\t     Size:%d\n", Pe_Optional.PeOpHeader64->BaseRelocationTable.Size);
		printf("\t   DEBUG Directory:\n");
		printf("\t     RVA:%#x\n", Pe_Optional.PeOpHeader64->DebugTable.RVA);
		printf("\t     Size:%d\n", Pe_Optional.PeOpHeader64->DebugTable.Size);
		printf("\t   Architecture Specific Data:\n");
		printf("\t     RVA:%#x\n", Pe_Optional.PeOpHeader64->ArchitectureTable.RVA);
		printf("\t     Size:%d\n", Pe_Optional.PeOpHeader64->ArchitectureTable.Size);
		printf("\t   GLOBAL POINTER Register:\n");
		printf("\t     RVA:%#x\n", Pe_Optional.PeOpHeader64->GlobalTable.RVA);
		printf("\t     Size:%d\n", Pe_Optional.PeOpHeader64->GlobalTable.Size);
		printf("\t   TLS Table:\n");
		printf("\t     RVA:%#x\n", Pe_Optional.PeOpHeader64->ThreadTable.RVA);
		printf("\t     Size:%d\n", Pe_Optional.PeOpHeader64->ThreadTable.Size);
		printf("\t   LOAD CONFIGURATION Table:\n");
		printf("\t     RVA:%#x\n", Pe_Optional.PeOpHeader64->LoadTable.RVA);
		printf("\t     Size:%d\n", Pe_Optional.PeOpHeader64->LoadTable.Size);
		printf("\t   BOUND IMPORT Table:\n");
		printf("\t     RVA:%#x\n", Pe_Optional.PeOpHeader64->BoundTable.RVA);
		printf("\t     Size:%d\n", Pe_Optional.PeOpHeader64->BoundTable.Size);
		printf("\t   IMPORT Address Table:\n");
		printf("\t     RVA:%#x\n", Pe_Optional.PeOpHeader64->ImportAddressTable.RVA);
		printf("\t     Size:%d\n", Pe_Optional.PeOpHeader64->ImportAddressTable.Size);
		printf("\t   DELAY IMPORT Descriptors:\n");
		printf("\t     RVA:%#x\n", Pe_Optional.PeOpHeader64->DelayTable.RVA);
		printf("\t     Size:%d\n", Pe_Optional.PeOpHeader64->DelayTable.Size);
		printf("\t   CLI Header:\n");
		printf("\t     RVA:%#x\n", Pe_Optional.PeOpHeader64->CLRTable.RVA);
		printf("\t     Size:%d\n", Pe_Optional.PeOpHeader64->CLRTable.Size);
		printf("\t   Reserved:\n");
		printf("\t     RVA:%#x\n", Pe_Optional.PeOpHeader64->Reserved.RVA);
		printf("\t     Size:%d\n", Pe_Optional.PeOpHeader64->Reserved.Size);
	}

	printf("\nSectionHeaders\n");
	union {
		PE_SECTION_HEADER* PeSectionHead;
		char* ntData;
	}Pe_SectionHeader;

	if (machineResult == 1) { //32bit
		Pe_SectionHeader.ntData = &dataBuffer[*Dos_Head.num + sizeof(PE_FILE_HEADER) + sizeof(PE_OPTIONAL_HEADER)];
	}
	else if (machineResult == 0) { //32bitPlus
		Pe_SectionHeader.ntData = &dataBuffer[*Dos_Head.num + sizeof(PE_FILE_HEADER) + sizeof(PE_OPTIONAL_HEADER64)];
	}

	for (int i = 0; i < Pe_NtHeader.PeHeader->NumberOfSections; i++) {
		printf("\t Name:");
		union {
			LONG64* name;
			byte* seq;
		}name_seq;

		name_seq.name = &Pe_SectionHeader.PeSectionHead[i].Name;
		for (int j = 0; j < 8; j++)
			printf("%c", name_seq.seq[j]);
		printf("\n");

		printf("\t VirtualSize:%d\n", Pe_SectionHeader.PeSectionHead[i].VirtualSize);
		printf("\t VirtualAddress:%#x\n", Pe_SectionHeader.PeSectionHead[i].VirtualAddress);
		printf("\t SizeOfRawData:%d\n", Pe_SectionHeader.PeSectionHead[i].SizeOfRawData);
		printf("\t PointerToRawData:%#x\n", Pe_SectionHeader.PeSectionHead[i].PointerToRawData);
		printf("\t PointerToRelocations:%#x\n", Pe_SectionHeader.PeSectionHead[i].PointerToRelocations);
		printf("\t PointerToLinenumbers:%#x\n", Pe_SectionHeader.PeSectionHead[i].PointerToLinenumbers);
		printf("\t NumberOfRelocations:%d\n", Pe_SectionHeader.PeSectionHead[i].NumberOfRelocations);
		printf("\t NumberOfLinenumbers:%d\n", Pe_SectionHeader.PeSectionHead[i].NumberOfLinenumbers);
		printf("\t Characteristics:%X\n", Pe_SectionHeader.PeSectionHead[i].Characteristics);
		printf("\n");
	}

	_getch();
	return EXIT_SUCCESS;
}