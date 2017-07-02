#ifndef __PE_HEADERS_H_
#define __PE_HEADERS_H_

#include<Windows.h>
#pragma warning(disable:4996)

#define PE_NUMBEROF_DIRECTORY_ENTRIES 17
#define IMAGE_FILE_LEN 30

typedef struct _PE_FILE_HEADER {
	DWORD Sig;
	WORD Machine;
	WORD NumberOfSections;
	DWORD TimeDateStamp;
	DWORD PointerToSymbolTable;
	DWORD NumberOfSymbols;
	WORD SizeOfOptionalHeader;
	WORD Characteristics;
}PE_FILE_HEADER;

typedef struct _PE_Data_Directory {
	DWORD RVA;
	DWORD Size;
}PE_Data_Directory;

typedef struct _PE_OPTIONAL_HEADER {
	// Standard fields.

	WORD    Magic;
	BYTE    MajorLinkerVersion;
	BYTE    MinorLinkerVersion;
	DWORD   SizeOfCode;
	DWORD   SizeOfInitializedData;
	DWORD   SizeOfUninitializedData;
	DWORD   AddressOfEntryPoint;
	DWORD   BaseOfCode;
	DWORD   BaseOfData;

	// NT additional fields.

	DWORD   ImageBase;
	DWORD   SectionAlignment;
	DWORD   FileAlignment;
	WORD    MajorOperatingSystemVersion;
	WORD    MinorOperatingSystemVersion;
	WORD    MajorImageVersion;
	WORD    MinorImageVersion;
	WORD    MajorSubsystemVersion;
	WORD    MinorSubsystemVersion;
	DWORD   Win32VersionValue;
	DWORD   SizeOfImage;
	DWORD   SizeOfHeaders;
	DWORD   CheckSum;
	WORD    Subsystem;
	WORD    DllCharacteristics;
	DWORD   SizeOfStackReserve;
	DWORD   SizeOfStackCommit;
	DWORD   SizeOfHeapReserve;
	DWORD   SizeOfHeapCommit;
	DWORD   LoaderFlags;
	DWORD   NumberOfRvaAndSizes;

	//DataDirectories
	PE_Data_Directory ExportTable;
	PE_Data_Directory ImportTable;
	PE_Data_Directory ResourceTable;
	PE_Data_Directory ExceptionTable;
	PE_Data_Directory CertificateTable;
	PE_Data_Directory BaseRelocationTable;
	PE_Data_Directory DebugTable;
	PE_Data_Directory ArchitectureTable;
	PE_Data_Directory GlobalTable;
	PE_Data_Directory ThreadTable;
	PE_Data_Directory LoadTable;
	PE_Data_Directory BoundTable;
	PE_Data_Directory ImportAddressTable;
	PE_Data_Directory DelayTable;
	PE_Data_Directory CLRTable;
	PE_Data_Directory Reserved;

}PE_OPTIONAL_HEADER;

typedef struct _PE_OPTINAL_HEADER64 {
	// Standard fields.

	WORD        Magic;
	BYTE        MajorLinkerVersion;
	BYTE        MinorLinkerVersion;
	DWORD       SizeOfCode;
	DWORD       SizeOfInitializedData;
	DWORD       SizeOfUninitializedData;
	DWORD       AddressOfEntryPoint;
	DWORD       BaseOfCode;
	DWORD       BaseOfData;

	// NT additional fields.

	ULONGLONG   ImageBase;
	DWORD       SectionAlignment;
	DWORD       FileAlignment;
	WORD        MajorOperatingSystemVersion;
	WORD        MinorOperatingSystemVersion;
	WORD        MajorImageVersion;
	WORD        MinorImageVersion;
	WORD        MajorSubsystemVersion;
	WORD        MinorSubsystemVersion;
	DWORD       Win32VersionValue;
	DWORD       SizeOfImage;
	DWORD       SizeOfHeaders;
	DWORD       CheckSum;
	WORD        Subsystem;
	WORD        DllCharacteristics;
	ULONGLONG   SizeOfStackReserve;
	ULONGLONG   SizeOfStackCommit;
	ULONGLONG   SizeOfHeapReserve;
	ULONGLONG   SizeOfHeapCommit;
	DWORD       LoaderFlags;
	DWORD       NumberOfRvaAndSizes;

	//DataDirectories
	PE_Data_Directory ExportTable;
	PE_Data_Directory ImportTable;
	PE_Data_Directory ResourceTable;
	PE_Data_Directory ExceptionTable;
	PE_Data_Directory CertificateTable;
	PE_Data_Directory BaseRelocationTable;
	PE_Data_Directory DebugTable;
	PE_Data_Directory ArchitectureTable;
	PE_Data_Directory GlobalTable;
	PE_Data_Directory ThreadTable;
	PE_Data_Directory LoadTable;
	PE_Data_Directory BoundTable;
	PE_Data_Directory ImportAddressTable;
	PE_Data_Directory DelayTable;
	PE_Data_Directory CLRTable;
	PE_Data_Directory Reserved;

}PE_OPTIONAL_HEADER64;

typedef struct _PE_SECTION_HEADER {
	LONG64 Name;
	DWORD VirtualSize;
	DWORD VirtualAddress;
	DWORD SizeOfRawData;
	DWORD PointerToRawData;
	DWORD PointerToRelocations;
	DWORD PointerToLinenumbers;
	WORD NumberOfRelocations;
	WORD NumberOfLinenumbers;
	DWORD Characteristics;
}PE_SECTION_HEADER;

void read_Machine_Type(PE_FILE_HEADER *PEFH, char* machine_Type);
void read_Characteristics(PE_FILE_HEADER *PEFH, int *characteristics);
int print_Characteristics(int* characteristics);
void print_SubSystem(PE_OPTIONAL_HEADER *PEOH);
void print_SubSystemPlus(PE_OPTIONAL_HEADER64 *PEOH64);
void read_DllCharacteristics(PE_OPTIONAL_HEADER *PEOH, int* dllCharacteristics);
void read_DllCharacteristicsPlus(PE_OPTIONAL_HEADER64 *PEOH64, int* dllCharacteristics);
void print_DllCharacteristics(int* dllCharacterisics);
#endif