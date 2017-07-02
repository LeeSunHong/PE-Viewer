#include <math.h>
#include "PEHeaders.h"

void read_Machine_Type(PE_FILE_HEADER *PEFH, char* machine_Type) {
	switch (PEFH->Machine)
	{
	case IMAGE_FILE_MACHINE_UNKNOWN:
		strcpy(machine_Type, "IMAGE_FILE_MACHINE_UNKOWN");
		break;
	case IMAGE_FILE_MACHINE_I386:
		strcpy(machine_Type, "IMAGE_FILE_MACHINE_I386");
		break;
	case IMAGE_FILE_MACHINE_R3000:
		strcpy(machine_Type, "IMAGE_FILE_MACHINE_R3000");
		break;
	case IMAGE_FILE_MACHINE_R4000:
		strcpy(machine_Type, "IMAGE_FILE_MACHINE_R4000");
		break;
	case IMAGE_FILE_MACHINE_R10000:
		strcpy(machine_Type, "IMAGE_FILE_MACHINE_R10000");
		break;
	case IMAGE_FILE_MACHINE_WCEMIPSV2:
		strcpy(machine_Type, "IMAGE_FILE_MACHINE_WCEMIPSV2");
		break;
	case IMAGE_FILE_MACHINE_ALPHA:
		strcpy(machine_Type, "IMAGE_FILE_MACHINE_ALPHA");
		break;
	case IMAGE_FILE_MACHINE_POWERPC:
		strcpy(machine_Type, "IMAGE_FILE_MACHINE_POWERPC");
		break;
	case IMAGE_FILE_MACHINE_SH3:
		strcpy(machine_Type, "IMAGE_FILE_MACHINE_SH3");
		break;
	case IMAGE_FILE_MACHINE_SH3E:
		strcpy(machine_Type, "IMAGE_FILE_MACHINE_SH3E");
		break;
	case IMAGE_FILE_MACHINE_SH4:
		strcpy(machine_Type, "IMAGE_FILE_MACHINE_SH4");
		break;
	case IMAGE_FILE_MACHINE_ARM:
		strcpy(machine_Type, "IMAGE_FILE_MACHINE_ARM");
		break;
	case IMAGE_FILE_MACHINE_THUMB:
		strcpy(machine_Type, "IMAGE_FILE_MACHINE_THUMB");
		break;
	case IMAGE_FILE_MACHINE_IA64:
		strcpy(machine_Type, "IMAGE_FILE_MACHINE_IA64");
		break;
	case IMAGE_FILE_MACHINE_MIPS16:
		strcpy(machine_Type, "IMAGE_FILE_MACHINE_MIPS16");
		break;
	case IMAGE_FILE_MACHINE_MIPSFPU:
		strcpy(machine_Type, "IMAGE_FILE_MACHINE_MIPSFPU");
		break;
	case IMAGE_FILE_MACHINE_MIPSFPU16:
		strcpy(machine_Type, "IMAGE_FILE_MACHINE_MIPSFPU16");
		break;
	case IMAGE_FILE_MACHINE_ALPHA64:
		strcpy(machine_Type, "IMAGE_FILE_MACHINE_ALPHA64");
		break;
	default:
		strcpy(machine_Type, " ", strlen(" "));
		break;
	}
}

void read_Characteristics(PE_FILE_HEADER *PEFH, int *characteristics) {
	for (int i = 0; i < 16; i++) {
		if ((PEFH->Characteristics & (1 << i)) == 1 << i) {
			characteristics[i] = 1;
		}
	}
}

int print_Characteristics(int* characteristics) {
	int result = 0;

	if (characteristics[(int)log2(IMAGE_FILE_RELOCS_STRIPPED)] == 1)
	{
		printf("\t IMAGE_FILE_RELOCS_STRIPPED \n");
	}

	if (characteristics[(int)log2(IMAGE_FILE_EXECUTABLE_IMAGE)] == 1)
	{
		printf("\t IMAGE_FILE_EXECUTABLE_IMAGE \n");
	}

	if (characteristics[(int)log2(IMAGE_FILE_LINE_NUMS_STRIPPED)] == 1)
	{
		printf("\t IMAGE_FILE_LINE_NUMS_STRIPPED \n");
	}

	if (characteristics[(int)log2(IMAGE_FILE_LOCAL_SYMS_STRIPPED)] == 1)
	{
		printf("\t IMAGE_FILE_LOCAL_SYMS_STRIPPED \n");
	}

	if (characteristics[(int)log2(IMAGE_FILE_AGGRESIVE_WS_TRIM)] == 1)
	{
		printf("\t IMAGE_FILE_AGGRESIVE_WS_TRIM \n");
	}

	if (characteristics[(int)log2(IMAGE_FILE_LARGE_ADDRESS_AWARE)] == 1)
	{
		printf("\t IMAGE_FILE_LARGE_ADDRESS_AWARE \n");
	}

	if (characteristics[(int)log2(IMAGE_FILE_BYTES_REVERSED_LO)] == 1)
	{
		printf("\t IMAGE_FILE_BYTES_REVERSED_LO \n");
	}

	if (characteristics[(int)log2(IMAGE_FILE_32BIT_MACHINE)] == 1)
	{
		result = 1;
		printf("\t IMAGE_FILE_32BIT_MACHINE \n");
	}

	if (characteristics[(int)log2(IMAGE_FILE_DEBUG_STRIPPED)] == 1)
	{
		printf("\t IMAGE_FILE_DEBUG_STRIPPED \n");
	}

	if (characteristics[(int)log2(IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP)] == 1)
	{
		printf("\t IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP \n");
	}

	if (characteristics[(int)log2(IMAGE_FILE_NET_RUN_FROM_SWAP)] == 1)
	{
		printf("\t IMAGE_FILE_NET_RUN_FROM_SWAP \n");
	}

	if (characteristics[(int)log2(IMAGE_FILE_SYSTEM)] == 1)
	{
		printf("\t IMAGE_FILE_SYSTEM \n");
	}

	if (characteristics[(int)log2(IMAGE_FILE_DLL)] == 1)
	{
		printf("\t IMAGE_FILE_DLL \n");
	}

	if (characteristics[(int)log2(IMAGE_FILE_UP_SYSTEM_ONLY)] == 1)
	{
		printf("\t IMAGE_FILE_UP_SYSTEM_ONLY \n");
	}

	if (characteristics[(int)log2(IMAGE_FILE_BYTES_REVERSED_HI)] == 1)
	{
		printf("\t IMAGE_FILE_BYTES_REVERSED_HI \n");
	}

	printf("\n");
	return result;
}

void print_SubSystem(PE_OPTIONAL_HEADER *PEOH) {
	switch (PEOH->Subsystem) {
	case IMAGE_SUBSYSTEM_UNKNOWN:
		printf("\t Subsystem:IMAGE_SUBSYSTEM_UNKNOWN\n");
		break;
	case IMAGE_SUBSYSTEM_NATIVE:
		printf("\t Subsystem:IMAGE_SUBSYSTEM_NATIVE\n");
		break;
	case IMAGE_SUBSYSTEM_WINDOWS_GUI:
		printf("\t Subsystem:IMAGE_SUBSYSTEM_WINDOWS_GUI\n");
		break;
	case IMAGE_SUBSYSTEM_WINDOWS_CUI:
		printf("\t Subsystem:IMAGE_SUBSYSTEM_WINDOWS_CUI\n");
		break;
	case IMAGE_SUBSYSTEM_OS2_CUI:
		printf("\t Subsystem:IMAGE_SUBSYSTEM_OS2_CUI\n");
		break;
	case IMAGE_SUBSYSTEM_POSIX_CUI:
		printf("\t Subsystem:IMAGE_SUBSYSTEM_POSIX_CUI\n");
		break;
	case IMAGE_SUBSYSTEM_WINDOWS_CE_GUI:
		printf("\t Subsystem:IMAGE_SUBSYSTEM_WINDOWS_CE_GUI\n");
		break;
	case IMAGE_SUBSYSTEM_EFI_APPLICATION:
		printf("\t Subsystem:IMAGE_SUBSYSTEM_EFI_APPLICATION\n");
		break;
	case IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER:
		printf("\t Subsystem:IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER\n");
		break;
	case IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER:
		printf("\t Subsystem:IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER\n");
		break;
	case IMAGE_SUBSYSTEM_EFI_ROM:
		printf("\t Subsystem:IMAGE_SUBSYSTEM_EFI_ROM\n");
		break;
	case IMAGE_SUBSYSTEM_XBOX:
		printf("\t Subsystem:IMAGE_SUBSYSTEM_XBOX\n");
		break;
	case IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION:
		printf("\t Subsystem:IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION\n");
		break;
	default: printf(" ");
		break;
	}
}

void print_SubSystemPlus(PE_OPTIONAL_HEADER64 *PEOH64) {
	switch (PEOH64->Subsystem) {
	case IMAGE_SUBSYSTEM_UNKNOWN:
		printf("\t Subsystem:IMAGE_SUBSYSTEM_UNKNOWN\n");
		break;
	case IMAGE_SUBSYSTEM_NATIVE:
		printf("\t Subsystem:IMAGE_SUBSYSTEM_NATIVE\n");
		break;
	case IMAGE_SUBSYSTEM_WINDOWS_GUI:
		printf("\t Subsystem:IMAGE_SUBSYSTEM_WINDOWS_GUI\n");
		break;
	case IMAGE_SUBSYSTEM_WINDOWS_CUI:
		printf("\t Subsystem:IMAGE_SUBSYSTEM_WINDOWS_CUI\n");
		break;
	case IMAGE_SUBSYSTEM_OS2_CUI:
		printf("\t Subsystem:IMAGE_SUBSYSTEM_OS2_CUI\n");
		break;
	case IMAGE_SUBSYSTEM_POSIX_CUI:
		printf("\t Subsystem:IMAGE_SUBSYSTEM_POSIX_CUI\n");
		break;
	case IMAGE_SUBSYSTEM_WINDOWS_CE_GUI:
		printf("\t Subsystem:IMAGE_SUBSYSTEM_WINDOWS_CE_GUI\n");
		break;
	case IMAGE_SUBSYSTEM_EFI_APPLICATION:
		printf("\t Subsystem:IMAGE_SUBSYSTEM_EFI_APPLICATION\n");
		break;
	case IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER:
		printf("\t Subsystem:IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER\n");
		break;
	case IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER:
		printf("\t Subsystem:IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER\n");
		break;
	case IMAGE_SUBSYSTEM_EFI_ROM:
		printf("\t Subsystem:IMAGE_SUBSYSTEM_EFI_ROM\n");
		break;
	case IMAGE_SUBSYSTEM_XBOX:
		printf("\t Subsystem:IMAGE_SUBSYSTEM_XBOX\n");
		break;
	case IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION:
		printf("\t Subsystem:IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION\n");
		break;
	default: printf(" ");
		break;
	}
}

void read_DllCharacteristics(PE_OPTIONAL_HEADER *PEOH, int* dllCharacteristics) {
	for (int i = 0; i < 15; i++) {
		if ((PEOH->DllCharacteristics & (1 << i)) == 1 << i)
			dllCharacteristics[i] = 1;
	}
}

void read_DllCharacteristicsPlus(PE_OPTIONAL_HEADER64 *PEOH64, int* dllCharacteristics) {
	for (int i = 0; i < 15; i++) {
		if ((PEOH64->DllCharacteristics & (1 << i)) == 1 << i)
			dllCharacteristics[i] = 1;
	}
}

void print_DllCharacteristics(int* dllCharacterisics) {
	printf("\t DllCharacteristics:\n");
	if (dllCharacterisics[(int)log2(0x0001)] == 1) {
		printf("\t Reserved\n");
	}
	if (dllCharacterisics[(int)log2(0x0002)] == 1) {
		printf("\t Reserved\n");
	}
	if (dllCharacterisics[(int)log2(0x0004)] == 1) {
		printf("\t Reserved\n");
	}
	if (dllCharacterisics[(int)log2(0x0008)] == 1) {
		printf("\t Reserved\n");
	}
	if (dllCharacterisics[(int)log2(IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE)] == 1) {
		printf("\t IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE\n");
	}
	if (dllCharacterisics[(int)log2(IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY)] == 1) {
		printf("\t IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY\n");
	}
	if (dllCharacterisics[(int)log2(IMAGE_DLLCHARACTERISTICS_NX_COMPAT)] == 1) {
		printf("\t IMAGE_DLLCHARACTERISTICS_NX_COMPAT\n");
	}
	if (dllCharacterisics[(int)log2(IMAGE_DLLCHARACTERISTICS_NO_ISOLATION)] == 1) {
		printf("\t IMAGE_DLLCHARACTERISTICS_NO_ISOLATION\n");
	}
	if (dllCharacterisics[(int)log2(IMAGE_DLLCHARACTERISTICS_NO_SEH)] == 1) {
		printf("\t IMAGE_DLLCHARACTERISTICS_NO_SEHN\n");
	}
	if (dllCharacterisics[(int)log2(IMAGE_DLLCHARACTERISTICS_NO_BIND)] == 1) {
		printf("\t IMAGE_DLLCHARACTERISTICS_NO_BIND\n");
	}
	if (dllCharacterisics[(int)log2(0x1000)] == 1) {
		printf("\t Reserved\n");
	}
	if (dllCharacterisics[(int)log2(IMAGE_DLLCHARACTERISTICS_WDM_DRIVER)] == 1) {
		printf("\t IMAGE_DLLCHARACTERISTICS_WDM_DRIVER\n");
	}
	if (dllCharacterisics[(int)log2(0x4000)] == 1) {
		printf("\t Reserved\n");
	}
	if (dllCharacterisics[(int)log2(IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE)] == 1) {
		printf("\t IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE\n");
	}
}

