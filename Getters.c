#include "Getters.h"
#include "Analyzers.h"

DWORD RvaToFa(PIMAGE_DOS_HEADER DosHeader, DWORD Rva)
{
	PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)
		((PBYTE)DosHeader + DosHeader->e_lfanew);

	PIMAGE_SECTION_HEADER sectionHeader = (PIMAGE_SECTION_HEADER)
		((PBYTE)ntHeader + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + ntHeader->FileHeader.SizeOfOptionalHeader);

	for (int i = 0; i < ntHeader->FileHeader.NumberOfSections; i++)
	{
		if (sectionHeader[i].VirtualAddress <= Rva &&
			Rva < sectionHeader[i].VirtualAddress + sectionHeader[i].Misc.VirtualSize)
		{
			DWORD offset = Rva - sectionHeader[i].VirtualAddress;
			DWORD fileAddress = sectionHeader[i].PointerToRawData + offset;
			return fileAddress;
		}
	}
	return 0;
}

PIMAGE_EXPORT_DIRECTORY GetExportDirectory(PIMAGE_DOS_HEADER DosHeader)
{
	PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)
		((PBYTE)DosHeader + DosHeader->e_lfanew);

	PIMAGE_OPTIONAL_HEADER optionalHeader = (PIMAGE_OPTIONAL_HEADER)
		((PBYTE)ntHeader + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER));

	PIMAGE_OPTIONAL_HEADER64 optionalHeader64 = (PIMAGE_OPTIONAL_HEADER64)optionalHeader;

	PIMAGE_DATA_DIRECTORY exportDirective;

	if (optionalHeader->Magic == 0x20B) // for 64 bit PE files
	{
		exportDirective = optionalHeader64->DataDirectory;
	}
	else
	{
		exportDirective = optionalHeader->DataDirectory;
	}


	DWORD fileAddress = RvaToFa(DosHeader, exportDirective->VirtualAddress);
	if (fileAddress == 0)
	{
		return NULL;
	}

	PIMAGE_EXPORT_DIRECTORY exportDirectory = (PIMAGE_EXPORT_DIRECTORY)
		((PBYTE)DosHeader + fileAddress);
	return exportDirectory;
}

PIMAGE_IMPORT_DESCRIPTOR GetImportDescriptor(PIMAGE_DOS_HEADER DosHeader)
{
	PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)
		((PBYTE)DosHeader + DosHeader->e_lfanew);

	PIMAGE_OPTIONAL_HEADER optionalHeader = (PIMAGE_OPTIONAL_HEADER)
		((PBYTE)ntHeader + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER));

	PIMAGE_OPTIONAL_HEADER64 optionalHeader64 = (PIMAGE_OPTIONAL_HEADER64) optionalHeader;

	PIMAGE_DATA_DIRECTORY importDirectory;

	if (optionalHeader->Magic == 0x20B) // for 64 bit PE files
	{
		importDirectory = optionalHeader64->DataDirectory + 1;
	}
	else
	{
		importDirectory = optionalHeader->DataDirectory + 1;
	}


	DWORD fileAddress = RvaToFa(DosHeader, importDirectory->VirtualAddress);
	if (fileAddress == 0)
	{
		return NULL;
	}

	PIMAGE_IMPORT_DESCRIPTOR importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)
		((PBYTE)DosHeader + fileAddress);

	return importDescriptor;
}

PBYTE GetDllName(PIMAGE_DOS_HEADER DosHeader, PIMAGE_IMPORT_DESCRIPTOR ImportDescriptor)
{
	DWORD fileAddress = RvaToFa(DosHeader, ImportDescriptor->Name);
	if (fileAddress == 0)
	{
		return NULL;
	}
	PBYTE dllName = (PBYTE)((PBYTE)DosHeader + fileAddress);
	return dllName;
}

PBYTE GetFuncName64(PIMAGE_DOS_HEADER DosHeader, PIMAGE_THUNK_DATA64 ThunkData)
{
	ULONGLONG funcRva = ThunkData->u1.Function;

	if (funcRva >> 63 != 0)
	{
		return NULL;
	}

	DWORD funcRva32 = (DWORD) *((PDWORD)&funcRva);

	DWORD fileAddress = RvaToFa(DosHeader, funcRva32);
	if (fileAddress == 0)
	{
		return NULL;
	}

	PIMAGE_IMPORT_BY_NAME importStruct = (PIMAGE_IMPORT_BY_NAME)
		((PBYTE)DosHeader + fileAddress);

	PBYTE name = (PBYTE)importStruct->Name;
	return name;
}

PBYTE GetFuncName(PIMAGE_DOS_HEADER DosHeader, PIMAGE_THUNK_DATA ThunkData)
{
	DWORD funcRva = ThunkData->u1.Function;

	if (funcRva >> 31 != 0)
	{
		return NULL;
	}

	DWORD fileAddress = RvaToFa(DosHeader, funcRva);
	if (fileAddress == 0)
	{
		return NULL;
	}

	PIMAGE_IMPORT_BY_NAME importStruct = (PIMAGE_IMPORT_BY_NAME)
		((PBYTE)DosHeader + fileAddress);

	PBYTE name = (PBYTE)importStruct->Name;
	return name;
}

DWORD GetOrdinal(PIMAGE_THUNK_DATA ThunkData)
{
	if (ThunkData == NULL)
	{
		return 0;
	}
	DWORD funcRva = ThunkData->u1.Function;
	if (funcRva >> 31 != 0)
	{
		return funcRva & 0xFFFF;
	}
	return 0;
}

ULONGLONG GetOrdinal64(PIMAGE_THUNK_DATA64 ThunkData)
{
	if (ThunkData == NULL)
	{
		return 0;
	}
	ULONGLONG funcRva = ThunkData->u1.Function;
	
	if (funcRva >> 63 != 0)
	{
		return funcRva & 0xFFFF;
	}
	return 0;
}

#include <stdio.h>

PBYTE GetExportedFuncName(PIMAGE_DOS_HEADER DosHeader, PIMAGE_EXPORT_DIRECTORY ExportDirectory, DWORD FuncRva, PWORD NameOrdinal)
{
	DWORD fileAddress = RvaToFa(DosHeader, ExportDirectory->AddressOfFunctions);
	if (fileAddress == 0)
	{
		return (PBYTE)0xFFFFFFFF;
	}
	PDWORD funcArray = (PDWORD)
		((PBYTE)DosHeader + fileAddress);

	fileAddress = RvaToFa(DosHeader, ExportDirectory->AddressOfNames);
	if (fileAddress == 0)
	{
		return (PBYTE)0xFFFFFFFF;
	}
	PDWORD nameArray = (PDWORD)
		((PBYTE)DosHeader + fileAddress);

	fileAddress = RvaToFa(DosHeader, ExportDirectory->AddressOfNameOrdinals);
	if (fileAddress == 0)
	{
		return (PBYTE)0xFFFFFFFF;
	}
	PWORD nameOrdinalArray = (PWORD)
		((PBYTE)DosHeader + fileAddress);

	for (DWORD i = 0; i < ExportDirectory->NumberOfNames; i++)
	{
		WORD ordinal = nameOrdinalArray[i];
		if (FuncRva == funcArray[ordinal])
		{
			*NameOrdinal = ordinal;
			fileAddress = RvaToFa(DosHeader, nameArray[i]);
			if (fileAddress == 0)
			{
				return (PBYTE) 0xFFFFFFFF;
			}
			PBYTE nameAddress = (PBYTE)
				((PBYTE)DosHeader + fileAddress);
			return nameAddress;
		}
	}
	return NULL;
}