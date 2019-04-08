#include "Analyzers.h"
#include <stdio.h>

int AnalyzeDosHeader(PIMAGE_DOS_HEADER DosHeader)
{
	if (!STRUCT_FITS_IN_FILE(DosHeader))
	{
		printf("Unexpected error: DosHeader too large to fit in file at offset %08X\n", STRUCT_OFFSET(DosHeader));
		return -1;
	}

	if (DosHeader->e_magic != 0x5A4D)
	{
		printf("Unexpected error: invalid magic number\n");
		return -1;
	}
	return 0;
}

int AnalyzeNtHeader(PIMAGE_NT_HEADERS NtHeader)
{
	if (!STRUCT_FITS_IN_FILE(NtHeader))
	{
		printf("Unexpected error: NtHeader too large to fit in file at offset %08X\n",  STRUCT_OFFSET(NtHeader));
		return -1;
	}

	if (NtHeader->Signature != 0x4550)
	{
		printf("Unexpected error: Invalid PE signature\n");
		return -1;
	}

	return 0;
}

int AnalyzeFileHeader(PIMAGE_FILE_HEADER FileHeader)
{
	if (!STRUCT_FITS_IN_FILE(FileHeader))
	{
		printf("Unexpected error: FileHeader too large to fit in file at offset %08X\n", STRUCT_OFFSET(FileHeader));
		return -1;
	}

	printf(
		"File Header:\n-Machine:%04X\n-NumberOfSections:%04X\n-Characteristics:%04X\n"
		, FileHeader->Machine
		, FileHeader->NumberOfSections
		, FileHeader->Characteristics
	);

	return 0;
}

int AnalyzeOptionalHeader(PIMAGE_OPTIONAL_HEADER OptionalHeader)
{
	if (!STRUCT_FITS_IN_FILE(OptionalHeader))
	{
		printf("Unexpected error: OptionalHeader too large to fit in file at offset %08X\n", STRUCT_OFFSET(OptionalHeader));
		return -1;
	}
	if (OptionalHeader->Magic == 0x20B) // it's a 64 bit PE file
	{
		PIMAGE_OPTIONAL_HEADER64 optionalHeader64 = (PIMAGE_OPTIONAL_HEADER64)OptionalHeader;
		if (!STRUCT_FITS_IN_FILE(optionalHeader64))
		{
			printf("Unexpected error: optionalHeader64 too large to fit in file at offset %08X\n", STRUCT_OFFSET(optionalHeader64));
			return -1;
		}
		gIs64Bit = TRUE;
		printf(
			"Optional Header:\n-AddressOfEntryPoint:%08X\n-ImageBase:%016llX\n-SectionAlignment:%08X\n-FileAlignment:%08X\n-Subsystem:%04X\n-NumberOfRvaAndSizes:%08X\n"
			, optionalHeader64->AddressOfEntryPoint
			, optionalHeader64->ImageBase
			, optionalHeader64->SectionAlignment
			, optionalHeader64->FileAlignment
			, optionalHeader64->Subsystem
			, optionalHeader64->NumberOfRvaAndSizes
		);
	}
	else if (OptionalHeader->Magic == 0x10B || OptionalHeader->Magic == 0x107)
	{
		printf(
			"Optional Header:\n-AddressOfEntryPoint:%08X\n-ImageBase:%08X\n-SectionAlignment:%08X\n-FileAlignment:%08X\n-Subsystem:%04X\n-NumberOfRvaAndSizes:%08X\n"
			, OptionalHeader->AddressOfEntryPoint
			, OptionalHeader->ImageBase
			, OptionalHeader->SectionAlignment
			, OptionalHeader->FileAlignment
			, OptionalHeader->Subsystem
			, OptionalHeader->NumberOfRvaAndSizes
		);
	}

	return 0;
}

int AnalyzeSectionHeaders(PIMAGE_SECTION_HEADER SectionHeader, DWORD NumberOfSections)
{
	printf("Sections:\n");
	if (SectionHeader == NULL)
	{
		printf("Unexpected error: invalid SectionHeader\n");
		return 0;
	}

	for (DWORD i = 0; i < NumberOfSections; i++)
	{
		if (!STRUCT_FITS_IN_FILE(SectionHeader + i))
		{
			printf("Unexpected error: SectionHeader[%d] too large to fit in file at offset %08X\n", i, STRUCT_OFFSET(SectionHeader+i));
			return -1;
		}
		char sectionName[9] = { 0 };
		DWORD size = SectionHeader[i].SizeOfRawData;
		DWORD fileAddress = SectionHeader[i].PointerToRawData;

		strcpy_s(sectionName, 9, (char*)SectionHeader[i].Name);

		printf("%s,%08X,%08X\n", sectionName, fileAddress, size);
	}
	return 0;
}

int AnalyzeImportDescriptor(PIMAGE_DOS_HEADER DosHeader, PIMAGE_IMPORT_DESCRIPTOR ImportDescriptor)
{
	if (DosHeader == NULL)
	{
		return 0;
	}

	printf("Imports:\n");
	if (ImportDescriptor == NULL)
	{
		printf("Unexpected error: invalid ImportDescriptor\n");
		return 0;
	}
	
	if (!STRUCT_FITS_IN_FILE(ImportDescriptor))
	{
		printf("Unexpected error: ImportDescriptor too large to fit in file at offset %08X\n", STRUCT_OFFSET(ImportDescriptor));
		return 0;
	}

	for (; ImportDescriptor->OriginalFirstThunk != 0 && ImportDescriptor->FirstThunk != 0; ImportDescriptor++)
	{
		if (!STRUCT_FITS_IN_FILE(ImportDescriptor))
		{
			printf("Unexpected error: ImportDescriptor too large to fit in file at offset %08X\n", STRUCT_OFFSET(ImportDescriptor));
			return -1;
		}

		char undefString[10] = "undef";

		PBYTE dllName = GetDllName(DosHeader, ImportDescriptor);
		if (dllName == NULL || !STRUCT_FITS_IN_FILE(dllName))
		{
			continue;
		}

		DWORD fileAddress = RvaToFa(DosHeader, ImportDescriptor->FirstThunk);
		if (fileAddress == 0)
		{
			continue;
		}

		if (gIs64Bit == FALSE)
		{
			PIMAGE_THUNK_DATA thunks = (PIMAGE_THUNK_DATA)
				((PBYTE)DosHeader + fileAddress);

			for (; thunks->u1.Function != 0; thunks++)
			{
				if (!STRUCT_FITS_IN_FILE(thunks))
				{
					printf("%s,undef\n", dllName);
					break;
				}
				PBYTE funcName = GetFuncName(DosHeader, thunks);
				if (funcName != NULL)
				{
					if (!STRUCT_FITS_IN_FILE(funcName))
					{
						funcName = (PBYTE) undefString;
					}
					printf("%s,%s\n", dllName, funcName);
				}
				else
				{
					printf("%s,%08X\n", dllName, GetOrdinal(thunks));
				}

			}
		}
		else
		{
			PIMAGE_THUNK_DATA64 thunks = (PIMAGE_THUNK_DATA64)
				((PBYTE)DosHeader + fileAddress);

			for (; thunks->u1.Function != 0; thunks++)
			{
				if (!STRUCT_FITS_IN_FILE(thunks))
				{
					printf("%s,undef\n", dllName);
					break;
				}
				PBYTE funcName = GetFuncName64(DosHeader, thunks);
				
				if (funcName != NULL)
				{
					if (STRUCT_FITS_IN_FILE(funcName))
					{
						printf("%s,%s\n", dllName, funcName);
					}
					else
					{
						printf("%s,undef\n", dllName);
					}
				}
				else
				{
					printf("%s,%016llX\n", dllName, GetOrdinal64(thunks));
				}

			}
		}
	}
	return 0;
}

int AnalyzeExportDirectory(PIMAGE_DOS_HEADER DosHeader, PIMAGE_EXPORT_DIRECTORY ExportDirectory)
{
	if (DosHeader == NULL)
	{
		return 0;
	}
	printf("Exports:\n");
	if (ExportDirectory == NULL)
	{
		printf("Unexpected error: invalid ExportDirectory\n");
		return 0;
	}
	if (!STRUCT_FITS_IN_FILE(ExportDirectory))
	{
		printf("Unexpected error: ExportDirectory too large to fit in file at offset %08X\n", STRUCT_OFFSET(ExportDirectory));
		return 0;
	}

	char emptyString[1] = { 0 };
	char fileAddressString[10] = { 0 };
	char undefString[10] = "undef";

	DWORD numberOfFunctions = ExportDirectory->NumberOfFunctions;

	DWORD fileAddress = RvaToFa(DosHeader, ExportDirectory->AddressOfFunctions);
	if (fileAddress == 0)
	{
		printf("Unexpected error: invalid RVA of Export Address Table (AddressOfFunctions) in ExportDirectory\n");
		return 0;
	}

	PDWORD funcArray = (PDWORD)
		((PBYTE)DosHeader + fileAddress);

	if (!STRUCT_FITS_IN_FILE(funcArray))
	{
		printf("Unexpected error: invalid offset of Export Address Table\n");
		return 0;
	}

	for (DWORD i = 0; i < numberOfFunctions; i++)
	{
		DWORD ordinal = ExportDirectory->Base + i;
		fileAddress = (DWORD)
			((PBYTE)DosHeader + RvaToFa(DosHeader, funcArray[ordinal]));
		
		if (fileAddress > (DWORD)DosHeader)
		{
			sprintf_s(fileAddressString, 10, "%08X", fileAddress);
		}
		else
		{
			sprintf_s(fileAddressString, 10, undefString);
		}

		WORD nameOrdinal;
		PBYTE nameAddress = GetExportedFuncName(DosHeader, ExportDirectory, funcArray[ordinal], &nameOrdinal);
		if ((DWORD)nameAddress == 0xFFFFFFFF || !STRUCT_FITS_IN_FILE(nameAddress))
		{
			nameAddress = (PBYTE)undefString;
		}
		else if (nameAddress == NULL)
		{	
			nameAddress = (PBYTE) emptyString;
		}

		printf("%s,%04hX,%s\n", nameAddress, nameOrdinal, fileAddressString);
	}

	return 0;
}