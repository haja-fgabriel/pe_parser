#include <stdio.h>
#include <windows.h>

#include "FileMapping.h"
#include "Analyzers.h"
#include "Getters.h"


int main(int argc, char** argv)
{
	if (argc != 2)
	{
		printf("Unexpected error: invalid argument count! Type \"%s file_name\"\n", argv[0]);
		return -1;
	}

	PBYTE fileMap;
	
	int retVal = MapFile(argv[1], &fileMap, &gFileSize);
	if (retVal != 0)
	{
		printf("Unexpected error: MapFile failed with err-code %08X\n", retVal);
		return retVal;
	}
	gFileBeginning = fileMap;
	
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)fileMap;


	retVal = AnalyzeDosHeader(dosHeader);
	if (retVal != 0)
	{
		printf("Unexpected error: AnalyzeDosHeader failed with err-code %08X\n", retVal);
		goto cleanup;
	}

	PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)(fileMap + dosHeader->e_lfanew);
	retVal = AnalyzeNtHeader(ntHeader);
	if (retVal != 0)
	{
		printf("Unexpected error: AnalyzeNtHeader failed with err-code %08X\n", retVal);
		goto cleanup;
	}

	PIMAGE_FILE_HEADER fileHeader = (PIMAGE_FILE_HEADER)
		((PBYTE)ntHeader + sizeof(DWORD));
	retVal = AnalyzeFileHeader(fileHeader);
	if (retVal != 0)
	{
		printf("Unexpected error: AnalyzeFileHeader failed with err-code %08X\n", retVal);
		goto cleanup;
	}

	PIMAGE_OPTIONAL_HEADER optionalHeader = (PIMAGE_OPTIONAL_HEADER)
		((PBYTE)ntHeader + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER));
	retVal = AnalyzeOptionalHeader(optionalHeader);
	if (retVal != 0)
	{
		printf("Unexpected error: AnalyzeOptionalHeader failed with err-code %08X\n", retVal);
		goto cleanup;
	}

	PIMAGE_SECTION_HEADER sectionHeader = (PIMAGE_SECTION_HEADER)
		((PBYTE)fileHeader + sizeof(IMAGE_FILE_HEADER) + fileHeader->SizeOfOptionalHeader);
	DWORD numberOfSections = fileHeader->NumberOfSections;
	
	retVal = AnalyzeSectionHeaders(sectionHeader, numberOfSections);
	if (retVal != 0)
	{
		printf("Unexpected error: AnalyzeSectionHeaders failed with err-code %08X\n", retVal);
		goto cleanup;
	}

	PIMAGE_EXPORT_DIRECTORY exportDirectory = GetExportDirectory(dosHeader);
	retVal = AnalyzeExportDirectory(dosHeader, exportDirectory);
	if (retVal != 0)
	{
		printf("Unexpected error: AnalyzeExportDirectory failed with err-code %08X\n", retVal);
		goto cleanup;
	}
	

	PIMAGE_IMPORT_DESCRIPTOR importDescriptor = GetImportDescriptor(dosHeader);

	retVal = AnalyzeImportDescriptor(dosHeader, importDescriptor);
	if (retVal != 0)
	{
		printf("Unexpected error: AnalyzeImportDescriptor failed with err-code %08X\n", retVal);
		goto cleanup;
	}

	

cleanup:

	UnmapFile(fileMap, gFileMapping, gFile);

	return 0;
}