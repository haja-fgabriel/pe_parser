#include "FileMapping.h"
#include <stdio.h>

int MapFile(char* FileName, PBYTE* MapResult, LPDWORD FileSize)
{
	int returnValue = 0;

	gFile = CreateFileA(
		FileName,
		GENERIC_READ,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);

	if (gFile == INVALID_HANDLE_VALUE)
	{
		returnValue = GetLastError();
		printf("Unexpected error: CreateFile failed with err-code 0x%X\n", returnValue);
		UnmapFile(*MapResult, gFileMapping, gFile);
	}
	gFileMapping = CreateFileMappingA(gFile, NULL, PAGE_READONLY, 0, 0, NULL);

	if (gFileMapping == NULL)
	{
		returnValue = GetLastError();
		printf("Unexpected error: CreateFileMappingA failed with err-code 0x%X\n", returnValue);
		UnmapFile(*MapResult, gFileMapping, gFile);
	}

	(*MapResult) = MapViewOfFile(gFileMapping, FILE_MAP_READ, 0, 0, 0);
	if ((*MapResult) == NULL)
	{
		returnValue = GetLastError();
		printf("Unexpected error: MapViewOfFile failed with err-code %X\n", returnValue);
		UnmapFile(*MapResult, gFileMapping, gFile);
	}

	*FileSize = GetFileSize(gFile, NULL);
	if (*FileSize == INVALID_FILE_SIZE)
	{
		*FileSize = 0;
		returnValue = INVALID_FILE_SIZE;
		UnmapFile(*MapResult, gFileMapping, gFile);
	}
	if (*FileSize < sizeof(IMAGE_DOS_HEADER))
	{
		returnValue = INVALID_FILE_SIZE;
		printf("Unexpected error: Invalid file size\n");
		UnmapFile(*MapResult, gFileMapping, gFile);
	}

	return returnValue;
}

void UnmapFile(PBYTE FileMapOnMemory, HANDLE FileMapping, HANDLE File)
{
	if (FileMapOnMemory != NULL)
	{
		UnmapViewOfFile(FileMapOnMemory);
	}

	if (FileMapping != NULL)
	{
		CloseHandle(FileMapping);
	}

	if (File != INVALID_HANDLE_VALUE)
	{
		CloseHandle(File);
	}
}
