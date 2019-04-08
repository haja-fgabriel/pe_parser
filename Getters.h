#pragma once

#include <Windows.h>

DWORD gFileSize;
PBYTE gFileBeginning;
BOOL gIs64Bit;

#define STRUCT_OFFSET(X) (DWORD) ((PBYTE) (X) - gFileBeginning)
#define STRUCT_FITS_IN_FILE(X)  (STRUCT_OFFSET(X) + sizeof( *(X) )  <= gFileSize )

DWORD RvaToFa(PIMAGE_DOS_HEADER DosHeader, DWORD Rva);

PIMAGE_EXPORT_DIRECTORY GetExportDirectory(PIMAGE_DOS_HEADER DosHeader);

PIMAGE_IMPORT_DESCRIPTOR GetImportDescriptor(PIMAGE_DOS_HEADER DosHeader);

PBYTE GetDllName(PIMAGE_DOS_HEADER DosHeader, PIMAGE_IMPORT_DESCRIPTOR ImportDescriptor);

PBYTE GetFuncName64(PIMAGE_DOS_HEADER DosHeader, PIMAGE_THUNK_DATA64 ThunkData);

PBYTE GetFuncName(PIMAGE_DOS_HEADER DosHeader, PIMAGE_THUNK_DATA ThunkData);

DWORD GetOrdinal(PIMAGE_THUNK_DATA ThunkData);

ULONGLONG GetOrdinal64(PIMAGE_THUNK_DATA64 ThunkData);

PBYTE GetExportedFuncName(PIMAGE_DOS_HEADER DosHeader, PIMAGE_EXPORT_DIRECTORY ExportDirectory, DWORD FuncRva, PWORD NameOrdinal);
