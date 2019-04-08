#pragma once
#include "Getters.h"
#include <Windows.h>


int AnalyzeDosHeader(PIMAGE_DOS_HEADER DosHeader);

int AnalyzeNtHeader(PIMAGE_NT_HEADERS NtHeader);

int AnalyzeFileHeader(PIMAGE_FILE_HEADER FileHeader);

int AnalyzeOptionalHeader(PIMAGE_OPTIONAL_HEADER OptionalHeader);

int AnalyzeSectionHeaders(PIMAGE_SECTION_HEADER SectionHeader, DWORD NumberOfSections);

int AnalyzeImportDescriptor(PIMAGE_DOS_HEADER DosHeader, PIMAGE_IMPORT_DESCRIPTOR ImportDescriptor);

int AnalyzeExportDirectory(PIMAGE_DOS_HEADER DosHeader, PIMAGE_EXPORT_DIRECTORY ExportDirectory);
