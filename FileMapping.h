#pragma once

#include <Windows.h>

static HANDLE gFile = INVALID_HANDLE_VALUE;
static HANDLE gFileMapping = NULL;

int MapFile(char * FileName, PBYTE * MapResult, LPDWORD FileSize);
void UnmapFile(PBYTE FileMapOnMemory, HANDLE FileMapping, HANDLE File);
