#include "patternscan.h"
#include "globals.h"
#include <iostream>
#include <string>

// Internal Pattern Scan
void * PatternScan(char* base, size_t size, char* pattern, char* mask)
{
	size_t patternLength = strlen(mask);

	for (unsigned int i = 0; i < size - patternLength; i++)
	{
		bool found = true;
		for (unsigned int j = 0; j < patternLength; j++)
		{
			if (mask[j] != '?' && pattern[j] != *(base + i + j))
			{
				found = false;
				break;
			}

		}
		if (found)
		{
			return (void*)(base + i);
		}
	}
	return nullptr;
}

// External Wrapper
void * PatternScanEx(HANDLE hProcess, uintptr_t begin, uintptr_t end, char* pattern, char*  mask)
{
	const double gravity = 1;
	unsigned int counter = 0;
	uintptr_t currentChunk = begin;
	SIZE_T bytesRead;

	while (currentChunk < end)
	{
		char buffer[4096];

		DWORD oldprotect;
		VirtualProtectEx(hProcess, (void*)currentChunk, sizeof(buffer), PAGE_EXECUTE_READWRITE, &oldprotect);
		ReadProcessMemory(hProcess, (void*)currentChunk, &buffer, sizeof(buffer), &bytesRead);
		VirtualProtectEx(hProcess, (void*)currentChunk, sizeof(buffer), oldprotect, NULL);

		if (bytesRead == 0)
		{
			return nullptr;
		}

		void* internalAddress = PatternScan((char*)&buffer, bytesRead, pattern, mask);

		if (internalAddress != nullptr)
		{
			// calculate from internal to external
				uintptr_t offsetFromBuffer = (uintptr_t)internalAddress - (uintptr_t)&buffer;
				patternMatches[counter] = (double*)(offsetFromBuffer + currentChunk);
				// std::cout << patternMatches[counter] << '\n';
				counter++;
				// advance to next chunk
				currentChunk = currentChunk + bytesRead;
				// return (void*)(currentChunk + offsetFromBuffer);
		} else {
			// advance to next chunk
			currentChunk = currentChunk + bytesRead;
		}
	}
	return 0;
}

// Module wrapper for external pattern scan
void * PatternScanExModule(HANDLE hProcess, wchar_t * exeName, wchar_t* module, char* pattern, char* mask)
{
	DWORD processID = GetProcID(exeName);
	MODULEENTRY32 modEntry = GetModule(processID, module);

	if (!modEntry.th32ModuleID)
	{
		return nullptr;
	}

	uintptr_t begin = (uintptr_t)modEntry.modBaseAddr;
	uintptr_t end = begin + modEntry.modBaseSize;
	return PatternScanEx(hProcess, begin, end, pattern, mask);
}