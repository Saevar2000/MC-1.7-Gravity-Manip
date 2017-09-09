#include <Windows.h>
#include <iostream>
#include <string>
#include <vector>
#include "inttypes.h"
#include "process.h"
#include "patternscan.h"
#include "globals.h"


int main()
{	
	// Get Process ID by enumerating the processes using tlhelp32snapshot
	DWORD processID = GetProcID(L"javaw.exe");
	// Get handle by OpenProcess
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, processID);

	
	// PatternScan. You need to be on the ground for it to work.
	PatternScanEx(hProcess, 0xCC000000, 0xCFFFFFFF, "\x29\x5c\x8f\xc2\x05\x12\xb4", "xxxxxxx");

	// PatternScan Results
	double amount = 1;
	for (int i = 0; i < 256; i++) {
			if (patternMatches[i] == NULL) {
				std::cout << "Found " << i+1 <<" possible matches\n";
				break;
			}
			double *j;
			j = patternMatches[i];
			// WriteProcessMemory(hProcess, (LPVOID)j, &amount, sizeof(double), NULL);
			std::cout << j << '\n';	
		}

	// Fly
	while (1) {
		if (GetAsyncKeyState(VK_F4) & 1) {
			for (int i = 0; i < 256; i++) {
				if (patternMatches[i] == NULL) {
					std::cout << "Fly\n";
					break;
				}
				double *j;
				j = patternMatches[i];
				WriteProcessMemory(hProcess, (LPVOID)j, &amount, sizeof(double), NULL);
			}
		}
	}
	std::cin.get();
	CloseHandle(hProcess);

	return  0;
}