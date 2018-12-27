#ifndef UNICODE
#define UNICODE
#define UNICODE_WAS_UNDEFINED
#endif

#include <Windows.h>

#ifdef UNICODE_WAS_UNDEFINED
#undef UNICODE
#endif

#include <vector>
#include <fstream>
#include <string>
#include <iostream>
#include <tchar.h>

using namespace std;

vector<wstring> decrypt_files(wstring path);
void GetPrivsnDelete();
