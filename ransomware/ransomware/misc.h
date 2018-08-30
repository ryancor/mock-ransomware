#include <Windows.h>
#include <strsafe.h>
#include <string>
#include <iostream>

using namespace std;

#define SELF_DELETE		TEXT("cmd.exe /C ping 1.1.1.1 -n 1 -w 3000 > Nul & Del /f /q \"%s\"")

class Misc {
public:
	string current_working_directory();
	void CopyMyself();
};