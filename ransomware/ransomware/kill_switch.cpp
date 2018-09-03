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
		std::cout << GetLastError() << std::endl;
	}

	// TODO: finish the decrypting of files
	// TODO: Must reset ACLs before files can be opened again.
	// TODO: Replace file extensions to a signature .txt->.w4nnacry
	// TODO: Delete persistance file created
	return matches;
}