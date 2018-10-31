#include "anti_checks.h"

static size_t checkDbg_size(size_t val)
{
	return val;
}

void Check::Debugger()
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

void Check::VirtualMachine()
{
	unsigned int var = 0;

	__try
	{
		__asm
		{
			// save register values on the stack
			push	eax 
			push	ebx 
			push	ecx 
			push	edx

			// perform fingerprint
			mov     eax, 'VMXh' // VMware magic value (0x564D5868)
			mov     ecx, 14h	// get memory size command (0x14)
			mov     dx, 'VH'	// special VMware I/O port (0x5658)

			in      eax, dx     // special I/O cmd

			mov     var, eax    // data

			// restore register values from the stack
			pop     edx
			pop     ecx
			pop     ebx
			pop     eax
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {}

	std::cout << "[+] VMware \"get memory size\" command" << std::endl;

	if (var > 0)
	{
		std::cout << "Result  : VMware detected" << std::endl;
		exit(-1);
	}
	else {
		std::cout << "Result  : Native OS\n\n" << std::endl;
		// if failed to find VM, check for sandbox
		Sandbox();
	}
}

BOOL GetDriveGeometry(LPWSTR wszPath, DISK_GEOMETRY *pdg)
{
	HANDLE hDevice = INVALID_HANDLE_VALUE;
	BOOL bResult = FALSE;
	DWORD junk = 0;

	hDevice = CreateFileW(wszPath,
		0,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL,
		OPEN_EXISTING,
		0,
		NULL
	);

	if (hDevice == INVALID_HANDLE_VALUE)
	{
		return (FALSE);
	}

	bResult = DeviceIoControl(hDevice, // device to query
		IOCTL_DISK_GET_DRIVE_GEOMETRY, // ioctl code to perform
		NULL, 0,
		pdg, sizeof(*pdg),
		&junk,
		(LPOVERLAPPED)NULL
	);

	CloseHandle(hDevice);

	return (bResult);
}

void Check::Sandbox()
{
	DISK_GEOMETRY pdg = { 0 };
	BOOL bResult = FALSE;
	ULONGLONG DiskSize = 0; // size of drive in bytes
	const wchar_t* wszDrive = L"\\\\.\\PhysicalDrive0";

	bResult = GetDriveGeometry((LPWSTR)wszDrive, &pdg);

	if (bResult)
	{
		DiskSize = pdg.Cylinders.QuadPart * (ULONG)pdg.TracksPerCylinder *
			(ULONG)pdg.SectorsPerTrack * (ULONG)pdg.BytesPerSector;
		double DiskSizeGb = (double)DiskSize / (1024 * 1024 * 1024);
		wprintf(L"[+] PhysicalDisk0 size %.2f (Gb)\n", DiskSizeGb);
		
		if (DiskSize <= 100.51)
		{
			wprintf(L"[!] Physical Drive space too low... Sandbox Detected\n\n");
			exit(-1);
		} 
		else {
			char *macAddr = getMAC();
			// check if macAddress is size of 00:03:FF
			if (strlen(macAddr) <= 8)
			{
				// list of VM/sandbox company and products MAC identifiers
				for (int i = 0; i < sizeof(listVmMacAddr) / sizeof(listVmMacAddr[0]); i++)
				{
					std::cout << "[!] Comparing " << macAddr << " to " << listVmMacAddr[i].c_str() << std::endl;
					if (strncmp(macAddr, listVmMacAddr[i].c_str(), 8) == 0)
					{
						std::cout << "[!] MAC ID Found to be a VM or Sandbox: " << listVmMacAddr[i].c_str() << std::endl;
						exit(-1);
					}
				}
			}
			else {
				std::cout << "[+] MAC ID Checks out" << std::endl;
			}
		}
		wprintf(L"\n\n");
	}
}

char* Check::getMAC()
{
	PIP_ADAPTER_INFO AllAdapterInfo;
	DWORD dwBufLen = sizeof(IP_ADAPTER_INFO);
	char *macAddr = (char*)malloc(18);

	AllAdapterInfo = (IP_ADAPTER_INFO *)malloc(sizeof(IP_ADAPTER_INFO));
	if (AllAdapterInfo == NULL)
	{
		std::cout << "[-] GetAdapters Error: Unable to allocate to heap memory" << std::endl;
		free(macAddr);
		return NULL;
	}

	if (GetAdaptersInfo(AllAdapterInfo, &dwBufLen) == ERROR_BUFFER_OVERFLOW)
	{
		free(AllAdapterInfo);
		AllAdapterInfo = (IP_ADAPTER_INFO *)malloc(dwBufLen);
		if (AllAdapterInfo == NULL)
		{
			std::cout << "[-] GetAdapters Error: Unable to allocate to heap memory" << std::endl;
			free(macAddr);
			return NULL;
		}
	}

	if (GetAdaptersInfo(AllAdapterInfo, &dwBufLen) == NO_ERROR)
	{
		PIP_ADAPTER_INFO pAllAdapterInfo = AllAdapterInfo;
		do
		{
			sprintf(macAddr, "%02x:%02x:%02x:%02x:%02x:%02x", pAllAdapterInfo->Address[0], pAllAdapterInfo->Address[1],
				pAllAdapterInfo->Address[2], pAllAdapterInfo->Address[3], pAllAdapterInfo->Address[4],
				pAllAdapterInfo->Address[5]);
			std::cout << "[+] Address: " << pAllAdapterInfo->IpAddressList.IpAddress.String <<
				", MAC: " << macAddr << std::endl;
			pAllAdapterInfo = pAllAdapterInfo->Next;
		} while (pAllAdapterInfo);
	}
	free(AllAdapterInfo);
	return macAddr;
}