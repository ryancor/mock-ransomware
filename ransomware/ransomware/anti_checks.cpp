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
		wprintf(L"\n\n");
	}
}