#include "gather.h"

void Shared::GetDirs()
{
	DWORD dwMask = 1; // LSB is A: flag
	DWORD dwDrives = GetLogicalDrives();
	char strDrive[4] = { '\0' };
	char strDrivex[4] = { '\0' };
	string szMsg;

	// 26 letters in [A .. Z]
	for (int i = 0; i < 26; i++)
	{
		// Logically 'AND' the bitmask with 0x1. We get zero if its a valid drive
		if (dwDrives & dwMask)
		{
			wsprintfA((LPSTR)strDrive, "%c:\\", 'A' + i);
			wsprintfA((LPSTR)strDrivex, "%c:", 'A' + i);
			std::cout << "[+] Drive Found: " << strDrive << std::endl; // print out the driver letter
			szMsg = FindDriveType(strDrivex);
			std::cout << "[+] " << szMsg << std::endl;

			// Zero filling the buffer to prevent overwrite
			for (int j = 0; j < 4; j++)
			{
				strDrive[j] = '\0';
			}
		}
		dwMask <<= 1;
	}
}

LPSTR FindDriveType(LPSTR lpdrv)
{
	UINT drvType;
	char szMsg[150];

	drvType = GetDriveType(lpdrv);

	switch (drvType)
	{
	case DRIVE_UNKNOWN:
		wsprintf(szMsg, "Drive %s is of unknown type", lpdrv);
		break;
	case DRIVE_NO_ROOT_DIR:
		wsprintf(szMsg, "Drive %s is invalid", lpdrv);
		break;
	case DRIVE_REMOVABLE:
		wsprintf(szMsg, "Drive %s is a removable drive", lpdrv);
		break;
	case DRIVE_FIXED:
		wsprintf(szMsg, "Drive %s is a hard disk", lpdrv);
		break;
	case DRIVE_REMOTE:
		wsprintf(szMsg, "Drive %s is a network drive", lpdrv);
		break;
	case DRIVE_CDROM:
		wsprintf(szMsg, "Drive %s is a CD-ROM drive", lpdrv);
		break;
	case DRIVE_RAMDISK:
		wsprintf(szMsg, "Drive %s is a RAM disk", lpdrv);
		break;
	default:
		wsprintf(szMsg, "Drive %s is of unknown type", lpdrv);
		break;
	}
	return szMsg;
}