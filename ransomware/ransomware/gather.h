#include <Windows.h>
#include <string>
#include <iostream>

using namespace std;

LPSTR FindDriveType(LPSTR lpdrv);

class Shared {
public:
	void GetDirs();
};
