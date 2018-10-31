#include <Windows.h>
#include <iphlpapi.h>
#include <iostream>

using namespace std;

const string listVmMacAddr[] = { "00:50:56", "00:0C:29", "00:05:69", "00:03:FF", "00:1C:42", "00:0F:4B", 
								 "00:16:3E", "08:00:27" };

class Check {
public:
	void Debugger();
	void VirtualMachine();
	void Sandbox();
private:
	char* getMAC();
};