#include "InjectionHandler.h"

W::HANDLE injectionTarget = NULL;
map <const char *, int> counterOfUsedAPIs; // Counter of APIs used for Process Injection

/*
	Create the process where the injection will be redirected
*/
void createInjectionTargetProcess(string processName)
{
	W::WinExec(processName.c_str(), 2);
}
/* 
	Find the process where the injection will be redirected
*/
bool findInjectionTargetProcess(string processName)
{
	W::PROCESSENTRY32 processInfo;
	processInfo.dwSize = sizeof(processInfo);
	DWORD processPid;

	/* Find process PID inside the currently active processes */
	HANDLE processesSnapshot = W::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (processesSnapshot == INVALID_HANDLE_VALUE) {
		return false;
	}

	W::Process32First(processesSnapshot, &processInfo);
	if (!processName.compare(processInfo.szExeFile))
	{
		processPid = processInfo.th32ProcessID;
	}
	else {
		while (W::Process32Next(processesSnapshot, &processInfo))
		{
			if (!processName.compare(processInfo.szExeFile))
			{
				processPid = processInfo.th32ProcessID;
				break;
			}
		}
		W::CloseHandle(processesSnapshot);
		return false;
	}

	W::CloseHandle(processesSnapshot);
	
	/* Get an handle to the process */
	injectionTarget = W::OpenProcess(PROCESS_ALL_ACCESS, false, processPid);

	if (injectionTarget == NULL)
		return false;

	return true;
}

/*
	check if the given address is the address of kernel32.LoadLibrary
	inside the target process
*/
bool isRemoteLoadLibraryAddress(ADDRINT address)
{
	return false;
}
