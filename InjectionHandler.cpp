#include "InjectionHandler.h"

W::HANDLE hInjectionTarget = NULL;
map <const char *, int> counterOfUsedAPIs; // Counter of APIs used for Process Injection
vector <pair <W::DWORD, W::SIZE_T>> remoteAllocatedMemory; 

/*
	Create the process where the injection will be redirected
*/
void createInjectionTargetProcess(string processName)
{
	// Create the new process
	W::PROCESS_INFORMATION ProcessInfo; 

	W::STARTUPINFO StartupInfo; 
	ZeroMemory(&StartupInfo, sizeof(StartupInfo));
	StartupInfo.cb = sizeof(StartupInfo);

	if (!CreateProcessA(processName.c_str(), NULL, NULL, NULL, FALSE, 0, NULL,
		NULL, &StartupInfo, &ProcessInfo))
		return;
	
	hInjectionTarget = ProcessInfo.hProcess;
	DEBUG("Injection target correctly created: %s", processName.c_str());

}
/* 
	Find the process where the injection will be redirected
*/
bool findInjectionTargetProcess(string processName)
{
	W::PROCESSENTRY32 processInfo;
	processInfo.dwSize = sizeof(processInfo);
	W::DWORD processPid = NULL;

	/* Find process PID inside the currently active processes */
	W::HANDLE processesSnapshot = W::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

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
		
	}
	W::CloseHandle(processesSnapshot);

	if (processPid == NULL)
		return false;
	
	/* Get an handle to the process */
	hInjectionTarget = W::OpenProcess(PROCESS_ALL_ACCESS, false, processPid);

	if (hInjectionTarget == NULL)
		return false;

	DEBUG("Injection target %s found with pid %d", processName.c_str(), processPid);
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
/* 
	Cycle every piece of memory allocated inside the injected process
	and write it on a file with format: [injected_process_name]_[address]_[size].bin
*/
void dumpRemoteMemory() {
	FILE* outFile;
	W::SIZE_T numberOfReadBytes;

	for (auto memBlock : remoteAllocatedMemory) {
		void* injectedBytes = malloc(memBlock.second);
		if (!W::ReadProcessMemory(hInjectionTarget, (W::LPVOID)memBlock.first, injectedBytes, memBlock.second, &numberOfReadBytes))
			ERROR("ReadProcessMemory error: %d %s", W::GetLastError(), GetLastErrorAsString().c_str());
		if (numberOfReadBytes != memBlock.second)
			ERROR("ReadProcessMemory get %d bytes, instead of %d", numberOfReadBytes, memBlock.second);
		if (numberOfReadBytes != 0) {
			char fileName[MAX_PATH];
			string injectedProcessName = getProcessNameFromHandle(hInjectionTarget);
			snprintf(fileName, MAX_PATH, "%s_%p_%d.bin", injectedProcessName.c_str(), memBlock.first, memBlock.second);
			outFile = fopen(fileName, "wb+");
			fwrite(injectedBytes, sizeof(char), numberOfReadBytes, outFile);
			fclose(outFile);
			VERBOSE("Injection Dump", "Dumped %d bytes on file %s", numberOfReadBytes, fileName);
		}
	}
}
/*
	Try to identify the injection method analyzing the used APIs
*/
void printInjectionInfos() {
	fprintf(stdout, "\nIjnection infos: .....TODO");
}