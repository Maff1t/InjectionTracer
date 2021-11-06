#include "InjectionHandler.h"
#include "PE32.h"

W::HANDLE hInjectionTarget = NULL;
W::DWORD injectionTargetPid = 0;

map <const char *, int> counterOfUsedAPIs; // Counter of APIs used for Process Injection
vector <pair <W::LPVOID, W::SIZE_T>> remoteAllocatedMemory;
vector <pair <W::LPVOID, W::SIZE_T>> remoteWrittenMemory;


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
	injectionTargetPid = ProcessInfo.dwProcessId;
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

	injectionTargetPid = processPid;
	DEBUG("Injection target %s found with pid %d", processName.c_str(), processPid);
	return true;
}

/*
	check if the given address is the address of kernel32.LoadLibrary 
	Returns:
		-> 2 for LoadLibraryW
		-> 1 for LoadLibraryA
		-> 0 otherwise
*/
int isLoadLibraryAddress(ADDRINT address)
{
	W::HMODULE hKernel32 = W::GetModuleHandle("kernel32.dll");
	if (hKernel32 == NULL) {
		ERR("GetModuleHandle, kernel32.dll not found");
		return 0;
	}

	ADDRINT loadLibraryWAddress = (ADDRINT)W::GetProcAddress(hKernel32, "LoadLibraryW");
	if (loadLibraryWAddress != NULL && loadLibraryWAddress == address)
		return 2;

	ADDRINT loadLibraryAAddress = (ADDRINT)W::GetProcAddress(hKernel32, "LoadLibraryA");
	if (loadLibraryAAddress == NULL && loadLibraryAAddress == address)
		return 1;

	return 0;
}
/* 
	Cycle every piece of memory allocated inside the injected process
	and write it on a file with format: [injected_process_name]_[address]_[size].bin
*/
void dumpRemoteMemory() {
	
	FILE* outFile;
	W::SIZE_T numberOfReadBytes;
	string injectedProcessName = getProcessNameFromPid(injectionTargetPid);

	for (auto memBlock : remoteAllocatedMemory) {
		DEBUG("Dumping %x bytes of memory at %p of %s", memBlock.second, memBlock.first, injectedProcessName.c_str());
		W::LPVOID injectedBytes = (W::LPVOID) malloc(memBlock.second);
		W::HANDLE hTargetProcess = W::OpenProcess(PROCESS_VM_READ, false, injectionTargetPid);
		if (hTargetProcess == NULL) {
			ERR("Unable to open process %s (%d) with read memory permissions", injectedProcessName, injectionTargetPid);
			return;
		}
		W::ReadProcessMemory(hTargetProcess, memBlock.first, injectedBytes, memBlock.second, &numberOfReadBytes);
		
		if (numberOfReadBytes == 0) {
			ERR("ReadProcessMemory Error: Unable to read remote process memory");
			return;
		}

		char fileName[MAX_PATH];
		snprintf(fileName, MAX_PATH, "%s_%p_%d.bin", injectedProcessName.c_str(), memBlock.first, memBlock.second);
		outFile = fopen(fileName, "wb+");
		fwrite(injectedBytes, sizeof(char), numberOfReadBytes, outFile);
		fclose(outFile);
		VERBOSE("Dump", "Dumped %d bytes on file %s", numberOfReadBytes, fileName);
			
		// Now try to "unmap" the dumped PE
		string fName = string(fileName);
		PEFile32* pe = new PEFile32(fName);
		/*
		if (pe->isValidPe32()) {
			VERBOSE("Dump", "Fixing dumped memory");
			pe->fixBaseAddress((W::DWORD)memBlock.first); //TODO: FIX THIS FOR 64 BIT
			pe->fixAlign();
			pe->fixSections();
			pe->fixRelocSection();
			pe->disableASLR();
			pe->write_to_file(fName + "_unmapped.bin");
		}
		else {
			ERR("Error fixing dumped memory: is not a valid PE32");
		}*/
	}
}
/*
	Try to identify the injection method analyzing the used APIs
*/
void printInjectionInfos() {
	fprintf(stdout, "\nIjnection infos: .....TODO");
}