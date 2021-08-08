#include "Hooks.h"


VOID VirtualAlloc_After(W::LPVOID lpAddress, size_t dwSize, W::DWORD flProtect, ADDRINT ret)
{
	if (!HooksHandler::getInstance()->procInfo->isPartOfProgramMemory(ret)) return;

	/* If VirtualAlloc Fails, return NULL*/
	if (!lpAddress)
		return;

	HooksHandler::getInstance()->procInfo->insertAllocatedMemory(lpAddress, dwSize);

	if (flProtect & PAGE_EXECUTE ||
		flProtect & PAGE_EXECUTE_READ ||
		flProtect & PAGE_EXECUTE_READWRITE ||
		flProtect & PAGE_EXECUTE_WRITECOPY)
		VERBOSE("VIRTUAL ALLOC EXECUTABLE MEMORY", "%p", lpAddress);

	if (flProtect & PAGE_EXECUTE_READWRITE ||
		flProtect & PAGE_EXECUTE_WRITECOPY ||
		flProtect & PAGE_READWRITE ||
		flProtect & PAGE_WRITECOPY
		) {
		VERBOSE("VIRTUAL ALLOC WRITABLE MEMORY", "%p", lpAddress);
		HooksHandler::getInstance()->procInfo->insertAllocatedWritableMemory(lpAddress, dwSize);
	}


}

VOID HeapAlloc_After(W::LPVOID returnAddress, W::SIZE_T dwBytes, ADDRINT ret)
{
	if (!HooksHandler::getInstance()->procInfo->isPartOfProgramMemory(ret)) return;

	/* If VirtualAlloc Fails, return NULL*/
	if (!returnAddress)
		return;

	HooksHandler::getInstance()->procInfo->insertAllocatedMemory(returnAddress, dwBytes);
}

VOID VirtualProtect_After(W::LPVOID lpAddress, size_t dwSize, W::DWORD flNewProtect, ADDRINT ret)
{
	if (!HooksHandler::getInstance()->procInfo->isPartOfProgramMemory(ret)) return;

	/* Check if the page is mapped as executable.*/
	if (flNewProtect & PAGE_EXECUTE ||
		flNewProtect & PAGE_EXECUTE_READ ||
		flNewProtect & PAGE_EXECUTE_READWRITE ||
		flNewProtect & PAGE_EXECUTE_WRITECOPY) {
		HooksHandler::getInstance()->procInfo->insertAllocatedMemory(lpAddress, dwSize);
		// The process set executable a preallocated piece of memory
		VERBOSE("VIRTUAL PROTECT Executable memory", "%p", lpAddress);
	}

	if (flNewProtect & PAGE_EXECUTE_READWRITE ||
		flNewProtect & PAGE_EXECUTE_WRITECOPY ||
		flNewProtect & PAGE_READWRITE ||
		flNewProtect & PAGE_WRITECOPY
		) {
		VERBOSE("VIRTUAL ALLOC WRITABLE MEMORY", "%p", lpAddress);
		HooksHandler::getInstance()->procInfo->insertAllocatedWritableMemory(lpAddress, dwSize);
	}

}

VOID VirtualAllocEx_Before(W::HANDLE *hProcess, W::SIZE_T dwSize, W::DWORD flProtect, W::SIZE_T* allocationSize, ADDRINT ret)
{

	if (!HooksHandler::getInstance()->procInfo->isPartOfProgramMemory(ret)) return;
	auto it = counterOfUsedAPIs.find("VirtualAllocEx");
	if (it != counterOfUsedAPIs.end())
		counterOfUsedAPIs["VirtualAllocEx"] += 1;
	else
		counterOfUsedAPIs["VirtualAllocEx"] = 1;

	W::HANDLE processHandle;
	PIN_SafeCopy(&processHandle, hProcess, sizeof(W::HANDLE));

	/* Get pid from handle */
	W::DWORD remoteProcessPID = W::GetProcessId(processHandle);

	/* Check if the allocation is inside another process */
	if (remoteProcessPID != HooksHandler::getInstance()->procInfo->pid) {
		VERBOSE("VirtualAllocEx", "Try allocation of %d bytes inside remote process: %d ", dwSize, remoteProcessPID);

		/* Check if there must be a redirection of the injection */
		PIN_SafeCopy(allocationSize, &dwSize, sizeof(W::SIZE_T));
		W::DWORD injectionTargetPID = W::GetProcessId(hInjectionTarget);

		if (redirectInjection && remoteProcessPID != injectionTargetPID) {
			PIN_SafeCopy(hProcess, &hInjectionTarget, sizeof(W::HANDLE));
			VERBOSE("VirtualAllocEx", "Allocation redirected from %d to %d", remoteProcessPID, injectionTargetPID);
		}
		else if (!redirectInjection) {
			PIN_SafeCopy(&hInjectionTarget, hProcess, sizeof(W::HANDLE));
		}
	}
}

VOID VirtualAllocEx_After(W::LPVOID lpAddress, W::SIZE_T* allocationSize, ADDRINT ret)
{
	if (!HooksHandler::getInstance()->procInfo->isPartOfProgramMemory(ret)) return;
	W::SIZE_T allocatedSpace;
	PIN_SafeCopy(&allocatedSpace, allocationSize, sizeof(W::SIZE_T));

	if (allocatedSpace != 0) {
		VERBOSE("VirtualAllocEx", "Allocated remote space at %p of %d bytes", lpAddress, allocatedSpace);
		remoteAllocatedMemory.push_back(pair<W::DWORD, W::SIZE_T>((W::DWORD)lpAddress, allocatedSpace));
	}

}

VOID WriteProcessMemory_Before(W::HANDLE *hProcess, W::LPVOID lpBaseAddress, W::LPCVOID lpBuffer, W::SIZE_T nSize, ADDRINT ret)
{
	if (!HooksHandler::getInstance()->procInfo->isPartOfProgramMemory(ret)) return;
	auto it = counterOfUsedAPIs.find("WriteProcessMemory");
	if (it != counterOfUsedAPIs.end())
		counterOfUsedAPIs["WriteProcessMemory"] += 1;
	else
		counterOfUsedAPIs["WriteProcessMemory"] = 1;

	/* Get pid from handle */
	W::HANDLE processHandle;
	PIN_SafeCopy(&processHandle, hProcess, sizeof(W::HANDLE));

	W::DWORD remoteProcessPID = W::GetProcessId(processHandle);

	/* Check if the write is inside another process */
	if (remoteProcessPID != HooksHandler::getInstance()->procInfo->pid) {
		VERBOSE("WriteProcessMemory", "Memory write of %d bytes inside remote process: %d ", nSize, remoteProcessPID);

		remoteWrittenMemory.push_back(pair<W::DWORD, W::SIZE_T>((W::DWORD)lpBaseAddress, nSize));
		/* Check if there must be a redirection of the injection */
		W::DWORD injectionTargetPID = W::GetProcessId(hInjectionTarget);
		if (redirectInjection && remoteProcessPID != injectionTargetPID) {
			PIN_SafeCopy(hProcess, &hInjectionTarget, sizeof(W::HANDLE));
			VERBOSE("WriteProcessMemory", "Memory write redirected from %d to %d", remoteProcessPID, injectionTargetPID);
		}
		else if (!redirectInjection) {
			PIN_SafeCopy(&hInjectionTarget, hProcess, sizeof(W::HANDLE));
		}
	}
}

VOID CreateRemoteThread_Before(W::HANDLE* hProcess, W::LPTHREAD_START_ROUTINE lpStartAddress, W::LPVOID lpParameter, ADDRINT ret)
{
	if (!HooksHandler::getInstance()->procInfo->isPartOfProgramMemory(ret)) return;
	auto it = counterOfUsedAPIs.find("CreateRemoteThread");
	if (it != counterOfUsedAPIs.end())
		counterOfUsedAPIs["CreateRemoteThread"] += 1;
	else
		counterOfUsedAPIs["CreateRemoteThread"] = 1;

	/* Get pid from handle */
	W::HANDLE processHandle;
	PIN_SafeCopy(&processHandle, hProcess, sizeof(W::HANDLE));
	W::DWORD remoteProcessPID = W::GetProcessId(processHandle);

	/* Check if the write is inside another process */
	if (remoteProcessPID != HooksHandler::getInstance()->procInfo->pid) {
		VERBOSE("CreateRemoteThread", "Thread creation with start address %p inside process %d ", lpStartAddress, remoteProcessPID);

		/* Check if there must be a redirection of the injection */
		W::DWORD injectionTargetPID = W::GetProcessId(hInjectionTarget);
		if (redirectInjection && remoteProcessPID != injectionTargetPID) {
			PIN_SafeCopy(hProcess, &hInjectionTarget, sizeof(W::HANDLE));
			VERBOSE("CreateRemoteThread", "Thread Execution redirected from %d to %d", remoteProcessPID, injectionTargetPID);
		}
		else if (!redirectInjection) {
			PIN_SafeCopy(&hInjectionTarget, hProcess, sizeof(W::HANDLE));
		}

		/*	
			In a DLL injection the remote thread starts at the address of LoadLibrary.
		*/
		int isLoadLibrary = isLoadLibraryAddress((ADDRINT)lpStartAddress);
		if (isLoadLibrary) { // DLL injection

			/* Get the DLL path!*/
			W::SIZE_T dllPathSize = 0;
			for (auto it = remoteAllocatedMemory.begin(); it != remoteAllocatedMemory.end(); it++) {
				if (it->first == (W::DWORD)lpParameter) {
					dllPathSize = it->second;
					break;
				}
			}
			if (dllPathSize && isLoadLibrary == 1) { // LoadLibraryA
				char* dllPath = (char*)malloc(dllPathSize);
				W::ReadProcessMemory(hInjectionTarget, lpParameter, dllPath, dllPathSize, NULL);
				DETECTION("DLL Injection detected of dll: %s", dllPath);
			}
			else if (dllPathSize && isLoadLibrary == 2) { // LoadLibraryW
				wchar_t* dllPath = (wchar_t*)malloc(dllPathSize);
				W::ReadProcessMemory(hInjectionTarget, lpParameter, dllPath, dllPathSize, NULL);
				DETECTION("DLL Injection detected of dll: %ls", dllPath);

			}
			else {
				DETECTION("DLL Injection detected");

			}
		}
		else { // NOT DLL Injection
			DETECTION("Shellcode Injection detected");
		}

		fprintf(stdout, "\nPress a key to start the remote thread (You can put a breakpoint at %p)...\n", lpStartAddress);
		getchar();
	}
}
