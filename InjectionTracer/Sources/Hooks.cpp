#include "Hooks.h"


/* MEMORY ALLOCATION HOOKS */

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
		VERBOSE("VirtualAlloc", "Allocated executable memory at %p", lpAddress);

	if (flProtect & PAGE_EXECUTE_READWRITE ||
		flProtect & PAGE_EXECUTE_WRITECOPY ||
		flProtect & PAGE_READWRITE ||
		flProtect & PAGE_WRITECOPY
		) {
		VERBOSE("VirtualAlloc", "Allocated Writable memory at %p", lpAddress);
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
		VERBOSE("VirtualProtect", "Modified permissions of %p to be EXECUTABLE", lpAddress);
	}

	if (flNewProtect & PAGE_EXECUTE_READWRITE ||
		flNewProtect & PAGE_EXECUTE_WRITECOPY ||
		flNewProtect & PAGE_READWRITE ||
		flNewProtect & PAGE_WRITECOPY
		) {
		VERBOSE("VirtualProtect", "Modified permissions of %p to be WRITABLE", lpAddress);
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
	PIN_SafeCopy(allocationSize, 0, sizeof(W::SIZE_T));

	/* Get pid from handle */
	W::DWORD remoteProcessId = W::GetProcessId(processHandle);

	/* Check if the allocation is inside another process */
	if (remoteProcessId != HooksHandler::getInstance()->procInfo->pid) {

		string remoteProcessName = getProcessNameFromHandle(processHandle);

		PIN_SafeCopy(allocationSize, &dwSize, sizeof(W::SIZE_T));
		VERBOSE("VirtualAllocEx", "Trying to allocate 0x%x bytes inside %s (pid: %d)", *allocationSize, remoteProcessName, remoteProcessId);

		W::DWORD injectionTargetPID = W::GetProcessId(hInjectionTarget);

		/* Check if there must be a redirection of the injection */
		if (redirectInjection && remoteProcessId != injectionTargetPID) {
			PIN_SafeCopy(hProcess, &hInjectionTarget, sizeof(W::HANDLE));
			string injectionTargetName = getProcessNameFromHandle(processHandle);
			VERBOSE("VirtualAllocEx", "Allocation redirected from %s to %s", remoteProcessName, injectionTargetName);
		}
		else if (!redirectInjection) {
			PIN_SafeCopy(&hInjectionTarget, hProcess, sizeof(W::HANDLE));
		}
	}
}

VOID VirtualAllocEx_After(W::LPVOID lpAddress, W::SIZE_T* allocationSize, ADDRINT ret)
{
	if (!HooksHandler::getInstance()->procInfo->isPartOfProgramMemory(ret)) return;

	if (*allocationSize != 0) {
		VERBOSE("VirtualAllocEx", "Remote memory allocated at %p", lpAddress);
		remoteAllocatedMemory.push_back(pair<W::DWORD, W::SIZE_T>((W::DWORD)lpAddress, *allocationSize));
	}

}

/* WRITE MEMORY HOOKS */

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

	W::DWORD remoteProcessId = W::GetProcessId(processHandle);

	/* Check if the write is inside another process */
	if (remoteProcessId != HooksHandler::getInstance()->procInfo->pid) {
		string remoteProcessName = getProcessNameFromHandle(processHandle);
		VERBOSE("WriteProcessMemory", "Memory write of 0x%x bytes inside %s", nSize, remoteProcessName);

		remoteWrittenMemory.push_back(pair<W::DWORD, W::SIZE_T>((W::DWORD)lpBaseAddress, nSize));
		/* Check if there must be a redirection of the injection */
		W::DWORD injectionTargetPID = W::GetProcessId(hInjectionTarget);
		if (redirectInjection && remoteProcessId != injectionTargetPID) {
			PIN_SafeCopy(hProcess, &hInjectionTarget, sizeof(W::HANDLE));
			string injectionTargetName = getProcessNameFromHandle(processHandle);
			VERBOSE("VirtualAllocEx", "Memory write redirected from %s to %s", remoteProcessName, injectionTargetName);
		}
		else if (!redirectInjection) {
			PIN_SafeCopy(&hInjectionTarget, hProcess, sizeof(W::HANDLE));
		}
	}
}

/* THREAD EXECUTION HOOKS */

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
	W::DWORD remoteProcessId = W::GetProcessId(processHandle);

	/* Check if the write is inside another process */
	if (remoteProcessId != HooksHandler::getInstance()->procInfo->pid) {
		string remoteProcessName = getProcessNameFromHandle(processHandle);
		VERBOSE("CreateRemoteThread", "Thread creation with start address %p inside process %s (pid: %d)", lpStartAddress, remoteProcessName, remoteProcessId);

		/* Check if there must be a redirection of the injection */
		W::DWORD injectionTargetPID = W::GetProcessId(hInjectionTarget);
		if (redirectInjection && remoteProcessId != injectionTargetPID) {
			PIN_SafeCopy(hProcess, &hInjectionTarget, sizeof(W::HANDLE));
			string injectionTargetName = getProcessNameFromHandle(processHandle);
			VERBOSE("CreateRemoteThread", "Execution redirected from %s to %s", remoteProcessName, injectionTargetName);
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

		fprintf(stdout, "\nPress a key to start the remote thread (You can put a breakpoint at %p)...", lpStartAddress);
		getchar();
	}
}

VOID NtCreateThreadEx_Before(W::HANDLE* hProcess, W::LPTHREAD_START_ROUTINE lpStartAddress, W::LPVOID lpParameter, ADDRINT ret)
{
	if (!HooksHandler::getInstance()->procInfo->isPartOfProgramMemory(ret)) return;
	
	auto it = counterOfUsedAPIs.find("NtCreateThreadEx");
	if (it != counterOfUsedAPIs.end())
		counterOfUsedAPIs["NtCreateThreadEx"] += 1;
	else
		counterOfUsedAPIs["NtCreateThreadEx"] = 1;

	/* Get pid from handle */
	W::HANDLE processHandle;
	PIN_SafeCopy(&processHandle, hProcess, sizeof(W::HANDLE));
	W::DWORD remoteProcessId = W::GetProcessId(processHandle);

	/* Check if the write is inside another process */
	if (remoteProcessId != HooksHandler::getInstance()->procInfo->pid) {
		string remoteProcessName = getProcessNameFromHandle(processHandle);
		VERBOSE("NtCreateThreadEx", "Thread creation with start address %p inside process %s (pid: %d)", lpStartAddress, remoteProcessName, remoteProcessId);

		/* Check if there must be a redirection of the injection */
		W::DWORD injectionTargetPID = W::GetProcessId(hInjectionTarget);
		if (redirectInjection && remoteProcessId != injectionTargetPID) {
			PIN_SafeCopy(hProcess, &hInjectionTarget, sizeof(W::HANDLE));
			string injectionTargetName = getProcessNameFromHandle(processHandle);
			VERBOSE("NtCreateThreadEx", "Execution redirected from %s to %s", remoteProcessName, injectionTargetName);
		}
		else if (!redirectInjection) {
			PIN_SafeCopy(&hInjectionTarget, hProcess, sizeof(W::HANDLE));
		}

		/*
			In a standard DLL injection the remote thread starts at the address of LoadLibrary.
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
				DETECTION("DLL Injection detected, Dll name not recovered");
			}
		}
		else { // NOT DLL Injection
			DETECTION("Shellcode Injection detected");
		}

		fprintf(stdout, "\nPress a key to start the remote thread (You can put a breakpoint at %p)...", lpStartAddress);
		getchar();
	}
}

VOID RtlCreateUserThread_Before(W::HANDLE* hProcess, W::LPVOID lpStartAddress, W::LPVOID lpParameter, ADDRINT ret)
{
	if (!HooksHandler::getInstance()->procInfo->isPartOfProgramMemory(ret)) return;
	
	auto it = counterOfUsedAPIs.find("RtlCreateUserThread");
	if (it != counterOfUsedAPIs.end())
		counterOfUsedAPIs["RtlCreateUserThread"] += 1;
	else
		counterOfUsedAPIs["RtlCreateUserThread"] = 1;

	/* Get pid from handle */
	W::HANDLE processHandle;
	PIN_SafeCopy(&processHandle, hProcess, sizeof(W::HANDLE));
	W::DWORD remoteProcessId = W::GetProcessId(processHandle);

	/* Check if the write is inside another process */
	if (remoteProcessId != HooksHandler::getInstance()->procInfo->pid) {
		string remoteProcessName = getProcessNameFromHandle(processHandle);
		VERBOSE("RtlCreateUserThread", "Thread creation with start address %p inside process %s (pid: %d)", lpStartAddress, remoteProcessName, remoteProcessId);

		/* Check if there must be a redirection of the injection */
		W::DWORD injectionTargetPID = W::GetProcessId(hInjectionTarget);
		if (redirectInjection && remoteProcessId != injectionTargetPID) {
			PIN_SafeCopy(hProcess, &hInjectionTarget, sizeof(W::HANDLE));
			string injectionTargetName = getProcessNameFromHandle(processHandle);
			VERBOSE("RtlCreateUserThread", "Allocation redirected from %s to %s", remoteProcessName, injectionTargetName);
		}
		else if (!redirectInjection) {
			PIN_SafeCopy(&hInjectionTarget, hProcess, sizeof(W::HANDLE));
		}

		/*
			In a standard DLL injection the remote thread starts at the address of LoadLibrary.
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
				DETECTION("DLL Injection detected, Dll name not recovered");
			}
		}
		else { // NOT DLL Injection
			DETECTION("Shellcode Injection detected");
		}

		fprintf(stdout, "\nPress a key to start the remote thread (You can put a breakpoint at %p)...", lpStartAddress);
		getchar();
	}
}