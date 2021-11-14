#include "Hooks.h"


/* MEMORY ALLOCATION HOOKS */

VOID VirtualAlloc_After(W::LPVOID lpAddress, size_t dwSize, W::DWORD flProtect, ADDRINT ret)
{

	/* If VirtualAlloc Fails, return NULL*/
	if (!lpAddress)
		return;

	HooksHandler::getInstance()->procInfo->insertAllocatedMemory(lpAddress, dwSize);

	if (flProtect & PAGE_EXECUTE ||
		flProtect & PAGE_EXECUTE_READ ||
		flProtect & PAGE_EXECUTE_READWRITE ||
		flProtect & PAGE_EXECUTE_WRITECOPY)
		verboseLog("VirtualAlloc", "Allocated executable memory at %p", lpAddress);

	if (flProtect & PAGE_EXECUTE_READWRITE ||
		flProtect & PAGE_EXECUTE_WRITECOPY ||
		flProtect & PAGE_READWRITE ||
		flProtect & PAGE_WRITECOPY
		) {
		verboseLog("VirtualAlloc", "Allocated Writable memory at %p", lpAddress);
		HooksHandler::getInstance()->procInfo->insertAllocatedWritableMemory(lpAddress, dwSize);
	}


}

VOID HeapAlloc_After(W::LPVOID returnAddress, W::SIZE_T dwBytes, ADDRINT ret)
{

	/* If VirtualAlloc Fails, return NULL*/
	if (!returnAddress)
		return;

	HooksHandler::getInstance()->procInfo->insertAllocatedMemory(returnAddress, dwBytes);
}

VOID VirtualProtect_After(W::LPVOID lpAddress, size_t dwSize, W::DWORD flNewProtect, ADDRINT ret)
{

	/* Check if the page is mapped as executable.*/
	if (flNewProtect & PAGE_EXECUTE ||
		flNewProtect & PAGE_EXECUTE_READ ||
		flNewProtect & PAGE_EXECUTE_READWRITE ||
		flNewProtect & PAGE_EXECUTE_WRITECOPY) {
		HooksHandler::getInstance()->procInfo->insertAllocatedMemory(lpAddress, dwSize);
		// The process set executable a preallocated piece of memory
		verboseLog("VirtualProtect", "Modified permissions of %p to be EXECUTABLE", lpAddress);
	}

	if (flNewProtect & PAGE_EXECUTE_READWRITE ||
		flNewProtect & PAGE_EXECUTE_WRITECOPY ||
		flNewProtect & PAGE_READWRITE ||
		flNewProtect & PAGE_WRITECOPY
		) {
		verboseLog("VirtualProtect", "Modified permissions of %p to be WRITABLE", lpAddress);
		HooksHandler::getInstance()->procInfo->insertAllocatedWritableMemory(lpAddress, dwSize);
	}

}

VOID VirtualAllocEx_Before(W::HANDLE *hProcess, W::SIZE_T dwSize, W::DWORD flProtect, W::SIZE_T* allocationSize, ADDRINT ret)
{

	auto it = counterOfUsedAPIs.find("VirtualAllocEx");
	if (it != counterOfUsedAPIs.end())
		counterOfUsedAPIs["VirtualAllocEx"] += 1;
	else
		counterOfUsedAPIs["VirtualAllocEx"] = 1;

	W::HANDLE processHandle;
	PIN_SafeCopy(&processHandle, hProcess, sizeof(W::HANDLE));
	PIN_SafeCopy(allocationSize, 0, sizeof(W::SIZE_T));

	// Get pid from handle
	W::DWORD remoteProcessId = W::GetProcessId(processHandle);

	// Check if the allocation is inside another process 
	
	if (remoteProcessId != HooksHandler::getInstance()->procInfo->pid) {

		string remoteProcessName = getProcessNameFromHandle(processHandle);

		PIN_SafeCopy(allocationSize, &dwSize, sizeof(W::SIZE_T));
		verboseLog("VirtualAllocEx", "Trying to allocate 0x%x bytes inside %s (pid: %d)", *allocationSize, remoteProcessName.c_str(), remoteProcessId);

		// Check if there must be a redirection of the injection
		if (redirectInjection && remoteProcessId != W::GetProcessId(hInjectionTarget)) {
			PIN_SafeCopy(hProcess, &hInjectionTarget, sizeof(W::HANDLE));
			string injectionTargetName = getProcessNameFromHandle(processHandle);
			verboseLog("VirtualAllocEx", "Allocation redirected from %s to %s", remoteProcessName.c_str(), injectionTargetName.c_str());
		}
		else if (!redirectInjection) {
			PIN_SafeCopy(&hInjectionTarget, hProcess, sizeof(W::HANDLE));
			injectionTargetPid = remoteProcessId;
		}
	}
}

VOID VirtualAllocEx_After(W::LPVOID lpAddress, W::SIZE_T* allocationSize, ADDRINT ret)
{

	if (*allocationSize != 0) {
		verboseLog("VirtualAllocEx", "Remote memory allocated at %p", lpAddress);
		remoteAllocatedMemory.push_back(pair<W::LPVOID, W::SIZE_T>(lpAddress, *allocationSize));
	}

}

/* WRITE MEMORY HOOKS */

VOID WriteProcessMemory_Before(W::HANDLE *hProcess, W::LPVOID lpBaseAddress, W::LPCVOID lpBuffer, W::SIZE_T nSize, ADDRINT ret)
{
	auto it = counterOfUsedAPIs.find("WriteProcessMemory");
	if (it != counterOfUsedAPIs.end())
		counterOfUsedAPIs["WriteProcessMemory"] += 1;
	else
		counterOfUsedAPIs["WriteProcessMemory"] = 1;

	/* Get pid from handle */
	W::HANDLE processHandle;
	PIN_SafeCopy(&processHandle, hProcess, sizeof(W::HANDLE));

	W::DWORD remoteProcessId = W::GetProcessId(processHandle);

	/* Check if is writing inside another process */
	if (remoteProcessId != HooksHandler::getInstance()->procInfo->pid) {
		string remoteProcessName = getProcessNameFromHandle(processHandle);
		verboseLog("WriteProcessMemory", "Memory write of 0x%x bytes inside %s", nSize, remoteProcessName.c_str());
		

		remoteWrittenMemory.push_back(pair<W::LPVOID, W::SIZE_T>(lpBaseAddress, nSize));
		/* Check if there must be a redirection of the injection */

		if (redirectInjection && remoteProcessId != W::GetProcessId(hInjectionTarget)) {
			PIN_SafeCopy(hProcess, &hInjectionTarget, sizeof(W::HANDLE));
			string injectionTargetName = getProcessNameFromHandle(processHandle);
			verboseLog("VirtualAllocEx", "Memory write redirected from %s to %s", remoteProcessName.c_str(), injectionTargetName.c_str());
		}
		else if (!redirectInjection) {
			PIN_SafeCopy(&hInjectionTarget, hProcess, sizeof(W::HANDLE));
			injectionTargetPid = remoteProcessId;
		}
	}
}

/* THREAD EXECUTION HOOKS */

VOID CreateRemoteThread_Before(W::HANDLE* hProcess, W::LPTHREAD_START_ROUTINE lpStartAddress, W::LPVOID lpParameter, ADDRINT ret)
{
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
		verboseLog("CreateRemoteThread", "Thread creation with start address %p inside process %s (pid: %d)", lpStartAddress, remoteProcessName.c_str(), remoteProcessId);

		dumpMemoryAtAddress(lpStartAddress, "CreateRemoteThread");

		/* Check if there must be a redirection of the injection */
		if (redirectInjection && remoteProcessId != W::GetProcessId(hInjectionTarget)) {
			PIN_SafeCopy(hProcess, &hInjectionTarget, sizeof(W::HANDLE));
			string injectionTargetName = getProcessNameFromHandle(processHandle);
			verboseLog("CreateRemoteThread", "Execution redirected from %s to %s", remoteProcessName.c_str(), injectionTargetName.c_str());
		}
		else if (!redirectInjection) {
			PIN_SafeCopy(&hInjectionTarget, hProcess, sizeof(W::HANDLE));
			injectionTargetPid = remoteProcessId;
		}

		/*	
			In a DLL injection the remote thread starts at the address of LoadLibrary.
		*/
		int isLoadLibrary = isLoadLibraryAddress((ADDRINT)lpStartAddress);
		if (isLoadLibrary) { // DLL injection

			/* Get the DLL path!*/
			W::SIZE_T dllPathSize = 0;
			for (auto it = remoteAllocatedMemory.begin(); it != remoteAllocatedMemory.end(); it++) {
				if (it->first == lpParameter) {
					dllPathSize = it->second;
					break;
				}
			}
			if (dllPathSize && isLoadLibrary == 1) { // LoadLibraryA
				char* dllPath = (char*)malloc(dllPathSize);
				W::ReadProcessMemory(hInjectionTarget, lpParameter, dllPath, dllPathSize, NULL);
				highlightedLog("DLL Injection detected of dll: %s", dllPath);
			}
			else if (dllPathSize && isLoadLibrary == 2) { // LoadLibraryW
				wchar_t* dllPath = (wchar_t*)malloc(dllPathSize);
				W::ReadProcessMemory(hInjectionTarget, lpParameter, dllPath, dllPathSize, NULL);
				highlightedLog("DLL Injection detected of dll: %ls", dllPath);

			}
			else {
				highlightedLog("DLL Injection detected");

			}
		}
		else { // NOT DLL Injection
			highlightedLog("Shellcode Injection detected");
		}

		// Pause execution of the thread before it starts
		char* message = (char*)malloc(256);
		W::DWORD readBytes;

		sprintf(message, "\nPress a key to start the remote thread (You can put a breakpoint at %p)...", lpStartAddress);
		W::WriteConsoleA(W::GetStdHandle((W::DWORD)-11), message, strlen(message), NULL, NULL);
		W::ReadConsoleA(W::GetStdHandle((W::DWORD)-10), message, 1, &readBytes, NULL);
		free(message);
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
		verboseLog("NtCreateThreadEx", "Thread creation with start address %p inside process %s (pid: %d)", lpStartAddress, remoteProcessName.c_str(), remoteProcessId);

		dumpMemoryAtAddress(lpStartAddress, "NtCreateThreadEx");

		/* Check if there must be a redirection of the injection */
		if (redirectInjection && remoteProcessId != W::GetProcessId(hInjectionTarget)) {
			PIN_SafeCopy(hProcess, &hInjectionTarget, sizeof(W::HANDLE));
			string injectionTargetName = getProcessNameFromHandle(processHandle);
			verboseLog("NtCreateThreadEx", "Execution redirected from %s to %s", remoteProcessName.c_str(), injectionTargetName.c_str());
		}
		else if (!redirectInjection) {
			PIN_SafeCopy(&hInjectionTarget, hProcess, sizeof(W::HANDLE));
			injectionTargetPid = remoteProcessId;
		}

		/*
			In a standard DLL injection the remote thread starts at the address of LoadLibrary.
		*/
		int isLoadLibrary = isLoadLibraryAddress((ADDRINT)lpStartAddress);
		if (isLoadLibrary) { // DLL injection

			/* Get the DLL path!*/
			W::SIZE_T dllPathSize = 0;
			for (auto it = remoteAllocatedMemory.begin(); it != remoteAllocatedMemory.end(); it++) {
				if (it->first == lpParameter) {
					dllPathSize = it->second;
					break;
				}
			}
			if (dllPathSize && isLoadLibrary == 1) { // LoadLibraryA
				char* dllPath = (char*)malloc(dllPathSize);
				W::ReadProcessMemory(hInjectionTarget, lpParameter, dllPath, dllPathSize, NULL);
				highlightedLog("DLL Injection detected of dll: %s", dllPath);
			}
			else if (dllPathSize && isLoadLibrary == 2) { // LoadLibraryW
				wchar_t* dllPath = (wchar_t*)malloc(dllPathSize);
				W::ReadProcessMemory(hInjectionTarget, lpParameter, dllPath, dllPathSize, NULL);
				highlightedLog("DLL Injection detected of dll: %ls", dllPath);

			}
			else {
				highlightedLog("DLL Injection detected, Dll name not recovered");
			}
		}
		else { // NOT DLL Injection
			highlightedLog("Shellcode Injection detected");
		}

		// Pause execution of the thread before it starts
		char* message = (char*)malloc(256);
		W::DWORD readBytes;

		sprintf(message, "\nPress a key to start the remote thread (You can put a breakpoint at %p)...", lpStartAddress);
		W::WriteConsoleA(W::GetStdHandle((W::DWORD)-11), message, strlen(message), NULL, NULL);
		W::ReadConsoleA(W::GetStdHandle((W::DWORD)-10), message, 1, &readBytes, NULL);
		free(message);
	}
}

VOID RtlCreateUserThread_Before(W::HANDLE* hProcess, W::LPVOID lpStartAddress, W::LPVOID lpParameter, ADDRINT ret)
{
	
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
		verboseLog("RtlCreateUserThread", "Thread creation with start address %p inside process %s (pid: %d)", lpStartAddress, remoteProcessName.c_str(), remoteProcessId);

		dumpMemoryAtAddress(lpStartAddress, "RtlCreateUserThread");

		/* Check if there must be a redirection of the injection */
		if (redirectInjection && remoteProcessId != W::GetProcessId(hInjectionTarget)) {
			PIN_SafeCopy(hProcess, &hInjectionTarget, sizeof(W::HANDLE));
			string injectionTargetName = getProcessNameFromHandle(processHandle);
			verboseLog("RtlCreateUserThread", "Allocation redirected from %s to %s", remoteProcessName.c_str(), injectionTargetName.c_str());
		}
		else if (!redirectInjection) {
			PIN_SafeCopy(&hInjectionTarget, hProcess, sizeof(W::HANDLE));
			injectionTargetPid = remoteProcessId;
		}

		/*
			In a standard DLL injection the remote thread starts at the address of LoadLibrary.
		*/
		int isLoadLibrary = isLoadLibraryAddress((ADDRINT)lpStartAddress);
		if (isLoadLibrary) { // DLL injection

			/* Get the DLL path!*/
			W::SIZE_T dllPathSize = 0;
			for (auto it = remoteAllocatedMemory.begin(); it != remoteAllocatedMemory.end(); it++) {
				if (it->first == lpParameter) {
					dllPathSize = it->second;
					break;
				}
			}
			if (dllPathSize && isLoadLibrary == 1) { // LoadLibraryA
				char* dllPath = (char*)malloc(dllPathSize);
				W::ReadProcessMemory(hInjectionTarget, lpParameter, dllPath, dllPathSize, NULL);
				highlightedLog("DLL Injection detected of dll: %s", dllPath);
			}
			else if (dllPathSize && isLoadLibrary == 2) { // LoadLibraryW
				wchar_t* dllPath = (wchar_t*)malloc(dllPathSize);
				W::ReadProcessMemory(hInjectionTarget, lpParameter, dllPath, dllPathSize, NULL);
				highlightedLog("DLL Injection detected of dll: %ls", dllPath);

			}
			else {
				highlightedLog("DLL Injection detected, Dll name not recovered");
			}
		}
		else { // NOT DLL Injection
			highlightedLog("Shellcode Injection detected");
		}

		// Pause execution of the thread before it starts
		char* message = (char*)malloc(256);
		W::DWORD readBytes;

		sprintf(message, "\nPress a key to start the remote thread (You can put a breakpoint at %p)...", lpStartAddress);
		W::WriteConsoleA(W::GetStdHandle((W::DWORD)-11), message, strlen(message), NULL, NULL);
		W::ReadConsoleA(W::GetStdHandle((W::DWORD)-10), message, 1, &readBytes, NULL);
		free(message);
	}
}

VOID ResumeThread_Before(W::HANDLE hThread, ADDRINT ret)
{
	W::LPVOID instructionPointer, parameterValue, threadStartingAddress;
	W::DWORD remoteProcessId;
	auto it = counterOfUsedAPIs.find("ResumeThread");
	if (it != counterOfUsedAPIs.end())
		counterOfUsedAPIs["ResumeThread"] += 1;
	else
		counterOfUsedAPIs["ResumeThread"] = 1;

	/* Get pid from thread handle */

	remoteProcessId = W::GetProcessIdOfThread(hThread);
	if (!remoteProcessId) {
		errorLog("Unable to retrive PID from thread handle");
		return;
	}

	if (remoteProcessId != W::GetCurrentProcessId()) {
		string remoteProcessName = getProcessNameFromPid(remoteProcessId);

		verboseLog("ResumeThread", "A remote thread inside %s will be resumed!", remoteProcessName.c_str());

		// TODO: This is not correct -> I should check if the remote process is 32/64 bit! 
		// Not the current one!
#ifdef _WIN64
		
		// Check if remote process is 32 bit - x64->x86 injection
		if (is32bitProcess(remoteProcessId)) {
			W::WOW64_CONTEXT * lpContext = new W::WOW64_CONTEXT();
			lpContext->ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;

			// Get the thread context of the child process's primary thread
			if (!W::Wow64GetThreadContext(hThread, lpContext)) {
				errorLog("Unable to retrive WoW64 Context from thread handle");
				return;
			}

			instructionPointer = (W::LPVOID)lpContext->Eip;
			parameterValue = (W::LPVOID)lpContext->Edx; //TODO: FIX this...on 32 bit this should not be correct.
		} else {
			W::LPCONTEXT lpContext = new W::CONTEXT();
			lpContext->ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;

			// Get the thread context of the child process's primary thread
			if (!W::GetThreadContext(hThread, lpContext)) {
				errorLog("Unable to retrive Context from thread handle");
				return;
			}
			instructionPointer = (W::LPVOID)lpContext->Rip;
			parameterValue = (W::LPVOID)lpContext->Rcx;
		}
		
#else
		// Check if I have a x86->x64 injection 
		// The majority of injection techniques doesn't work in this case. 
		// Maybe in future I will handle this
		if (!is32bitProcess(remoteProcessId)) {
			errorLog("Unable to handle x86->x64 injection and get the remote starting address");
			return;
		}

		W::LPCONTEXT lpContext = new W::CONTEXT();
		lpContext->ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;

		// Get the thread context of the child process's primary thread
		if (!W::GetThreadContext(hThread, lpContext)) {
			errorLog("Unable to retrive Context from thread handle");
			return;
		}
		instructionPointer = (W::LPVOID)lpContext->Eip;
		parameterValue = (W::LPVOID)lpContext->Eax; // I don't actually know why this is correct, but I've tested it and it seems to work.
#endif
		// Retrive start address of remote thread: two possible cases:
		// 1. The thread has been created suspended -> the execution starts at ntdll.RtlUserThreadStart
		// 2. The thread has been suspended by the injector.
		// In the first case the real address is in RCX/ECX, in the second one is at EIP/RIP
		if (isFunctionAddress((ADDRINT)instructionPointer, "ntdll.dll", "RtlUserThreadStart"))
			threadStartingAddress = parameterValue;
		else
			threadStartingAddress = instructionPointer;

		dumpMemoryAtAddress(threadStartingAddress, "ResumeThread");

		// Pause execution of the thread before it starts
		char* message = (char*)malloc(256);
		W::DWORD readBytes;

		sprintf(message, "\nPress a key to start the remote thread (You can put a breakpoint at %p)...", threadStartingAddress);
		W::WriteConsoleA(W::GetStdHandle((W::DWORD)-11), message, strlen(message), NULL, NULL);
		W::ReadConsoleA(W::GetStdHandle((W::DWORD)-10), message, 1, &readBytes, NULL);
		free(message);
	}

	// TODO: Get eip/rip from context using GetThreadContext, dump memory and stop execution!
}

