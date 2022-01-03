#include "Hooks.h"

W::SIZE_T allocationSize = 0;
map <string, libraryHooksId> libraryHooks;
set <string> hookedLibraries;

void initApiHooks()
{
	libraryHooks.insert(pair <string, libraryHooksId>("HeapAlloc", HEAPALLOC));
	libraryHooks.insert(pair <string, libraryHooksId>("VirtualAlloc", VIRTUALALLOC));
	libraryHooks.insert(pair <string, libraryHooksId>("VirtualAllocEx", VIRTUALALLOCEX));
	libraryHooks.insert(pair <string, libraryHooksId>("VirtualProtect", VIRTUALPROTECT));
	libraryHooks.insert(pair <string, libraryHooksId>("WriteProcessMemory", WRITEPROCESSMEMORY));
	libraryHooks.insert(pair <string, libraryHooksId>("NtWriteVirtualMemory", NTWRITEVIRTUALMEMORY));
	libraryHooks.insert(pair <string, libraryHooksId>("ZwWriteVirtualMemory", NTWRITEVIRTUALMEMORY));
	libraryHooks.insert(pair <string, libraryHooksId>("CreateRemoteThread", CREATEREMOTETHREAD));
	libraryHooks.insert(pair <string, libraryHooksId>("CreateRemoteThreadEx", CREATEREMOTETHREAD));
	libraryHooks.insert(pair <string, libraryHooksId>("ResumeThread", RESUMETHREAD));
	libraryHooks.insert(pair <string, libraryHooksId>("NtCreateThreadEx", NTCREATETHREADEX));
	libraryHooks.insert(pair <string, libraryHooksId>("ZwCreateThreadEx", NTCREATETHREADEX));
	libraryHooks.insert(pair <string, libraryHooksId>("RtlCreateUserThread", RTLCREATEUSERTHREAD));
	libraryHooks.insert(pair <string, libraryHooksId>("QueueUserAPC", QUEUEUSERAPC));
	libraryHooks.insert(pair <string, libraryHooksId>("SetWindowsHookExA", SETWINDOWSHOOKEX));
	libraryHooks.insert(pair <string, libraryHooksId>("SetWindowsHookExW", SETWINDOWSHOOKEX));

	hookedLibraries.insert("kernelbase.dll");
	hookedLibraries.insert("ntdll.dll");
}

void hookApiInThisLibrary(IMG img)
{
	// Check if the current library should be hooked
	string imageName = IMG_Name(img);
	string fileName = getNameFromPath(imageName);
	char* lowerString = stringToLower(fileName);
	if (hookedLibraries.find(lowerString) == hookedLibraries.end())
		return;

	// Try to find the function to hook inside the image
	for (auto iter = libraryHooks.begin(); iter != libraryHooks.end(); ++iter)
	{
		string funcName = iter->first;
		RTN rtn = RTN_FindByName(img, funcName.c_str());
		if (!RTN_Valid(rtn)) continue;
		debugLog("Hook inserted: %s->%s", imageName.c_str(), funcName.c_str());
		REGSET regsIn;
		REGSET regsOut;

		// Instrument the routine found
		RTN_Open(rtn);
		switch (iter->second)
		{
		case HEAPALLOC:
			RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)HeapAlloc_After, IARG_FUNCRET_EXITPOINT_VALUE, IARG_FUNCARG_ENTRYPOINT_VALUE, 2, IARG_END);
			break;
		case VIRTUALALLOC:
			RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)VirtualAlloc_After, IARG_FUNCRET_EXITPOINT_VALUE, IARG_FUNCARG_ENTRYPOINT_VALUE, 1, IARG_FUNCARG_ENTRYPOINT_VALUE, 3, IARG_END);
			break;
		case VIRTUALPROTECT:
			RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)VirtualProtect_After, IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_FUNCARG_ENTRYPOINT_VALUE, 1, IARG_FUNCARG_ENTRYPOINT_VALUE, 2, IARG_END);
			break;
		case VIRTUALALLOCEX:
			RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)VirtualAllocEx_Before, IARG_FUNCARG_ENTRYPOINT_REFERENCE, 0, IARG_FUNCARG_ENTRYPOINT_VALUE, 2, IARG_FUNCARG_ENTRYPOINT_VALUE, 4, IARG_ADDRINT, &allocationSize, IARG_END);
			RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)VirtualAllocEx_After, IARG_FUNCRET_EXITPOINT_VALUE, IARG_ADDRINT, &allocationSize, IARG_END);
			break;
		case WRITEPROCESSMEMORY:
			RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)WriteProcessMemory_Before, IARG_FUNCARG_ENTRYPOINT_REFERENCE, 0, IARG_FUNCARG_ENTRYPOINT_VALUE, 1, IARG_FUNCARG_ENTRYPOINT_VALUE, 2, IARG_FUNCARG_ENTRYPOINT_VALUE, 3, IARG_END);
			break;
		case NTWRITEVIRTUALMEMORY:
			RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)NtWriteVirtualMemory_Before, IARG_FUNCARG_ENTRYPOINT_REFERENCE, 0, IARG_FUNCARG_ENTRYPOINT_VALUE, 1, IARG_FUNCARG_ENTRYPOINT_VALUE, 2, IARG_FUNCARG_ENTRYPOINT_VALUE, 3, IARG_RETURN_IP, IARG_END);
			break;
		case CREATEREMOTETHREAD:
			RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)CreateRemoteThread_Before, IARG_FUNCARG_ENTRYPOINT_REFERENCE, 0, IARG_FUNCARG_ENTRYPOINT_VALUE, 3, IARG_FUNCARG_ENTRYPOINT_VALUE, 4, IARG_END);
			break;
		case NTCREATETHREADEX:
			RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)NtCreateThreadEx_Before, IARG_FUNCARG_ENTRYPOINT_REFERENCE, 3, IARG_FUNCARG_ENTRYPOINT_VALUE, 4, IARG_FUNCARG_ENTRYPOINT_VALUE, 5, IARG_RETURN_IP, IARG_END);
			break;
		case RTLCREATEUSERTHREAD:
			RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)RtlCreateUserThread_Before, IARG_FUNCARG_ENTRYPOINT_REFERENCE, 0, IARG_FUNCARG_ENTRYPOINT_VALUE, 6, IARG_FUNCARG_ENTRYPOINT_VALUE, 7, IARG_END);
			break;
		case RESUMETHREAD:
			RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)ResumeThread_Before, IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_END);
			break;
		case QUEUEUSERAPC:
			RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)QueueUserAPC_Before, IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_FUNCARG_ENTRYPOINT_VALUE, 1, IARG_END);
			break;
			/*
			case SETWINDOWSHOOKEX:
				RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)SetWindowsHookEx_Before, IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_FUNCARG_ENTRYPOINT_VALUE, 1, IARG_FUNCARG_ENTRYPOINT_VALUE, 2, IARG_FUNCARG_ENTRYPOINT_VALUE, 3, IARG_END);
				break;
			*/
		}
		RTN_Close(rtn);
	}
}

VOID VirtualAlloc_After(W::LPVOID lpAddress, size_t dwSize, W::DWORD flProtect)
{

	/* If VirtualAlloc Fails, return NULL*/
	if (!lpAddress)
		return;

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
	}


}

VOID HeapAlloc_After(W::LPVOID returnAddress, W::SIZE_T dwBytes)
{

	/* If VirtualAlloc Fails, return NULL*/
	if (!returnAddress)
		return;

}

VOID VirtualProtect_After(W::LPVOID lpAddress, size_t dwSize, W::DWORD flNewProtect)
{

	/* Check if the page is mapped as executable.*/
	if (flNewProtect & PAGE_EXECUTE ||
		flNewProtect & PAGE_EXECUTE_READ ||
		flNewProtect & PAGE_EXECUTE_READWRITE ||
		flNewProtect & PAGE_EXECUTE_WRITECOPY) {
		// The process set executable a preallocated piece of memory
		verboseLog("VirtualProtect", "Modified permissions of %p to be EXECUTABLE", lpAddress);
	}

	if (flNewProtect & PAGE_EXECUTE_READWRITE ||
		flNewProtect & PAGE_EXECUTE_WRITECOPY ||
		flNewProtect & PAGE_READWRITE ||
		flNewProtect & PAGE_WRITECOPY
		) {
		verboseLog("VirtualProtect", "Modified permissions of %p to be WRITABLE", lpAddress);
	}

}

VOID VirtualAllocEx_Before(W::HANDLE *hProcess, W::SIZE_T dwSize, W::DWORD flProtect, W::SIZE_T* allocationSize)
{

	W::HANDLE processHandle;
	PIN_SafeCopy(&processHandle, hProcess, sizeof(W::HANDLE));
	PIN_SafeCopy(allocationSize, 0, sizeof(W::SIZE_T));

	// Get pid from handle
	W::DWORD remoteProcessId = W::GetProcessId(processHandle);

	// Check if the allocation is inside another process 
	
	if (remoteProcessId != currentProcessPid) {

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

VOID VirtualAllocEx_After(W::LPVOID lpAddress, W::SIZE_T* allocationSize)
{

	if (*allocationSize != 0) {
		verboseLog("VirtualAllocEx", "Remote memory allocated at %p", lpAddress);
		remoteAllocatedMemory.push_back(pair<W::LPVOID, W::SIZE_T>(lpAddress, *allocationSize));
	}

}

/* WRITE MEMORY HOOKS */

VOID WriteProcessMemory_Before(W::HANDLE *hProcess, W::LPVOID lpBaseAddress, W::LPCVOID lpBuffer, W::SIZE_T nSize)
{
	/* Get pid from handle */
	W::HANDLE processHandle;
	PIN_SafeCopy(&processHandle, hProcess, sizeof(W::HANDLE));

	W::DWORD remoteProcessId = W::GetProcessId(processHandle);

	/* Check if is writing inside another process */
	if (remoteProcessId != currentProcessPid) {
		string remoteProcessName = getProcessNameFromHandle(processHandle);
		verboseLog("WriteProcessMemory", "Memory write of 0x%x bytes inside %s", nSize, remoteProcessName.c_str());
		

		remoteWrittenMemory.push_back(pair<W::LPVOID, W::SIZE_T>(lpBaseAddress, nSize));
		/* Check if there must be a redirection of the injection */

		if (redirectInjection && remoteProcessId != W::GetProcessId(hInjectionTarget)) {
			PIN_SafeCopy(hProcess, &hInjectionTarget, sizeof(W::HANDLE));
			string injectionTargetName = getProcessNameFromHandle(processHandle);
			verboseLog("WriteProcessMemory", "Memory write redirected from %s to %s", remoteProcessName.c_str(), injectionTargetName.c_str());
		}
		else if (!redirectInjection) {
			PIN_SafeCopy(&hInjectionTarget, hProcess, sizeof(W::HANDLE));
			injectionTargetPid = remoteProcessId;
		}
	}
}

VOID NtWriteVirtualMemory_Before(W::HANDLE* hProcess, W::LPVOID lpBaseAddress, W::LPCVOID lpBuffer, W::SIZE_T nSize, ADDRINT ret)
{
	// Check if this API is called by the malware itself and NOT 
	// by the corresponding high-level API WriteProcessMemory
	if (isPartOfModuleMemory((W::LPVOID)ret, L"kernelbase.dll")) return;

	/* Get pid from handle */
	W::HANDLE processHandle;
	PIN_SafeCopy(&processHandle, hProcess, sizeof(W::HANDLE));

	W::DWORD remoteProcessId = W::GetProcessId(processHandle);

	/* Check if is writing inside another process */
	if (remoteProcessId != currentProcessPid) {
		string remoteProcessName = getProcessNameFromHandle(processHandle);
		verboseLog("NtWriteVirtualMemory", "Memory write of 0x%x bytes inside %s", nSize, remoteProcessName.c_str());


		remoteWrittenMemory.push_back(pair<W::LPVOID, W::SIZE_T>(lpBaseAddress, nSize));
		/* Check if there must be a redirection of the injection */

		if (redirectInjection && remoteProcessId != W::GetProcessId(hInjectionTarget)) {
			PIN_SafeCopy(hProcess, &hInjectionTarget, sizeof(W::HANDLE));
			string injectionTargetName = getProcessNameFromHandle(processHandle);
			verboseLog("NtWriteVirtualMemory", "Memory write redirected from %s to %s", remoteProcessName.c_str(), injectionTargetName.c_str());
		}
		else if (!redirectInjection) {
			PIN_SafeCopy(&hInjectionTarget, hProcess, sizeof(W::HANDLE));
			injectionTargetPid = remoteProcessId;
		}
	}
}

/* THREAD EXECUTION HOOKS */

VOID CreateRemoteThread_Before(W::HANDLE* hProcess, W::LPTHREAD_START_ROUTINE lpStartAddress, W::LPVOID lpParameter)
{

	/* Get pid from handle */
	W::HANDLE processHandle;
	PIN_SafeCopy(&processHandle, hProcess, sizeof(W::HANDLE));
	W::DWORD remoteProcessId = W::GetProcessId(processHandle);

	/* Check if the write is inside another process */
	if (remoteProcessId != currentProcessPid) {
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
	
	// Check if this API is called by the malware itself and NOT 
	// by the corresponding high-level API (CreateRemoteThread/CreateRemoteThreadEx)
	if (isPartOfModuleMemory((W::LPVOID)ret, L"kernelbase.dll")) return;

	/* Get pid from handle */
	W::HANDLE processHandle;
	PIN_SafeCopy(&processHandle, hProcess, sizeof(W::HANDLE));
	W::DWORD remoteProcessId = W::GetProcessId(processHandle);

	/* Check if the write is inside another process */
	if (remoteProcessId != currentProcessPid) {
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

VOID RtlCreateUserThread_Before(W::HANDLE* hProcess, W::LPVOID lpStartAddress, W::LPVOID lpParameter)
{

	/* Get pid from handle */
	W::HANDLE processHandle;
	PIN_SafeCopy(&processHandle, hProcess, sizeof(W::HANDLE));
	W::DWORD remoteProcessId = W::GetProcessId(processHandle);

	/* Check if the write is inside another process */
	if (remoteProcessId != currentProcessPid) {
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

VOID ResumeThread_Before(W::HANDLE hThread)
{
	W::LPVOID instructionPointer, parameterValue, threadStartingAddress;
	W::DWORD remoteProcessId;

	/* Get pid from thread handle */

	remoteProcessId = W::GetProcessIdOfThread(hThread);
	if (!remoteProcessId) {
		errorLog("Unable to retrive PID from thread handle");
		return;
	}

	if (remoteProcessId != W::GetCurrentProcessId()) {
		string remoteProcessName = getProcessNameFromPid(remoteProcessId);

		verboseLog("ResumeThread", "A remote thread inside %s will be resumed!", remoteProcessName.c_str());
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
}

VOID QueueUserAPC_Before(W::PAPCFUNC pfnAPC, W::HANDLE hThread)
{
	W::DWORD remoteProcessId;

	/* Get pid from thread handle */

	remoteProcessId = W::GetProcessIdOfThread(hThread);
	if (!remoteProcessId) {
		errorLog("Unable to retrive PID from thread handle");
		return;
	}

	if (remoteProcessId != W::GetCurrentProcessId()) {
		string remoteProcessName = getProcessNameFromPid(remoteProcessId);

		verboseLog("QueueUserAPC", "A remote thread inside %s will execute the code at %p!", remoteProcessName.c_str(), (W::LPVOID)pfnAPC);

		dumpMemoryAtAddress((W::LPVOID)pfnAPC, "QueueUserAPC");

		// Pause execution of the thread before it starts

		char* message = (char*)malloc(256);
		W::DWORD readBytes;

		sprintf(message, "\nPress a key to start the remote execution (You can put a breakpoint at %p)...", (W::LPVOID)pfnAPC);
		W::WriteConsoleA(W::GetStdHandle((W::DWORD)-11), message, strlen(message), NULL, NULL);
		W::ReadConsoleA(W::GetStdHandle((W::DWORD)-10), message, 1, &readBytes, NULL);
		free(message);
	}
}

