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

VOID VirtualAllocEx_Before(W::HANDLE hProcess, W::SIZE_T dwSize, W::DWORD flProtect, W::SIZE_T* allocationSize, ADDRINT ret)
{

	if (!HooksHandler::getInstance()->procInfo->isPartOfProgramMemory(ret)) return;
	auto it = counterOfUsedAPIs.find("VirtualAllocEx");
	if (it != counterOfUsedAPIs.end())
		counterOfUsedAPIs["VirtualAllocEx"] += 1;
	else
		counterOfUsedAPIs["VirtualAllocEx"] = 1;

	/* Get process path from handle */
	W::DWORD remoteProcessPID = W::GetProcessId(hProcess);
	
	VERBOSE("VirtualAllocEx", "Try allocation inside PID %d of %d bytes", remoteProcessPID, dwSize);

	/* Check if the allocation is inside another process */
	if (remoteProcessPID != HooksHandler::getInstance()->procInfo->pid) {

		/* Check if there must be a redirection of the injection */
		PIN_SafeCopy(allocationSize, &dwSize, sizeof(W::SIZE_T));
		if (redirectInjection && remoteProcessPID != W::GetProcessId(hInjectionTarget)) {
			VERBOSE("VirtualAllocEx Redirection", "VirtualAllocEx detected inside remote process, it will be redirected");
			PIN_SafeCopy(&hProcess, &hInjectionTarget, sizeof(W::HANDLE));
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
