#include "HooksHandler.h"

HooksHandler* HooksHandler::instance = NULL;
uint64_t lastRdtsc = 0;
W::ULONGLONG lastRdtscInstr = 0;
W::ULONGLONG numberOfExecutedInstructionsProgram = 0;
uint32_t rdtscCounter = 0;
uint32_t getTickCountCounter = 0;
uint32_t process32NextCounter = 0;

HooksHandler* HooksHandler::getInstance()
{
	return instance;
}

HooksHandler::~HooksHandler()
{
}

HooksHandler::HooksHandler(ProcessInfo* procInfo)
{
	this->procInfo = procInfo;
	this->instance = this;

	this->libraryHooks.insert(pair <string, libraryHooksId>("VirtualAlloc", VIRTUALALLOC));
	this->libraryHooks.insert(pair <string, libraryHooksId>("VirtualProtect", VIRTUALPROTECT));
	
	return;
}


/* ------------------ API HOOK FUNCTIONS --------------------- */

void HooksHandler::hookApiInThisLibrary(IMG img)
{

	for (auto iter = libraryHooks.begin(); iter != libraryHooks.end(); ++iter)
	{
		/* Trying to find the routine in the image */
		string funcName = iter->first;
		RTN rtn = RTN_FindByName(img, funcName.c_str());
		if (!RTN_Valid(rtn)) continue;
		REGSET regsIn;
		REGSET regsOut;
		/* Instrument the routine found */
		RTN_Open(rtn);
		switch (iter->second)
		{
		case VIRTUALALLOC:
			RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)VirtualAlloc_After, IARG_FUNCRET_EXITPOINT_VALUE, IARG_FUNCARG_ENTRYPOINT_VALUE, 1, IARG_FUNCARG_ENTRYPOINT_VALUE, 3, IARG_RETURN_IP, IARG_END);
			break;
		case VIRTUALPROTECT:
			RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)VirtualProtect_After, IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_FUNCARG_ENTRYPOINT_VALUE, 1, IARG_FUNCARG_ENTRYPOINT_VALUE, 2, IARG_RETURN_IP, IARG_END);
			break;
		}
		RTN_Close(rtn);

	}
}

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
		MYINFO("VIRTUAL ALLOC EXECUTABLE MEMORY", "%p", lpAddress);

	if (flProtect & PAGE_EXECUTE_READWRITE ||
		flProtect & PAGE_EXECUTE_WRITECOPY ||
		flProtect & PAGE_READWRITE ||
		flProtect & PAGE_WRITECOPY
		) {
		MYINFO("VIRTUAL ALLOC WRITABLE MEMORY", "%p", lpAddress);
		HooksHandler::getInstance()->procInfo->insertAllocatedWritableMemory(lpAddress, dwSize);
	}
		

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
		MYINFO("VIRTUAL PROTECT Executable memory", " %p", lpAddress);
	}
	
	if (flNewProtect & PAGE_EXECUTE_READWRITE || 
		flNewProtect & PAGE_EXECUTE_WRITECOPY ||
		flNewProtect & PAGE_READWRITE ||
		flNewProtect & PAGE_WRITECOPY
		) {
		MYINFO("VIRTUAL ALLOC WRITABLE MEMORY", "%p", lpAddress);
		HooksHandler::getInstance()->procInfo->insertAllocatedWritableMemory(lpAddress, dwSize);
	}

}

/* If a monitored address is overwritten, I can delete the read/write hooks. */
/* Monitor writes*/
void HooksHandler::writeHooksHandler(ADDRINT writtenAddress, ADDRINT oldByte) {
	
	//TODO: Check if is written MZ somewhere!

}