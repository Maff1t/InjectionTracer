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

	this->libraryHooks.insert(pair <string, libraryHooksId>("HeapAlloc", HEAPALLOC));
	this->libraryHooks.insert(pair <string, libraryHooksId>("VirtualAlloc", VIRTUALALLOC));
	this->libraryHooks.insert(pair <string, libraryHooksId>("VirtualAllocEx", VIRTUALALLOCEX));
	this->libraryHooks.insert(pair <string, libraryHooksId>("VirtualProtect", VIRTUALPROTECT));
	this->libraryHooks.insert(pair <string, libraryHooksId>("WriteProcessMemory", WRITEPROCESSMEMORY));

	return;
}


/* ------------------ API HOOK FUNCTIONS --------------------- */

void HooksHandler::hookApiInThisLibrary(IMG img)
{
	W::SIZE_T allocationSize = 0;
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
		case HEAPALLOC:
			RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)HeapAlloc_After, IARG_FUNCRET_EXITPOINT_VALUE, IARG_FUNCARG_ENTRYPOINT_VALUE, 2, IARG_RETURN_IP, IARG_END);
			break;
		case VIRTUALALLOC:
			RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)VirtualAlloc_After, IARG_FUNCRET_EXITPOINT_VALUE, IARG_FUNCARG_ENTRYPOINT_VALUE, 1, IARG_FUNCARG_ENTRYPOINT_VALUE, 3, IARG_RETURN_IP, IARG_END);
			break;
		case VIRTUALPROTECT:
			RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)VirtualProtect_After, IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_FUNCARG_ENTRYPOINT_VALUE, 1, IARG_FUNCARG_ENTRYPOINT_VALUE, 2, IARG_RETURN_IP, IARG_END);
			break; 
		case VIRTUALALLOCEX:
			RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)VirtualAllocEx_Before, IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_FUNCARG_ENTRYPOINT_VALUE, 2, IARG_FUNCARG_ENTRYPOINT_VALUE, 4, IARG_ADDRINT, &allocationSize, IARG_RETURN_IP, IARG_END);
			RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)VirtualAllocEx_After, IARG_FUNCRET_EXITPOINT_VALUE, IARG_ADDRINT, &allocationSize, IARG_RETURN_IP, IARG_END);
			break;
		case WRITEPROCESSMEMORY:
			RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)WriteProcessMemory_Before, IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_FUNCARG_ENTRYPOINT_VALUE, 1, IARG_FUNCARG_ENTRYPOINT_VALUE, 2, IARG_FUNCARG_ENTRYPOINT_VALUE, 3, IARG_RETURN_IP, IARG_END);
			break;
		}
		RTN_Close(rtn);

	}
}

/* If a monitored address is overwritten, I can delete the read/write hooks. */
/* Monitor writes*/
void HooksHandler::writeHooksHandler(ADDRINT writtenAddress, ADDRINT oldByte) {
	
	//TODO: Check if is written MZ somewhere!

}