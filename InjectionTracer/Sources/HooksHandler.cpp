#include "HooksHandler.h"

HooksHandler* HooksHandler::instance = NULL;
uint64_t lastRdtsc = 0;
W::ULONGLONG lastRdtscInstr = 0;
W::ULONGLONG numberOfExecutedInstructionsProgram = 0;
uint32_t rdtscCounter = 0;
uint32_t getTickCountCounter = 0;
uint32_t process32NextCounter = 0;
W::SIZE_T allocationSize = 0;

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
	//this->libraryHooks.insert(pair <string, libraryHooksId>("CreateRemoteThread", CREATEREMOTETHREAD));
	//this->libraryHooks.insert(pair <string, libraryHooksId>("CreateRemoteThreadEx", CREATEREMOTETHREAD));
	this->libraryHooks.insert(pair <string, libraryHooksId>("NtCreateThreadEx", NTCREATETHREADEX));
	this->libraryHooks.insert(pair <string, libraryHooksId>("RtlCreateUserThread", RTLCREATEUSERTHREAD));

	this->hookedLibraries.insert("KERNELBASE.dll");
	this->hookedLibraries.insert("ntdll.dll");
	return;
}


/* ------------------ API HOOK FUNCTIONS --------------------- */

void HooksHandler::hookApiInThisLibrary(IMG img)
{

	// Check if the current image must be hooked
	string imageName = IMG_Name(img);
	string fileName = getFilenameFromPath(imageName);
	if (hookedLibraries.find(fileName) == hookedLibraries.end())
		return;
	
	// Try to find the function to hook inside the image
	for (auto iter = libraryHooks.begin(); iter != libraryHooks.end(); ++iter)
	{
		/* Trying to find the routine in the image */
		string funcName = iter->first;
		RTN rtn = RTN_FindByName(img, funcName.c_str());
		if (!RTN_Valid(rtn)) continue;
		DEBUG("Hook inserted: %s->%s", imageName.c_str(), iter->first);
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
			RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)VirtualAllocEx_Before, IARG_FUNCARG_ENTRYPOINT_REFERENCE, 0, IARG_FUNCARG_ENTRYPOINT_VALUE, 2, IARG_FUNCARG_ENTRYPOINT_VALUE, 4, IARG_ADDRINT, &allocationSize, IARG_RETURN_IP, IARG_END);
			RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)VirtualAllocEx_After, IARG_FUNCRET_EXITPOINT_VALUE, IARG_ADDRINT, &allocationSize, IARG_RETURN_IP, IARG_END);
			break;
		case WRITEPROCESSMEMORY:
			RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)WriteProcessMemory_Before, IARG_FUNCARG_ENTRYPOINT_REFERENCE, 0, IARG_FUNCARG_ENTRYPOINT_VALUE, 1, IARG_FUNCARG_ENTRYPOINT_VALUE, 2, IARG_FUNCARG_ENTRYPOINT_VALUE, 3, IARG_RETURN_IP, IARG_END);
			break;
		case CREATEREMOTETHREAD:
			RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)CreateRemoteThread_Before, IARG_FUNCARG_ENTRYPOINT_REFERENCE, 0, IARG_FUNCARG_ENTRYPOINT_VALUE, 3, IARG_FUNCARG_ENTRYPOINT_VALUE, 4, IARG_RETURN_IP, IARG_END);
			break;
		case NTCREATETHREADEX:
			RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)NtCreateThreadEx_Before, IARG_FUNCARG_ENTRYPOINT_REFERENCE, 3, IARG_FUNCARG_ENTRYPOINT_VALUE, 4, IARG_FUNCARG_ENTRYPOINT_VALUE, 5, IARG_RETURN_IP, IARG_END);
			break;
		case RTLCREATEUSERTHREAD:
			RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)RtlCreateUserThread_Before, IARG_FUNCARG_ENTRYPOINT_REFERENCE, 0, IARG_FUNCARG_ENTRYPOINT_VALUE, 6, IARG_FUNCARG_ENTRYPOINT_VALUE, 7, IARG_RETURN_IP, IARG_END);
			break;
		}
		RTN_Close(rtn);
	}
}