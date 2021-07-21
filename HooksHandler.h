#pragma once
#include "pin.h"
#include <map>
#include <set>

#include "ProcessInfo.h"
#include "utils.h"

namespace W
{
#include "sysinfoapi.h"
#include "windef.h"
#include "winioctl.h"
#include "Windows.h"
#include "minwindef.h"
}

using std::map;
using std::set;
using std::pair;

/* Library Hooks */
enum libraryHooksId {
	VIRTUALALLOC,
	VIRTUALPROTECT,
};

/* Library Hooks */
VOID VirtualAlloc_After(W::LPVOID lpAddress, size_t dwSize, W::DWORD flProtect, ADDRINT ret);
VOID VirtualProtect_After(W::LPVOID lpAddress, size_t dwSize, W::DWORD flNewProtect, ADDRINT ret);


class HooksHandler
{
public:
	static HooksHandler* getInstance();
	HooksHandler(ProcessInfo* procInfo);
	~HooksHandler();
	VOID hookApiInThisLibrary(IMG img); // Called each time a new IMG is loaded
	VOID writeHooksHandler(ADDRINT writtenAddress, ADDRINT oldByte); // Called each time an instruction write in memory

	ProcessInfo* procInfo;

private:
	static HooksHandler* instance;
	map <string, libraryHooksId> libraryHooks;

};

