#pragma once

namespace W
{
#include "sysinfoapi.h"
#include "windef.h"
#include "winioctl.h"
#include "Windows.h"
#include "minwindef.h"
}

#include "pin.h"

#include "HooksHandler.h"
#include "Utils.h"

/* Library Hooks */
enum libraryHooksId {
	VIRTUALALLOC,
	VIRTUALPROTECT,
};

/* Library Hooks */
VOID VirtualAlloc_After(W::LPVOID lpAddress, size_t dwSize, W::DWORD flProtect, ADDRINT ret);
VOID VirtualProtect_After(W::LPVOID lpAddress, size_t dwSize, W::DWORD flNewProtect, ADDRINT ret);

