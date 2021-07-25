#pragma once
#include "pin.h"
#include <map>
#include <set>

#include "ProcessInfo.h"
#include "Utils.h"
#include "HooksHandler.h"

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
VOID VirtualAlloc_After(W::LPVOID lpAddress, size_t dwSize, W::DWORD flProtect, ADDRINT ret);
VOID VirtualProtect_After(W::LPVOID lpAddress, size_t dwSize, W::DWORD flNewProtect, ADDRINT ret);