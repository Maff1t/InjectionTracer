#pragma once
#include "pin.H"

#include <vector>
#include <string>
#include <map>

#include "Utils.h"
#include "ProcessInfo.h"

using std::vector;
using std::string;
using std::map;
using std::pair;

namespace W {
#include "Windows.h"
#include "minwindef.h"
#include "winbase.h"
#include <tlhelp32.h>

}

/* Useful variables */

extern W::HANDLE injectionTarget; 
extern map <const char*, int> counterOfUsedAPIs;

/* Useful functions */

void createInjectionTargetProcess (string processName);
bool findInjectionTargetProcess (string processName);
string getInjectedProcessName(W::HANDLE);
bool isRemoteLoadLibraryAddress(ADDRINT address);