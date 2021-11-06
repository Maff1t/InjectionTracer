#pragma once
#include "pin.H"

#include <vector>
#include <string>
#include <map>
#include <stdio.h>

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

extern W::HANDLE hInjectionTarget;
extern W::DWORD injectionTargetPid;

extern map <const char*, int> counterOfUsedAPIs;
extern vector <pair <W::LPVOID, W::SIZE_T>> remoteAllocatedMemory;
extern vector <pair <W::LPVOID, W::SIZE_T>> remoteWrittenMemory;

/* Useful functions */

void createInjectionTargetProcess (string processName);
bool findInjectionTargetProcess (string processName);
string getInjectedProcessName(W::HANDLE);
int isLoadLibraryAddress(ADDRINT address);
void dumpRemoteMemory();
void printInjectionInfos();