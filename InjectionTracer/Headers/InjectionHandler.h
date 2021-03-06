#pragma once
#include "pin.H"

#include <vector>
#include <string>
#include <map>
#include <stdio.h>

#include "Utils.h"
#include "PE32.h"
#include "PE64.h"

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
bool isFunctionAddress(ADDRINT address, const char* moduleName, const char* functionName);
void dumpRemoteMemory(const char * tag);
void printInjectionInfos();

void dumpMemoryAtAddress(W::LPVOID address, const char * tag);