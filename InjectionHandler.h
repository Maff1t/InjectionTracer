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
}

/* Useful variables */

extern W::HANDLE injectionTarget; 
extern vector <string> listOfUsedAPIs; // List of APIs used for Process Injection
extern map <string, int> counterOfUsedAPIs; // Counter of APIs used for Process Injection

/* Useful functions */

bool createInjectionTargetProcess (string processName);
bool findInjectionTargetProcess(string processName);
string getInjectedProcessName(W::HANDLE);
bool isRemoteLoadLibraryAddress(ADDRINT address);