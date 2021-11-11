#pragma once
#include "pin.H"
#include <iostream>
#include <fstream>
#include <string>
#include <cstdio>
#include <cstdarg>

#include "stdio.h"
#include "stdlib.h"

namespace W {
	#include "Windows.h"
	#include "minwindef.h"
	#include "psapi.h"
	#include "winbase.h"
	#include "processthreadsapi.h"
}

#include <vector>

using std::cerr;
using std::string;
using std::endl;

extern W::HANDLE hStdout;

#define DEBUGGING_MODE 1
#define VERBOSE_MODE 1


INT32 Usage();
bool followChild(CHILD_PROCESS childProcess, VOID* val);
EXCEPT_HANDLING_RESULT ExceptionHandler(THREADID tid, EXCEPTION_INFO* pExceptInfo, PHYSICAL_CONTEXT* pPhysCtxt, VOID* v);


// Auxiliary functions

string getProcessPathFromHandle(W::HANDLE handle);
string getNameFromPath(string path);
string getProcessNameFromPid(W::DWORD pid);
string getProcessNameFromHandle(W::HANDLE handle);
string getCurrentProcessPath();
string GetLastErrorAsString();
char* stringToLower(string s);

// Logging functions
void log(W::HANDLE hOutput, const char* level, const char* format, va_list args);
void debugLog(const char* fmt, ...);
void detectionLog(const char* fmt, ...);
void errorLog(const char* fmt, ...);
void verboseLog(const char* title, const char* fmt, ...);