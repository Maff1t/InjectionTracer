#pragma once
#include "pin.H"
#include <iostream>
#include <fstream>

namespace W {
	#include "Windows.h"
	#include "minwindef.h"
	#include "psapi.h"
}

#include "stdio.h"
#include "stdlib.h"


using std::cerr;
using std::string;
using std::endl;

#define DEBUGGING_MODE 1

#define MYINFO(title, fmt, ...) fprintf (stdout, "%s: ", title); fprintf(stdout, fmt, __VA_ARGS__)
#define DEBUG(fmt, ...) if (DEBUGGING_MODE) fprintf(stdout, fmt, __VA_ARGS__)

INT32 Usage();
bool followChild(CHILD_PROCESS childProcess, VOID* val);
EXCEPT_HANDLING_RESULT ExceptionHandler(THREADID tid, EXCEPTION_INFO* pExceptInfo, PHYSICAL_CONTEXT* pPhysCtxt, VOID* v);

// Auxiliary functions

string getProcessPathFromHandle(W::HANDLE handle);
string getCurrentProcessPath();