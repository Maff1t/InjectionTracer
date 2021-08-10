#pragma once
#include "pin.H"
#include <iostream>
#include <fstream>
#include <string>

#include "stdio.h"
#include "stdlib.h"

namespace W {
	#include "Windows.h"
	#include "minwindef.h"
	#include "psapi.h"
	#include "winbase.h"
}


using std::cerr;
using std::string;
using std::endl;

#define DEBUGGING_MODE 1
#define VERBOSE_MODE 1

#define VERBOSE(title, fmt, ...) if (VERBOSE_MODE) { fprintf (stdout, "\n[%s] ", title); fprintf(stdout, fmt, __VA_ARGS__); }
#define DEBUG(fmt, ...) if (DEBUGGING_MODE) { fprintf(stdout, "\n[DEBUG] "); fprintf(stdout, fmt, __VA_ARGS__); }
#define ERROR(fmt, ...) fprintf(stdout, "\n[ERROR] "); fprintf(stdout, fmt, __VA_ARGS__);
#define LOG(fmt, ...) fprintf(stdout, "\n[LOG] "); fprintf(stdout, fmt, __VA_ARGS__);
#define DETECTION(fmt, ...) fprintf(stdout, "\n\n[DETECTION] "); fprintf(stdout, fmt, __VA_ARGS__); fprintf (stdout, "\n");

INT32 Usage();
bool followChild(CHILD_PROCESS childProcess, VOID* val);
EXCEPT_HANDLING_RESULT ExceptionHandler(THREADID tid, EXCEPTION_INFO* pExceptInfo, PHYSICAL_CONTEXT* pPhysCtxt, VOID* v);


// Auxiliary functions

string getProcessPathFromHandle(W::HANDLE handle);
string getNameFromPath(string path);
string getProcessNameFromHandle(W::HANDLE handle);
string getCurrentProcessPath();
string GetLastErrorAsString();
