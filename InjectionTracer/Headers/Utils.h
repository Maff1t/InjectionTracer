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
	#include "processthreadsapi.h"
}


using std::cerr;
using std::string;
using std::endl;

#define DEBUGGING_MODE 1
#define VERBOSE_MODE 1

#define VERBOSE(title, fmt, ...) W::SetConsoleTextAttribute(W::GetStdHandle((W::DWORD)-11), 14);if (VERBOSE_MODE) { fprintf (stdout, "\n[%s] ", title); fprintf(stdout, fmt, __VA_ARGS__); fflush(stdout); W::SetConsoleTextAttribute(W::GetStdHandle((W::DWORD)-11), 15);}
#define DEBUG(fmt, ...) if (DEBUGGING_MODE) { W::SetConsoleTextAttribute(W::GetStdHandle((W::DWORD)-11), FOREGROUND_BLUE | FOREGROUND_INTENSITY); fprintf(stdout, "\n[DEBUG] "); fprintf(stdout, fmt, __VA_ARGS__); fflush(stdout); W::SetConsoleTextAttribute(W::GetStdHandle((W::DWORD)-11), 15);}
#define ERR(fmt, ...) W::SetConsoleTextAttribute(W::GetStdHandle((W::DWORD)-11), 4);fprintf(stdout, "\n[ERR] "); fprintf(stdout, fmt, __VA_ARGS__); fflush(stdout); fflush(stdout); W::SetConsoleTextAttribute(W::GetStdHandle((W::DWORD)-11), 15);
#define DETECTION(fmt, ...) W::SetConsoleTextAttribute(W::GetStdHandle((W::DWORD)-11),FOREGROUND_GREEN | FOREGROUND_INTENSITY); fprintf(stdout, "\n\n[DETECTION] "); fprintf(stdout, fmt, __VA_ARGS__); fflush(stdout); W::SetConsoleTextAttribute(W::GetStdHandle((W::DWORD)-11), 15);

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