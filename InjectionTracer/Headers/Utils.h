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
bool is32bitProcess(W::DWORD pid);

// Logging functions
void debugLog(const char* fmt, ...);
void highlightedLog(const char* fmt, ...);
void errorLog(const char* fmt, ...);
void verboseLog(const char* title, const char* fmt, ...);
void _log(W::HANDLE hOutput, const char* level, const char* format, va_list args);


// Useful structures

typedef struct DECLSPEC_ALIGN(16) DECLSPEC_NOINITALL _CONTEXT {

    //
    // Register parameter home addresses.
    //
    // N.B. These fields are for convience - they could be used to extend the
    //      context record in the future.
    //

    W::DWORD64 P1Home;
    W::DWORD64 P2Home;
    W::DWORD64 P3Home;
    W::DWORD64 P4Home;
    W::DWORD64 P5Home;
    W::DWORD64 P6Home;

    //
    // Control flags.
    //

    W::DWORD ContextFlags;
    W::DWORD MxCsr;

    //
    // Segment Registers and processor flags.
    //

    W::WORD   SegCs;
    W::WORD   SegDs;
    W::WORD   SegEs;
    W::WORD   SegFs;
    W::WORD   SegGs;
    W::WORD   SegSs;
    W::DWORD EFlags;

    //
    // Debug registers
    //

    W::DWORD64 Dr0;
    W::DWORD64 Dr1;
    W::DWORD64 Dr2;
    W::DWORD64 Dr3;
    W::DWORD64 Dr6;
    W::DWORD64 Dr7;

    //
    // Integer registers.
    //

    W::DWORD64 Rax;
    W::DWORD64 Rcx;
    W::DWORD64 Rdx;
    W::DWORD64 Rbx;
    W::DWORD64 Rsp;
    W::DWORD64 Rbp;
    W::DWORD64 Rsi;
    W::DWORD64 Rdi;
    W::DWORD64 R8;
    W::DWORD64 R9;
    W::DWORD64 R10;
    W::DWORD64 R11;
    W::DWORD64 R12;
    W::DWORD64 R13;
    W::DWORD64 R14;
    W::DWORD64 R15;

    //
    // Program counter.
    //

    W::DWORD64 Rip;

} CONTEXT64, * PCONTEXT64;