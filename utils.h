#pragma once
#include "pin.H"
#include <iostream>
#include <fstream>
using std::cerr;
using std::string;
using std::endl;

#define MYINFO(title, fmt, ...) fprintf (stdout, "%s: ", title); fprintf(stdout, fmt, __VA_ARGS__)

INT32 Usage();
bool followChild(CHILD_PROCESS childProcess, VOID* val);
EXCEPT_HANDLING_RESULT ExceptionHandler(THREADID tid, EXCEPTION_INFO* pExceptInfo, PHYSICAL_CONTEXT* pPhysCtxt, VOID* v);

// Auxiliary functions
