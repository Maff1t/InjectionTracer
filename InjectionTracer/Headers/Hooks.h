#pragma once
#include "pin.h"

#include <iostream>
#include <map>
#include <set>

#include "Utils.h"
#include "InjectionHandler.h"

namespace W
{
#include "sysinfoapi.h"
#include "windef.h"
#include "winioctl.h"
#include "Windows.h"
#include "minwindef.h"
}

using std::map;
using std::set;
using std::pair;


enum libraryHooksId {
	HEAPALLOC,
	VIRTUALPROTECT,
	VIRTUALALLOC,
	VIRTUALALLOCEX,
	NTALLOCATEPROCESSMEMORY,
	WRITEPROCESSMEMORY,
	NTWRITEVIRTUALMEMORY,
	CREATEREMOTETHREAD,
	NTCREATETHREADEX,
	RTLCREATEUSERTHREAD,
	SUSPENDTHREAD,
	NTQUEUEAPCTHREAD,
	QUEUEUSERAPC,
	SETWINDOWSHOOKEX,
	NTUNMAPVIEWOFSECTION,
	SETTHREADCONTEXT,
	ALERTRESUMETHREAD,
	NTALERTRESUMETHREAD,
	RESUMETHREAD,
	NTRESUMETHREAD
};

extern vector <pair <W::LPVOID, W::SIZE_T>> remoteAllocatedMemory;
extern vector <pair <W::LPVOID, W::SIZE_T>> remoteWrittenMemory;
extern W::DWORD currentProcessPid;
extern W::HANDLE hInjectionTarget;
extern W::DWORD injectionTargetPid;
extern bool redirectInjection;


//---------------------------Auxiliary Functions---------------------------
void initApiHooks();
void hookApiInThisLibrary(IMG img);

//------------------------------Function HOOKS--------------------------------

/* MEMORY ALLOCATION HOOKS */
VOID VirtualAlloc_After(W::LPVOID lpAddress, size_t dwSize, W::DWORD flProtect);
VOID HeapAlloc_After(W::LPVOID returnAddress, W::SIZE_T dwBytes);
VOID VirtualProtect_After(W::LPVOID lpAddress, size_t dwSize, W::DWORD flNewProtect);
VOID VirtualAllocEx_Before(W::HANDLE *hProcess, W::SIZE_T dwSize, W::DWORD flProtect, W::SIZE_T * allocationSize);
VOID VirtualAllocEx_After(W::LPVOID lpAddress, W::SIZE_T* allocationSize);

/* WRITE MEMORY HOOKS */
VOID WriteProcessMemory_Before(W::HANDLE* hProcess, W::LPVOID lpBaseAddress, W::LPCVOID lpBuffer, W::SIZE_T nSize);
VOID NtWriteVirtualMemory_Before(W::HANDLE* hProcess, W::LPVOID lpBaseAddress, W::LPCVOID lpBuffer, W::SIZE_T nSize, ADDRINT ret);

/* THREAD EXECUTION HOOKS */
VOID CreateRemoteThread_Before(W::HANDLE* hProcess, W::LPTHREAD_START_ROUTINE lpStartAddress, W::LPVOID lpParameter);
VOID NtCreateThreadEx_Before(W::HANDLE* hProcess, W::LPTHREAD_START_ROUTINE lpStartAddress, W::LPVOID lpParameter, ADDRINT ret);
VOID RtlCreateUserThread_Before(W::HANDLE* hProcess, W::LPVOID lpStartAddress, W::LPVOID lpParameter);
VOID ResumeThread_Before(W::HANDLE hThread);
VOID QueueUserAPC_Before(W::PAPCFUNC pfnAPC, W::HANDLE hThread);