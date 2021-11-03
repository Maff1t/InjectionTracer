#pragma once
#include "pin.h"

#include <iostream>
#include <map>
#include <set>

#include "ProcessInfo.h"
#include "Utils.h"
#include "HooksHandler.h"
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

extern map <const char*, int> counterOfUsedAPIs;
extern vector <pair <W::DWORD, W::SIZE_T>> remoteAllocatedMemory;
extern vector <pair <W::DWORD, W::SIZE_T>> remoteWrittenMemory;
extern W::HANDLE hInjectionTarget;
extern bool redirectInjection;

/* MEMORY ALLOCATION HOOKS */
VOID VirtualAlloc_After(W::LPVOID lpAddress, size_t dwSize, W::DWORD flProtect, ADDRINT ret);
VOID HeapAlloc_After(W::LPVOID returnAddress, W::SIZE_T dwBytes, ADDRINT ret);
VOID VirtualProtect_After(W::LPVOID lpAddress, size_t dwSize, W::DWORD flNewProtect, ADDRINT ret);
VOID VirtualAllocEx_Before(W::HANDLE *hProcess, W::SIZE_T dwSize, W::DWORD flProtect, W::SIZE_T * allocationSize, ADDRINT ret);
VOID VirtualAllocEx_After(W::LPVOID lpAddress, W::SIZE_T* allocationSize, ADDRINT ret);

/* WRITE MEMORY HOOKS */
VOID WriteProcessMemory_Before(W::HANDLE* hProcess, W::LPVOID lpBaseAddress, W::LPCVOID lpBuffer, W::SIZE_T nSize, ADDRINT ret);

/* THREAD EXECUTION HOOKS */
VOID CreateRemoteThread_Before(W::HANDLE* hProcess, W::LPTHREAD_START_ROUTINE lpStartAddress, W::LPVOID lpParameter, ADDRINT ret);
VOID NtCreateThreadEx_Before(W::HANDLE* hProcess, W::LPTHREAD_START_ROUTINE lpStartAddress, W::LPVOID lpParameter, ADDRINT ret);
VOID RtlCreateUserThread_Before(W::HANDLE* hProcess, W::LPVOID lpStartAddress, W::LPVOID lpParameter, ADDRINT ret);

