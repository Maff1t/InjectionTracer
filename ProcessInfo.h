#pragma once
#include "pin.H"
#include <vector>
#include <set>

using std::string;
using std::vector;
using std::pair;
using std::set;

namespace W {
#include "Windows.h"
#include "winternl.h"
#include "minwindef.h"
#include "processthreadsapi.h"
}

class ProcessInfo
{
    public:

        ProcessInfo(IMG img);
        ~ProcessInfo();

        W::DWORD pid;

        /* Utils */
        bool isPartOfProgramMemory(ADDRINT instructionPointer);
        void insertAllocatedMemory(W::LPVOID startAddress, W::DWORD size);
        void insertAllocatedWritableMemory(W::LPVOID startAddress, W::DWORD size);
        void insertMonitoredModule(IMG img);
        bool isInsideAllocatedMemory(ADDRINT ip);
        bool isInsideAllocatedWritableMemory(ADDRINT ip);

    private:
        IMG mainModule;
        set<pair<W::LPVOID, size_t>> allocatedMemory; // From VirtualAlloc()
        set<pair<W::LPVOID, size_t>> allocatedWritableMemory; // From VirtualAlloc() + VirtualProtect()
        vector<IMG> monitoredModules;
};

