#pragma once
#include "pin.H"
#include <vector>
#include <set>

using std::string;
using std::pair;
using std::set;

namespace W {
#include "Windows.h"
#include "winternl.h"
#include "minwindef.h"
}

class ProcessInfo
{
    public:
        ProcessInfo(IMG img);
        ~ProcessInfo();

        /* Utils */
        bool isPartOfProgramMemory(ADDRINT instructionPointer);
        void insertAllocatedMemory(W::LPVOID startAddress, W::DWORD size);
        void insertAllocatedWritableMemory(W::LPVOID startAddress, W::DWORD size);
        bool isInsideAllocatedMemory(ADDRINT ip);
        bool isInsideAllocatedWritableMemory(ADDRINT ip);

    private:
        IMG img;
        ADDRINT moduleStartAddress;
        ADDRINT moduleEndAddress;
        set<pair<W::LPVOID, size_t>> allocatedMemory; // From VirtualAlloc()
        set<pair<W::LPVOID, size_t>> allocatedWritableMemory; // From VirtualAlloc() + VirtualProtect()
};

