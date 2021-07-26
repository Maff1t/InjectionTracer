#include "ProcessInfo.h"


ProcessInfo::ProcessInfo(IMG img)
{
	this->mainModule = img;
	this->monitoredModules.push_back(img);
}

ProcessInfo::~ProcessInfo()
{
}


/*
	This function checks whether the instructionPointer is inside one of the following memory regions:
	- Into a monitored module
	- Into a dynamically allocated piece of memory
*/
bool ProcessInfo::isPartOfProgramMemory(ADDRINT instructionPointer)
{
	/* Check if instruction pointer is inside a monitored module*/
	for (auto it = this->monitoredModules.begin(); it != this->monitoredModules.end(); ++it) {
		if (instructionPointer >= IMG_StartAddress(*it) && instructionPointer <= IMG_HighAddress(*it))
			return true;
	}

	/* Check if instruction pointer is inside dynamically allocated memory */
	return this->isInsideAllocatedMemory(instructionPointer);
}

void ProcessInfo::insertAllocatedMemory(W::LPVOID startAddress, W::DWORD size)
{
	allocatedMemory.insert(pair<W::LPVOID, size_t>(startAddress, size));
}

void ProcessInfo::insertAllocatedWritableMemory(W::LPVOID startAddress, W::DWORD size)
{
	allocatedWritableMemory.insert(pair<W::LPVOID, size_t>(startAddress, size));
}

void ProcessInfo::insertMonitoredModule(IMG img)
{
	this->monitoredModules.push_back(img);
}

bool ProcessInfo::isInsideAllocatedMemory(ADDRINT ip)
{
	if (!this->allocatedMemory.size()) return false;

	for (auto it = allocatedMemory.begin(); it != allocatedMemory.end(); it++) {
		ADDRINT start = (ADDRINT)it->first;
		ADDRINT end = start + it->second;
		if (ip >= start && ip <= end)
			return true;
	}
	return false;
}

bool ProcessInfo::isInsideAllocatedWritableMemory(ADDRINT ip)
{
	if (!this->allocatedWritableMemory.size()) return false;

	for (auto it = allocatedWritableMemory.begin(); it != allocatedWritableMemory.end(); it++) {
		ADDRINT start = (ADDRINT)it->first;
		ADDRINT end = start + it->second;
		if (ip >= start && ip <= end)
			return true;
	}
	return false;
}
