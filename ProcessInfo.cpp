#include "ProcessInfo.h"


ProcessInfo::ProcessInfo(IMG img)
{
	this->img = img;
	this->moduleStartAddress = IMG_StartAddress(img);
	this->moduleEndAddress = IMG_HighAddress(img);
}

ProcessInfo::~ProcessInfo()
{
}


/*
	This function checks if the instructionPointer is inside:
	- the main module of the program
	- into a dynamically allocated piece of memory
*/
bool ProcessInfo::isPartOfProgramMemory(ADDRINT instructionPointer)
{
	/* Check if instruction pointer is inside the program module*/
	if (instructionPointer >= this->moduleStartAddress && instructionPointer <= this->moduleEndAddress)
		return true;

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
