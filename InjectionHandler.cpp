#include "InjectionHandler.h"

/*
	Create the process where the injection will be redirected
*/
bool createInjectionTargetProcess(string processName)
{

	return true;
}
/* 
	Find the process where the injection will be redirected
*/
bool findInjectionTargetProcess(string processName)
{

	return false;
}
/*
	check if the given address is the address of kernel32.LoadLibrary
	inside the target process
*/
bool isRemoteLoadLibraryAddress(ADDRINT address)
{
	return false;
}
