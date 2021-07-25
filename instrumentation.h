#pragma once
#include "pin.H"
#include "ProcessInfo.h"
#include "HooksHandler.h"
#include "Utils.h"

namespace W {
#include "Windows.h"
#include "winternl.h"
#include "minwindef.h"
}

extern ProcessInfo* procInfo;
extern HooksHandler* hooksHandler;

VOID traceInstrumentation(TRACE trace, VOID* v);
VOID onImageLoad(IMG img, VOID* v);
VOID memWriteCheckerBefore(ADDRINT writtenAddress, ADDRINT writtenByte);
VOID memWriteCheckerAfter(ADDRINT writtenAddress, unsigned char* oldByte);