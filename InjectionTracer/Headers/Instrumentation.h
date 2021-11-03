#pragma once
#include "pin.H"
#include "ProcessInfo.h"
#include "HooksHandler.h"
#include "Utils.h"
#include "InjectionHandler.h"

namespace W {
#include "Windows.h"
#include "winternl.h"
#include "minwindef.h"
}

extern ProcessInfo* procInfo;
extern HooksHandler* hooksHandler;
extern bool dumpMemory;

VOID onImageLoad(IMG img, VOID* v);
VOID onFinish(INT32 exitCode, VOID* v);
