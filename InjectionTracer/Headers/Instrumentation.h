#pragma once
#include "pin.H"
#include "Utils.h"
#include "Hooks.h"
#include "InjectionHandler.h"

namespace W {
#include "Windows.h"
#include "winternl.h"
#include "minwindef.h"
}

extern W::DWORD currentProcessPid;

VOID onImageLoad(IMG img, VOID* v);
VOID onFinish(INT32 exitCode, VOID* v);