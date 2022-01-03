#include "Instrumentation.h"

W::DWORD currentProcessPid = 0;

VOID onImageLoad(IMG img, VOID* v) {
    currentProcessPid = W::GetCurrentProcessId();

    if (IMG_IsMainExecutable(img)) 
        initApiHooks();
    else 
        hookApiInThisLibrary(img);
}

VOID onFinish(INT32 exitCode, VOID* v)
{
    
    dumpRemoteMemory("END");

    //printInjectionInfos();
}