#include "Instrumentation.h"

ProcessInfo* procInfo = NULL;
HooksHandler* hooksHandler = NULL;

VOID onImageLoad(IMG img, VOID* v) {

    if (IMG_IsMainExecutable(img)) {

        /* Initialize hooks*/
        ProcessInfo* procInfo= new ProcessInfo(img);
        hooksHandler = new HooksHandler(procInfo);
        
    }
    else {
        string name = IMG_Name(img);

        /* If this dll has a strange path, I insert his code in the red zone*/
        if (name.find("C:\\Windows\\") == string::npos) {
            VERBOSE("LOADED ANOMALOUS DLL", "%s", name.c_str());
            procInfo->insertMonitoredModule(img);
        }
        /* Hook library calls in this module */
        hooksHandler->hookApiInThisLibrary(img);
        return;
    }
}

VOID onFinish(INT32 exitCode, VOID* v)
{
    fprintf(stdout, "Do you want to dump injected memory? [(y)/n] : ");
    int response = getchar();
    if (response != 'n')
        dumpRemoteMemory();

    //printInjectionInfos();
}