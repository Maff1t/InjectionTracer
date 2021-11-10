#include "pin.H"
#include <fstream>

#include "Utils.h"
#include "Instrumentation.h"
#include "InjectionHandler.h"


KNOB<string> knobRedirect(KNOB_MODE_WRITEONCE, "pintool",
    "redirect", "", "[processName]. Redirect the process injection inside another process (no redirection by default).\
    \nIf the process already exists InjectionTracer uses that one, otherwise it creates the process");

KNOB<bool> knobverboseLog(KNOB_MODE_WRITEONCE, "pintool",
    "verbose", "1", "[0/1] Enable verbose output (default 1)");

bool redirectInjection = false;
W::HANDLE hStdout = NULL;

int main(int argc, char *argv[])
{

    PIN_InitSymbols();

    // GUI applications does not have a console. So I have to Allocate it to write output
    W::AllocConsole();
    W::HANDLE hStdout = W::GetStdHandle((W::DWORD)-11);

    if (PIN_Init(argc, argv)) return Usage();

    // This will catch eventual exceptions inside pin or inside the tool
    PIN_AddInternalExceptionHandler(ExceptionHandler, NULL);

    // Register function to be called to instrument Image loading
    IMG_AddInstrumentFunction(onImageLoad, 0);

    // Register function to be called when the program exit
    PIN_AddFiniFunction(onFinish, 0);

    PIN_AddFollowChildProcessFunction(followChild, NULL); // Follow child process!

    /* Parse arguments */
    string processName = knobRedirect.Value();
    if (processName != "") {
        redirectInjection = true;
        verboseLog("Injection Redirect", "Redirection inside: %s", processName.c_str());
        /* Try to find the process by name */
        if (!findInjectionTargetProcess(processName)) {
            /* Process not found, so create the process */
            createInjectionTargetProcess(processName);
        }
    }

    verboseLog("INFO", "Starting program Execution");
    /* Start the program*/
    PIN_StartProgram();


    return 0;
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */
