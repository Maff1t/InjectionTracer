#include "pin.H"
#include <fstream>

#include "Utils.h"
#include "Instrumentation.h"
#include "InjectionHandler.h"


KNOB<string> knobRedirect(KNOB_MODE_WRITEONCE, "pintool",
    "redirect", "", "[processName]. Redirect the process injection inside another process (no redirection by default).\
    \nIf the process already exists InjectionTracer uses that one, otherwise it creates the process");

KNOB<bool> knobDumping(KNOB_MODE_WRITEONCE, "pintool",
    "dump", "1", "[0/1] Dump the injected code (default 1)");

KNOB<bool> knobFixDump(KNOB_MODE_WRITEONCE, "pintool",
    "fixdump", "1", "[0/1] Fix dumped PE the injected code (default 1)");

bool dumpMemory = false;
bool fixDump = false;
bool redirectInjection = false;

int main(int argc, char *argv[])
{

    PIN_InitSymbols();

    if (PIN_Init(argc, argv)) return Usage();

    // This will catch eventual exceptions inside pin or inside the tool
    PIN_AddInternalExceptionHandler(ExceptionHandler, NULL);

    // Register function to be called to instrument Image loading
    IMG_AddInstrumentFunction(onImageLoad, 0);

    // Register function to be called when the program exit
    PIN_AddFiniFunction(onFinish, 0);

    PIN_AddFollowChildProcessFunction(followChild, NULL); // Follow child process!

    /* Parse arguments */
    dumpMemory = knobDumping.Value();
    fixDump = knobFixDump.Value();
    string processName = knobRedirect.Value();
    if (processName != "") {
        redirectInjection = true;
        VERBOSE("Injection Redirect", "Redirection inside: %s", processName.c_str());
        /* Try to find the process by name */
        if (!findInjectionTargetProcess(processName)) {
            /* Process not found, so create the process */
            createInjectionTargetProcess(processName);
        }
    }

    /* Start the program*/
    PIN_StartProgram();


    return 0;
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */
