#include "pin.H"
#include <fstream>

#include "Utils.h"
#include "Instrumentation.h"
#include "InjectionHandler.h"


KNOB<string> knobRedirect(KNOB_MODE_WRITEONCE, "pintool",
    "redirect", "", "[processName]. Redirect the process injection inside another process (no redirection by default).\
    \nIf the process already exists InjectionTracer uses that one, otherwise it creates the process");

KNOB<bool> knobDebugging(KNOB_MODE_WRITEONCE,  "pintool",
    "debug", "0", "Enable/Disable debugging mode (default 0).\
    \nDebugging mode put a breakpoint at the beginning of the injected shellcode");

KNOB<bool> knobDumping(KNOB_MODE_WRITEONCE, "pintool",
    "dump", "0", "[0/1] Dump the injected code (default 0)");

int main(int argc, char *argv[])
{

    PIN_InitSymbols();

    if (PIN_Init(argc, argv)) return Usage();

    // This will catch eventual exceptions inside pin or inside the tool
    PIN_AddInternalExceptionHandler(ExceptionHandler, NULL);

    // Register function to be called to instrument instructions
    //TRACE_AddInstrumentFunction(traceInstrumentation, 0);

    // Register function to be called to instrument Image loading
    IMG_AddInstrumentFunction(onImageLoad, 0);

    PIN_AddFollowChildProcessFunction(followChild, NULL); // Follow child process!

    /* Parse arguments */
    string processName = knobRedirect.Value();
    if (processName != "") {
        DEBUG("Redirection of process injection inside: %s", processName.c_str());
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
