
/*! @file
 *  This is an example of the PIN tool that demonstrates some basic PIN APIs 
 *  and could serve as the starting point for developing your first PIN tool
 */

#include "pin.H"
#include <fstream>

#include "utils.h"
#include "instrumentation.h"

/*
KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE,  "pintool",
    "o", "", "specify file name for MyPinTool output");
*/
int main(int argc, char *argv[])
{

    PIN_InitSymbols();

    if (PIN_Init(argc, argv)) return Usage();

    // This will catch eventual exceptions inside pin or inside the tool
    PIN_AddInternalExceptionHandler(ExceptionHandler, NULL);

    // Register function to be called to instrument instructions
    TRACE_AddInstrumentFunction(traceInstrumentation, 0);

    // Register function to be called to instrument Image loading
    IMG_AddInstrumentFunction(onImageLoad, 0);

    PIN_AddFollowChildProcessFunction(followChild, NULL); // Follow child process!

    /* Start the program*/
    PIN_StartProgram();

    return 0;
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */
