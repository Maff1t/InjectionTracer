#include "utils.h"

INT32 Usage()
{
    cerr << "This tool prints out the number of dynamically executed " << endl <<
        "instructions, basic blocks and threads in the application." << endl << endl;

    cerr << KNOB_BASE::StringKnobSummary() << endl;

    return -1;
}

EXCEPT_HANDLING_RESULT ExceptionHandler(THREADID tid, EXCEPTION_INFO* pExceptInfo, PHYSICAL_CONTEXT* pPhysCtxt, VOID* v)
{
    EXCEPTION_CODE c = PIN_GetExceptionCode(pExceptInfo);
    EXCEPTION_CLASS cl = PIN_GetExceptionClass(c);
    std::cerr << "Exception occurred class " << cl << " : " << PIN_ExceptionToString(pExceptInfo) << std::endl;
    return EHR_UNHANDLED;
}

BOOL followChild(CHILD_PROCESS childProcess, VOID* val) {

    int argc = 0;
    const CHAR* const* argv = NULL;
    CHILD_PROCESS_GetCommandLine(childProcess, &argc, &argv);
    OS_PROCESS_ID childPid = CHILD_PROCESS_GetId(childProcess);
    std::stringstream ss;
    for (int i = 0; i < argc; i++)
        ss << argv[i] << " ";

    MYINFO("CHILDPROCESS CMD", "%s", ss.str().c_str());
    MYINFO("CHILDPROCESS PID", "%d", childPid);

    return TRUE; // To say that I want to follow the child process!
}
