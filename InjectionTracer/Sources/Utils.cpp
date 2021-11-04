#include "Utils.h"

INT32 Usage()
{
    std::cerr << "This tool prints out the number of dynamically executed " << endl <<
        "instructions, basic blocks and threads in the application." << endl << endl;

    std::cerr << KNOB_BASE::StringKnobSummary() << endl;

    return -1;
}

EXCEPT_HANDLING_RESULT ExceptionHandler(THREADID tid, EXCEPTION_INFO* pExceptInfo, PHYSICAL_CONTEXT* pPhysCtxt, VOID* v)
{
    EXCEPTION_CODE c = PIN_GetExceptionCode(pExceptInfo);
    EXCEPTION_CLASS cl = PIN_GetExceptionClass(c);
    std::cerr << "Exception occurred class " << cl << " : " << PIN_ExceptionToString(pExceptInfo) << std::endl;
    return EHR_UNHANDLED;
}

string getProcessPathFromHandle(W::HANDLE handle)
{
    char* processName = (char*)malloc(MAX_PATH);
    
    if (!W::GetModuleFileNameExA(handle, NULL, processName, MAX_PATH))
        DEBUG("getProcessPathFromHandle: Unable to get process path from handle");

    return string(processName);
}

string getNameFromPath(string path)
{
    return path.substr(path.rfind("\\") + 1, path.size());
}

string getProcessNameFromHandle(W::HANDLE handle)
{
    string processPath = getProcessPathFromHandle(handle);
    return getNameFromPath(processPath);
}

string getCurrentProcessPath()
{
    char * path = (char *)malloc(MAX_PATH);
    if (!W::GetModuleFileNameA(NULL, path, MAX_PATH))
        DEBUG("getCurrentProcessPath: Unable to get process path");

    return string(path);
}

BOOL followChild(CHILD_PROCESS childProcess, VOID* val) {

    int argc = 0;
    const CHAR* const* argv = NULL;
    CHILD_PROCESS_GetCommandLine(childProcess, &argc, &argv);
    OS_PROCESS_ID childPid = CHILD_PROCESS_GetId(childProcess);
    std::stringstream ss;
    for (int i = 0; i < argc; i++)
        ss << argv[i] << " ";

    VERBOSE("CHILDPROCESS CMD", "%s", ss.str().c_str());
    VERBOSE("CHILDPROCESS PID", "%d", childPid);

    return TRUE; // To say that I want to follow the child process!
}

string GetLastErrorAsString()
{
    //Get the ERR message ID, if any.
    W::DWORD errMessageId = W::GetLastError();
    if (errMessageId == 0) {
        return string(); //No ERR message has been recorded
    }

    W::LPSTR messageBuffer = NULL;

    //Ask Win32 to give us the string version of that message ID.
    //The parameters we pass in, tell Win32 to create the buffer that holds the message for us (because we don't yet know how long the message string will be).
    size_t size = W::FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL, errMessageId, ((((W::WORD)(LANG_NEUTRAL)) << 10) | (W::WORD)(SUBLANG_DEFAULT)), (W::LPSTR)&messageBuffer, 0, NULL);

    //Copy the ERR message into a std::string.
    string message(messageBuffer, size);

    //Free the Win32's string's buffer.
    W::LocalFree(messageBuffer);

    return message;
}

string getFilenameFromPath(string path)
{
    std::size_t found = path.rfind("\\");
    if (found != std::string::npos)
        return path.substr(found+1, path.length() - found);
    else
        return "";
}
