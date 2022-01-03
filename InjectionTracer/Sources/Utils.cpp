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
    if (!W::GetModuleFileNameExA(handle, NULL, processName, MAX_PATH)) {
        errorLog("getProcessPathFromHandle: Unable to get process path from handle");
        return string();
    }
    return string(processName);
}

string getNameFromPath(string path)
{
    return path.substr(path.rfind("\\") + 1, path.size());
}

string getProcessNameFromPid(W::DWORD pid)
{
    W::HANDLE handle = W::OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (handle == NULL) {
        errorLog("getProcessNameFromPid: Unable to open process %d with the correct permissions", pid);
        return string();
    }
    else
        return getProcessNameFromHandle(handle);
}

string getProcessNameFromHandle(W::HANDLE handle)
{
    string processPath = getProcessPathFromHandle(handle);
    return getNameFromPath(processPath);
}

string getCurrentProcessPath()
{
    char * path = (char *)malloc(MAX_PATH);
    if (!W::GetModuleFileNameA(NULL, path, MAX_PATH)) {
        errorLog("getCurrentProcessPath: Unable to get process path");
        return string();
    }

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

    verboseLog("CHILDPROCESS CMD", "%s", ss.str().c_str());
    verboseLog("CHILDPROCESS PID", "%d", childPid);

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

char* stringToLower(string s)
{
    char* lowerString = (char*)malloc(s.size() + 1);
    for (int i = 0; i < s.size(); i++)
        lowerString[i] = tolower(s[i]);
    lowerString[s.size()] = '\x00';
    
    return lowerString;
}

const wchar_t* wcharToLower(const wchar_t* s)
{
    /*size_t size = wcslen(s);
    wchar_t * lowerString = (wchar_t *) malloc (size + 1);
    for (int i = 0; i < size; i++)
        lowerString[i] = towlower(s[i]);
    
    lowerString[size] = '\x00';

    return lowerString;*/
    std::wstring str(s);
    std::transform(str.begin(), str.end(), str.begin(), ::tolower);
    return str.c_str();
}

bool is32bitProcess(W::DWORD pid)
{
#ifdef _WIN64
    W::HANDLE hProcess = W::OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);

    if (!hProcess) {
        errorLog("is32bitProcess: Unable to get process handle");
        return false;
    }
    W::BOOL returnValue;
    W::IsWow64Process(hProcess, &returnValue);

    return returnValue;
#else
    return true; // If we are on a 32 bit system, no problem!
#endif
}

bool isPE(char* buffer)
{
    return buffer [0] == 'M' && buffer[1] == 'Z';
}

/*
    This function checks if the given address is inside the address space
    of the given module
*/
bool isPartOfModuleMemory(W::PVOID address, const wchar_t* moduleName)
{
    W::MODULEENTRY32W moduleEntry = { 0 };
    W::HANDLE moduleSnap = W::CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, currentProcessPid);

    if (!moduleSnap) return NULL;

    moduleEntry.dwSize = sizeof(moduleEntry);

    if (!W::Module32FirstW(moduleSnap, &moduleEntry)) return NULL;

    // Iterate every module of the process
    do
    {
        // Check if this module is exactly the module that i'm searching
        const wchar_t* lowerString = wcharToLower(moduleEntry.szModule);
        if (!wcscmp(lowerString, moduleName))
        {
            W::CloseHandle(moduleSnap);
            // Return true if the address is inside the address space of the module
            return address > moduleEntry.modBaseAddr && 
                    address < (moduleEntry.modBaseAddr + moduleEntry.modBaseSize);
        }
        /*if (address > moduleEntry.modBaseAddr && address < (moduleEntry.modBaseAddr + moduleEntry.modBaseSize)) {
            verboseLog("FOUND", "%ls", lowerString);
        }*/
    } while (W::Module32NextW(moduleSnap, &moduleEntry));

    W::CloseHandle(moduleSnap);
    return false;
}

void _log(W::HANDLE hOutput, const char* level, const char* format, va_list args) {
    int len;
    char* message;
    char* finalFormat;
    char* logformat = "\n[%s] %s\n";

    len = snprintf(NULL, 0, logformat, level, format);
    len++;  // Trailing null byte.

    finalFormat = (char*) malloc(len);

    len = snprintf(finalFormat, len, logformat, level, format);

    len = vsnprintf(NULL, 0, finalFormat, args);

    message = (char*)malloc(len);

    vsnprintf(message, len,finalFormat, args);
    
    // Write output
    W::WriteConsoleA(hOutput, message, strlen(message), NULL, NULL);

    free(message);
    free(finalFormat);
}

void debugLog (const char* fmt, ...) {
    if (!DEBUGGING_MODE) 
        return;

    W::HANDLE hStdout = W::GetStdHandle((W::DWORD)-11);
    
    // Set console color
    W::SetConsoleTextAttribute(hStdout, FOREGROUND_BLUE | FOREGROUND_INTENSITY);

    va_list args;
    va_start(args, fmt);
    _log(hStdout, "DEBUG", fmt, args);

    // Restore console color
    W::SetConsoleTextAttribute(hStdout, 15);
}

void errorLog(const char* fmt, ...) {
    W::HANDLE hStdout = W::GetStdHandle((W::DWORD)-11);

    // Set console color
    W::SetConsoleTextAttribute(hStdout, 4);

    va_list args;
    va_start(args, fmt);
    _log(hStdout, "ERROR", fmt, args);

    // Restore console color
    W::SetConsoleTextAttribute(hStdout, 15);
}

void highlightedLog(const char* fmt, ...) {
    W::HANDLE hStdout = W::GetStdHandle((W::DWORD)-11);

    // Set console color
    W::SetConsoleTextAttribute(hStdout, FOREGROUND_GREEN | FOREGROUND_INTENSITY);

    va_list args;
    va_start(args, fmt);
    _log(hStdout, "DETECTION", fmt, args);

    // Restore console color
    W::SetConsoleTextAttribute(hStdout, 15);
}

void verboseLog(const char* title, const char* fmt, ...) {

    if (!VERBOSE_MODE) return;

    W::HANDLE hStdout = W::GetStdHandle((W::DWORD)-11);

    // Set console color
    W::SetConsoleTextAttribute(hStdout, 14);

    va_list args;
    va_start(args, fmt);
    _log(hStdout, title, fmt, args);

    // Restore console color
    W::SetConsoleTextAttribute(hStdout, 15);
}

