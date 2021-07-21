#include "instrumentation.h"

ProcessInfo* procInfo = NULL;
HooksHandler* hooksHandler = NULL;

VOID traceInstrumentation(TRACE trace, VOID* v) {
    if (!hooksHandler) return;

    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {

        for (INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins)) {

            /* Get instruction pointer */
            ADDRINT ip = INS_Address(ins);

            if (!procInfo->isPartOfProgramMemory(ip))

            /*
                If there is a memory write, I want to be sure that the written
                address CHANGE the content of the written address.
                */
            if (INS_IsMemoryWrite(ins)) {
                UINT32 memOperands = INS_MemoryOperandCount(ins);

                for (UINT32 memOp = 0; memOp < memOperands; memOp++)
                {
                    if (INS_MemoryOperandIsWritten(ins, memOp))
                    {
                        unsigned char* oldByte = (unsigned char*)malloc(sizeof(unsigned char) * 4);

                        // Check before the write
                        INS_InsertPredicatedCall(
                            ins, IPOINT_BEFORE, (AFUNPTR)memWriteCheckerBefore,
                            IARG_MEMORYOP_EA, memOp,
                            IARG_ADDRINT, oldByte,
                            IARG_END);

                        // Check after the write
                        if (INS_IsValidForIpointAfter(ins))
                            INS_InsertPredicatedCall(
                                ins, IPOINT_AFTER, (AFUNPTR)memWriteCheckerAfter,
                                IARG_FAST_ANALYSIS_CALL,
                                IARG_MEMORYOP_EA, memOp,
                                IARG_ADDRINT, oldByte,
                                IARG_END);
                        else
                            INS_InsertPredicatedCall(
                                ins, IPOINT_TAKEN_BRANCH, (AFUNPTR)memWriteCheckerAfter,
                                IARG_FAST_ANALYSIS_CALL,
                                IARG_MEMORYOP_EA, memOp,
                                IARG_ADDRINT, oldByte,
                                IARG_END);
                    }
                }
            }
        }
    }
}



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
            MYINFO("SUSPECT DLL", "%s", name.c_str());
        }
        /* Hook library calls in this module */
        hooksHandler->hookApiInThisLibrary(img);
        return;
    }
}


VOID memWriteCheckerBefore(ADDRINT writtenAddress, ADDRINT writtenByte) {
    hooksHandler->writeHooksHandler(writtenAddress, writtenByte);
}

VOID memWriteCheckerAfter(ADDRINT writtenAddress, unsigned char* oldByte) {
    /*
        We want to be sure (to avoid false positives)
        that the address has been overwritten the PE Header with a different value!
    */
    return;
}