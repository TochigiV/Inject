#include <Windows.h>
#include <iostream>
#include <TlHelp32.h>

#define WIN32_LEAN_AND_MEAN

#define ERROREXIT(errorMessage, returnValue)  printf("\nError in " __FUNCTION__ ": " errorMessage "\nError code: 0x%X\n\n", GetLastError()); \
				return returnValue;

BOOL loadLibEx(HANDLE hProcess, const char* dll)
{
	//Allocate some memory in the target process for the DLL path string
	if (void* remoteString = VirtualAllocEx(hProcess, NULL, strlen(dll), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE))
	{
		HANDLE hThread;
		DWORD eCode;

		//Write the path of the DLL into the memory of the process
		if (!WriteProcessMemory(hProcess, remoteString, dll, strlen(dll), NULL))
		{
			ERROREXIT("Failed to write path string to memory!", FALSE);
		}

		//Call the function LoadLibraryA in the target process
		hThread = CreateRemoteThread(hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleA("Kernel32.dll"), "LoadLibraryA"), remoteString, NULL, NULL);
		if (hThread == INVALID_HANDLE_VALUE)
		{
			ERROREXIT("Failed to create remote thread!", FALSE);
		}

		//Wait for the thread to terminate
		if (WaitForSingleObject(hThread, -1) == WAIT_FAILED)
		{
			ERROREXIT("Failed to wait for thread to terminate!", FALSE);
		}

		//Get the exit code
		if (!GetExitCodeThread(hThread, &eCode))
		{
			ERROREXIT("Failed to get the exit code of the thread!", FALSE);
		}

		//Close the the handle to the remote thread
		if (!CloseHandle(hThread))
		{
			ERROREXIT("Failed to close the thread handle!", FALSE);
		}

		//Free the path string
		if (!VirtualFreeEx(hProcess, remoteString, NULL, MEM_RELEASE))
		{
			ERROREXIT("Failed to free memory for path string!", FALSE);
		}

		//Return if the exit code is 0 or not
		return (eCode != NULL);
	}
	else
	{
		ERROREXIT("Failed to allocate memory for path string!", FALSE);
	}
}

DWORD getModuleHandleEx(HANDLE hProcess, const char* moduleName)
{
	//Allocate some memory in the target process for the module name string
	if (void* remoteString = VirtualAllocEx(hProcess, NULL, strlen(moduleName), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE))
	{
		HANDLE hThread;
		DWORD eCode;

		//Write the name of the module into the memory of the process
		if (!WriteProcessMemory(hProcess, remoteString, moduleName, strlen(moduleName), NULL))
		{
			ERROREXIT("Failed to write module string to memory!", -1);
		}

		//Call the function GetModuleHandleA in the target process
		hThread = CreateRemoteThread(hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleA("Kernel32.dll"), "GetModuleHandleA"), remoteString, NULL, NULL);
		if (hThread == INVALID_HANDLE_VALUE)
		{
			ERROREXIT("Failed to create remote thread!", -1);
		}

		//Wait for the thread to terminate
		if (WaitForSingleObject(hThread, -1) == WAIT_FAILED)
		{
			ERROREXIT("Failed to wait for the thread to terminate!", -1);
		}

		//Get the exit code of the thread
		if (!GetExitCodeThread(hThread, &eCode))
		{
			ERROREXIT("Failed to get the exit code of the thread!", -1);
		}

		//Free the module name string
		if (!VirtualFreeEx(hProcess, remoteString, NULL, MEM_RELEASE))
		{
			ERROREXIT("Failed to free memory for module string!", -1);
		}

		//Close the handle to the thread
		if (!CloseHandle(hThread))
		{
			ERROREXIT("Failed to close the thread handle!", -1);
		}

		//Return the exit code
		return eCode;
	}
	else
	{
		ERROREXIT("Failed to allocate memory for module string!", -1);
	}
}

DWORD getProcessID(const char* processName)
{
	DWORD pid = 0;
	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32);
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	Process32First(snapshot, &pe32);
	while (Process32Next(snapshot, &pe32))
	{
		if (strcmp(processName, pe32.szExeFile) == 0)
		{
			pid = pe32.th32ProcessID;
			break;
		}
	}
	return pid;
}

int main(int argc, char *argv[])
{
	if (argc > 2)
	{
		DWORD processID = getProcessID(argv[1]);
		if (processID == 0)
		{
			std::cout << "Failed to find process \"" << argv[1] << "!\"" << std::endl;
			return -1;
		}

		std::cout << "Injecting..." << std::endl;

		HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
		if (!hProc)
		{
			std::cout << "Failed to open process!" << std::endl;
			return -1;
		}

		for (int i = 2; i < argc; i++)
		{
			switch (getModuleHandleEx(hProc, argv[i]))
			{
			case 0:
			{
				char path[MAX_PATH];
				GetFullPathName(argv[i], MAX_PATH, path, NULL);

				if (!loadLibEx(hProc, path))
				{
					std::cout << "Failed to inject \"" << argv[i] << "!\"" << std::endl;
				}
			}
			break;
			case -1:
				ExitProcess(-1);
			break;
			default:
				std::cout << "\"" << argv[i] << "\"" << " is already loaded in the specified process!" << std::endl;
			}
		}

		if (!CloseHandle(hProc))
		{
			ERROREXIT("Failed to close process handle!", -1);
		}
	}
	else
	{
		std::cout << "Usage: Inject [PROCNAME] [DLLS]" << std::endl;
		return -1;
	}
	return 0;
}