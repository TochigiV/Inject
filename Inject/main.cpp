#include <Windows.h>
#include <iostream>
#include <TlHelp32.h>

#define WIN32_LEAN_AND_MEAN

#define Error() printf("Error in " __FUNCTION__ ": 0x%X\n", GetLastError()); \
				return FALSE;

BOOL LoadLibEx(HANDLE hProcess, const char* DLL)
{
	//Write the DLL path to the memory of the process we want to inject our DLL into
	if(void* RemoteString = VirtualAllocEx(hProcess, NULL, strlen(DLL), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE))
	{
		if(WriteProcessMemory(hProcess, RemoteString, DLL, strlen(DLL), NULL))
		{	
			//Call the function LoadLibraryA in the target process
			HANDLE hThread = CreateRemoteThread(hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleA("Kernel32.dll"), "LoadLibraryA"), RemoteString, NULL, NULL);
			if(hThread != INVALID_HANDLE_VALUE)
			{
				//Wait for the exit code
				if(WaitForSingleObject(hThread, -1) != WAIT_FAILED)
				{
					DWORD eCode;
					if(GetExitCodeThread(hThread, &eCode))
					{					
						//Free the path string
						if(VirtualFreeEx(hProcess, RemoteString, strlen(DLL), MEM_RELEASE))
						{
							if (eCode == NULL)
								return FALSE;
							return TRUE;
						}
						else
						{
							Error();
						}
					}
					else
					{
						Error();
					}
				}
				else
				{
					Error();
				}
			}
			else
			{
				Error();
			}
		}
		else
		{
			Error();
		}
	}
	else
	{
		Error();
	}
}

BOOL CheckModule(HANDLE hProcess, const char* moduleName)
{
	if(void* RemoteString = VirtualAllocEx(hProcess, NULL, strlen(moduleName), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE))
	{
		if(WriteProcessMemory(hProcess, RemoteString, moduleName, strlen(moduleName), NULL))
		{
			HANDLE hThread = CreateRemoteThread(hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleA("Kernel32.dll"), "GetModuleHandleA"), RemoteString, NULL, NULL);
			if(hThread != INVALID_HANDLE_VALUE)
			{
				if(WaitForSingleObject(hThread, -1) != WAIT_FAILED)
				{
					DWORD eCode;
					if(GetExitCodeThread(hThread, &eCode))
					{
						if(VirtualFreeEx(hProcess, RemoteString, strlen(moduleName), MEM_RELEASE))
						{
							if (eCode == NULL)
								return FALSE;
							return TRUE;
						}
						else
						{
							Error();
						}
					}
					else
					{
						Error();
					}
				}
				else
				{
					Error();
				}
			}
			else
			{
				Error();
			}
		}
		else
		{
			Error();
		}
	}
	else
	{
		Error();
	}
}

DWORD GetProcessID(const char* processName)
{
	DWORD pid = 0;
	PROCESSENTRY32 pe32;
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	pe32.dwSize = sizeof(PROCESSENTRY32);
	Process32First(snapshot, &pe32);
	while (Process32Next(snapshot, &pe32))
	{
		if (strcmp(processName, pe32.szExeFile) == 0)
		{
			pid = pe32.th32ProcessID;
			break;
		}
	}
	CloseHandle(snapshot);
	return pid;
}

int main(int argc, char *argv[])
{
	if (argc > 2)
	{
		DWORD processID = GetProcessID(argv[1]);
		if (processID)
		{
			std::cout << "Injecting..." << std::endl;
			HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
			if (hProc)
			{
				for (int i = 2; i < argc; i++)
				{
					if (!CheckModule(hProc, argv[i]))
					{
						char path[MAX_PATH];
						GetFullPathName(argv[i], MAX_PATH, path, NULL);
						if (!LoadLibEx(hProc, path))
						{
							std::cout << "Failed to inject \"" << argv[i] << "!\"" << std::endl;
						}
					}
					else
					{
						std::cout << "\"" << argv[i] << "\"" << " is already injected!" << std::endl;
					}
				}
				CloseHandle(hProc);
			}
			else
			{
				std::cout << "Failed to open process!" << std::endl;
			}
		}
		else
		{
			std::cout << "Failed to find process \"" << argv[1] << "!\"" << std::endl;
		}
	}
	else
	{
		std::cout << "Usage: Inject [PROCNAME] [DLLS]" << std::endl;
	}
	return 0;
}
