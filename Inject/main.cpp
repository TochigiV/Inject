#include <Windows.h>
#include <iostream>
#include <TlHelp32.h>

#define WIN32_LEAN_AND_MEAN

BOOL LoadLibEx(HANDLE hProcess, const char* DLL)
{
	//Write the DLL path to the memory of the process we want to inject our DLL into
	void* RemoteString = VirtualAllocEx(hProcess, NULL, strlen(DLL), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	WriteProcessMemory(hProcess, RemoteString, DLL, strlen(DLL), NULL);

	//Create a remote thread in the process and call LoadLibraryA
	HANDLE hThread = CreateRemoteThread(hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleA("Kernel32.dll"), "LoadLibraryA"), RemoteString, NULL, NULL);
	
	//Wait for the exit code
	WaitForSingleObject(hThread, -1);
	DWORD eCode;
	GetExitCodeThread(hThread, &eCode);

	//Free the path string
	VirtualFreeEx(hProcess, RemoteString, strlen(DLL), MEM_RELEASE);

	if (hThread == INVALID_HANDLE_VALUE || eCode == 0) return FALSE;
	return TRUE;
}

BOOL CheckModule(HANDLE hProcess, const char* modulename)
{
	void* RemoteString = VirtualAllocEx(hProcess, NULL, strlen(modulename), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	WriteProcessMemory(hProcess, RemoteString, modulename, strlen(modulename), NULL);
	HANDLE hThread = CreateRemoteThread(hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleA("Kernel32.dll"), "GetModuleHandleA"), RemoteString, NULL, NULL);
	WaitForSingleObject(hThread, -1);
	DWORD eCode;
	GetExitCodeThread(hThread, &eCode);

	VirtualFreeEx(hProcess, RemoteString, strlen(modulename), MEM_RELEASE);

	if (hThread == INVALID_HANDLE_VALUE || eCode == 0) return FALSE;
	return TRUE;
}

DWORD GetProcessID(const char* ProcessName)
{
	DWORD pid = 0;
	PROCESSENTRY32 pe32;
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	pe32.dwSize = sizeof(PROCESSENTRY32);
	Process32First(snapshot, &pe32);
	while (Process32Next(snapshot, &pe32))
	{
		if (strcmp(ProcessName, pe32.szExeFile) == 0)
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
	SetConsoleTitle("Inject");
	std::cout << "Inject\nby Tochigi" << std::endl;
	if (argc > 2)
	{
		DWORD processID = GetProcessID(argv[1]);
		if (processID)
		{
			std::cout << "Injecting...";
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