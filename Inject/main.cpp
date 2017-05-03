#include <Windows.h>
#include <iostream>

#define WIN32_LEAN_AND_MEAN

BOOL LoadLibEx(HANDLE Process, const char* DLL)
{
	void* RemoteString;
	RemoteString = (void*)VirtualAllocEx(Process, NULL, strlen(DLL), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	WriteProcessMemory(Process, (void*)RemoteString, DLL, strlen(DLL), NULL);
	HANDLE hThread = CreateRemoteThread(Process, NULL, NULL, (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleA("Kernel32.dll"), "LoadLibraryA"), RemoteString, NULL, NULL);
	WaitForSingleObject(hThread, -1);
	DWORD eCode;
	GetExitCodeThread(hThread, &eCode);
	if (hThread == INVALID_HANDLE_VALUE || eCode == 0) return FALSE;
	return TRUE;
}

int main(int argc, char *argv[])
{
	SetConsoleTitle("Inject");
	std::cout << "Inject\nby Tochigi" << std::endl;
	if (argc > 3)
	{
		HWND hWnd = FindWindow(NULL, argv[1]);
		if (hWnd)
		{
			std::cout << "Injecting..." << std::endl;
			DWORD processID;
			GetWindowThreadProcessId(hWnd, &processID);
			HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
			if (hProc)
			{
				for (int i = 2; i < argc; i++)
				{
					char path[MAX_PATH];
					GetFullPathName(argv[i], MAX_PATH, path, NULL);
					if (!LoadLibEx(hProc, path))
					{
						break;
						std::cout << "Failed to inject " << argv[i] << "!" << std::endl;
						system("pause");
						return -1;
					}
				}
				CloseHandle(hProc);
			}
			else
			{
				std::cout << "Failed to open process!" << std::endl;
				system("pause");
				return -1;
			}
		}
		else
		{
			std::cout << "Failed to find window " << argv[1] << "!" << std::endl;
			system("pause");
			return -1;
		}
	}
	else
	{
		std::cout << "Usage: Inject [WINDOWNAME] [DLLS]" << std::endl;
	}
	return 0;
}