#include <cstdio>
#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <chrono>
#include <psapi.h>

// forward declarations
void exitAndReportWin32APIFailureIfConditionTrue(bool shouldExit, const char* errorDescription);
uint32_t GetModuleAddressWithinProcess(DWORD processId, const char* targetModuleName);


int main()
{
    char* pathToDllToInject = "C:\\Users\\sully\\source\\repos\\D2LootDropLooper\\Release\\D2LootDropLooper.dll";
    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
    int i = 0;
    int d2ProcessId = 0;
    if (Process32First(snapshot, &entry) == TRUE)
    {
        do {
            i++;
            if (stricmp(entry.szExeFile, "Game.exe") == 0)
            {
                d2ProcessId = entry.th32ProcessID;
                break;
            }
        } while (Process32Next(snapshot, &entry) == TRUE);
    }

    CloseHandle(snapshot);

    if (d2ProcessId == 0) { return 0; }
    std::cout << "Found d2 process id : " << d2ProcessId << std::endl;


    /* START OF "Acquire debug privilege" code" */
    TOKEN_PRIVILEGES NewState;
    NewState.PrivilegeCount = 1;
    if (!LookupPrivilegeValue(nullptr, SE_DEBUG_NAME, &NewState.Privileges[0].Luid)) {
        std::cout << "Could not acquire debug-privilege name: " << GetLastError() << "\n";
        return EXIT_FAILURE;
    }

    HANDLE token;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &token)) {
        std::cout << "Could not acquire process token: " << GetLastError() << "\n";
        return EXIT_FAILURE;
    }

    NewState.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (!AdjustTokenPrivileges(token, FALSE, &NewState, sizeof(NewState), nullptr, nullptr)) {
        std::cout << "Could not enable debug privilege: " << GetLastError() << "\n";
        return EXIT_FAILURE;
    }
    std::cout << "Acquired debug privilege\n";
    /* END OF "Acquire debug privilege" code" */


    HANDLE d2Process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, d2ProcessId);

    // kernel32.dll is always loaded at the same virtual memory location in every win32 process, so we don't need to worry about
    // the address being different in the D2 process than our process
    uint32_t addressOfLoadLibraryFunc = (uint32_t) GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");
    exitAndReportWin32APIFailureIfConditionTrue(addressOfLoadLibraryFunc == NULL, "Failed to find address of LoadLibraryA");



    LPVOID remoteAddrForDllPath = (LPVOID)VirtualAllocEx(d2Process, NULL, strlen(pathToDllToInject), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    exitAndReportWin32APIFailureIfConditionTrue(remoteAddrForDllPath == NULL, "Could not allocate memory in D2 process");


    BOOL result = WriteProcessMemory(d2Process, remoteAddrForDllPath, pathToDllToInject, strlen(pathToDllToInject), NULL);
    exitAndReportWin32APIFailureIfConditionTrue(result == FALSE, "Could not write to D2 process memory");


    HANDLE threadId = CreateRemoteThread(d2Process, NULL, 0, (LPTHREAD_START_ROUTINE) addressOfLoadLibraryFunc, remoteAddrForDllPath, NULL, NULL);
    exitAndReportWin32APIFailureIfConditionTrue(threadId == NULL, "Remote Thread could not be started");

    // wait for the remote thread to do its work injecting D2LootDropLooper.dll to the D2 process
    uint32_t injectedDllAddressInD2Process = -1;
    int j = 0;
    while (injectedDllAddressInD2Process == -1) {
        if (j > 10) {
            printf("Could not find D2LootDropLooper.dll in D2 process after 10 seconds\n");
            ExitProcess(1);
        }
        Sleep(1000);
        injectedDllAddressInD2Process = GetModuleAddressWithinProcess(d2ProcessId, "D2LootDropLooper.dll");
        printf("injectedDllAddressInD2Process %i\n", injectedDllAddressInD2Process);
        j++;
    }

    HMODULE dllInjectedInOurProcess = LoadLibraryA(pathToDllToInject);
    exitAndReportWin32APIFailureIfConditionTrue(dllInjectedInOurProcess == NULL, "LoadLibraryA failed");
    printf("Local address of injected dll %i\n", dllInjectedInOurProcess);

    uint32_t injectedDllAddressInOurProcess = GetModuleAddressWithinProcess(GetCurrentProcessId(), "D2LootDropLooper.dll");
    printf("injectedDllAddressInOurProcess %i\n", injectedDllAddressInOurProcess);

    uint32_t functionAddressInOurProcess = (uint32_t)GetProcAddress(dllInjectedInOurProcess, "InitLootDropLooper");
    uint32_t functionOffsetWithinDll = functionAddressInOurProcess - injectedDllAddressInOurProcess;

    uint32_t functionAddressInD2Process = injectedDllAddressInD2Process + functionOffsetWithinDll;


    LPVOID remoteAddrToPassParams = (LPVOID)VirtualAllocEx(d2Process, NULL, strlen(pathToDllToInject), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    exitAndReportWin32APIFailureIfConditionTrue(remoteAddrToPassParams == NULL, "Could not allocate memory in D2 process");


    uint32_t paramToPassToInjectedDll = 1;
    result = WriteProcessMemory(d2Process, remoteAddrToPassParams, &paramToPassToInjectedDll, sizeof(uint32_t), NULL);
    exitAndReportWin32APIFailureIfConditionTrue(result == FALSE, "Could not write to D2 process memory");

    threadId = CreateRemoteThread(d2Process, NULL, 0, (LPTHREAD_START_ROUTINE) functionAddressInD2Process, remoteAddrToPassParams, NULL, NULL);
    exitAndReportWin32APIFailureIfConditionTrue(threadId == NULL, "Remote Thread could not be started");


    CloseHandle(d2Process);
    

    return 0;
}




void exitAndReportWin32APIFailureIfConditionTrue(bool shouldExit, const char* errorDescription) {
    if (!shouldExit) return;

    DWORD error = GetLastError();
    if (error) {
        LPVOID lpMsgBuf;
        DWORD bufLen = FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            NULL, error, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPTSTR)&lpMsgBuf, 0, NULL);
        if (bufLen) {
            printf("Error from Win32 API : %s : %s \n", errorDescription, (char*)lpMsgBuf);
            LocalFree(lpMsgBuf);
        }
    }
    ExitProcess(1);
}

uint32_t GetModuleAddressWithinProcess(DWORD processId, const char* targetModuleName) {
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    exitAndReportWin32APIFailureIfConditionTrue(hProcess == NULL, "OpenProcess failed");

    HMODULE modules[1000];
    DWORD outputBytes;
    char moduleName[1000];

    BOOL result = EnumProcessModulesEx(hProcess, modules, sizeof(modules), &outputBytes, LIST_MODULES_32BIT);
    exitAndReportWin32APIFailureIfConditionTrue(result == FALSE, "EnumProcessModulesEx failed");

    int i = 0;
    for (i = 0; i < (outputBytes / sizeof(HMODULE)); i++) {
        DWORD len = GetModuleBaseName(hProcess, modules[i], moduleName, sizeof(moduleName));
        exitAndReportWin32APIFailureIfConditionTrue(len == 0, "GetModuleBaseName failed");

        if (stricmp(moduleName, targetModuleName) == 0) {
            HMODULE foundModule = modules[i];
            MODULEINFO moduleInfo;
            BOOL moduleInfoCallResult = GetModuleInformation(hProcess, foundModule, &moduleInfo, sizeof(MODULEINFO));
            exitAndReportWin32APIFailureIfConditionTrue(moduleInfoCallResult == FALSE, "GetModuleInformation failed");
            CloseHandle(hProcess);
            return (uint32_t)moduleInfo.lpBaseOfDll;
        }
    }

    CloseHandle(hProcess);
    return -1;
}