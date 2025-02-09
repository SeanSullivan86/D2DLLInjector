#include <cstdio>
#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <chrono>
#include <psapi.h>

#ifndef ArraySize
#define ArraySize(x) (sizeof((x)) / sizeof((x)[0]))
#endif

std::string GetLastErrorStdStr()
{
    DWORD error = GetLastError();
    if (error)
    {
        LPVOID lpMsgBuf;
        DWORD bufLen = FormatMessage(
            FORMAT_MESSAGE_ALLOCATE_BUFFER |
            FORMAT_MESSAGE_FROM_SYSTEM |
            FORMAT_MESSAGE_IGNORE_INSERTS,
            NULL,
            error,
            MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
            (LPTSTR)&lpMsgBuf,
            0, NULL);
        if (bufLen)
        {
            LPCSTR lpMsgStr = (LPCSTR)lpMsgBuf;
            std::string result(lpMsgStr, lpMsgStr + bufLen);

            LocalFree(lpMsgBuf);

            return result;
        }
    }
    return std::string();
}

void GetModuleInfo(DWORD processId) {
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    if (hProcess == NULL) {
        printf("OpenProcess failed\n");
        std::cout << GetLastErrorStdStr() << std::endl;
        return;
    }

    HMODULE modules[1000];
    DWORD outputBytes;
    char moduleName[1000];

    BOOL x = EnumProcessModulesEx(hProcess, modules, sizeof(modules), &outputBytes, LIST_MODULES_32BIT);
    if (x == 0) {
        printf("EnumProcessModulesEx failed\n");
        std::cout << GetLastErrorStdStr() << std::endl;
        CloseHandle(hProcess);
        return;
    }

    int i = 0;
    for (i = 0; i < (outputBytes / sizeof(HMODULE)); i++) {
        int r = GetModuleBaseName(hProcess, modules[i], moduleName, sizeof(moduleName));
        if (r == 0) {
            printf("GetModuleBaseName failed\n");
            std::cout << GetLastErrorStdStr() << std::endl;
            CloseHandle(hProcess);
            return;
        }
        printf("Module %s\n", moduleName);
    }

    CloseHandle(hProcess);
}

uint32_t GetModuleAddressWithinProcess(DWORD processId, const char* targetModuleName) {
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    if (hProcess == NULL) {
        printf("OpenProcess failed\n");
        std::cout << GetLastErrorStdStr() << std::endl;
        return -1;
    }

    HMODULE modules[1000];
    DWORD outputBytes;
    char moduleName[1000];

    BOOL x = EnumProcessModulesEx(hProcess, modules, sizeof(modules), &outputBytes, LIST_MODULES_32BIT);
    if (x == 0) {
        printf("EnumProcessModulesEx failed\n");
        std::cout << GetLastErrorStdStr() << std::endl;
        CloseHandle(hProcess);
        return -1;
    }

    int i = 0;
    for (i = 0; i < (outputBytes / sizeof(HMODULE)); i++) {
        int r = GetModuleBaseName(hProcess, modules[i], moduleName, sizeof(moduleName));
        if (r == 0) {
            printf("GetModuleBaseName failed\n");
            std::cout << GetLastErrorStdStr() << std::endl;
            CloseHandle(hProcess);
            return -1;
        }
        if (stricmp(moduleName, targetModuleName) == 0) {
            HMODULE foundModule = modules[i];
            MODULEINFO moduleInfo;
            BOOL moduleInfoCallResult = GetModuleInformation(hProcess, foundModule, &moduleInfo, sizeof(MODULEINFO));
            if (moduleInfoCallResult == 0) {
                printf("GetModuleInformation failed\n");
                std::cout << GetLastErrorStdStr() << std::endl;
                CloseHandle(hProcess);
                return -1;
            }

            return (uint32_t) moduleInfo.lpBaseOfDll;
        }
        printf("Module %s\n", moduleName);
    }

    CloseHandle(hProcess);
    return -1;
}

/*
uint64_t GetModuleAddressWithinProcess(DWORD th32ProcessID, const char* moduleName) {
    MODULEENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, th32ProcessID);
    if (snapshot == INVALID_HANDLE_VALUE) {
        printf("CreateToolhelp32Snapshot failed\n");
        std::cout << GetLastErrorStdStr() << std::endl;
        return -1;
    }

    if (Module32First(snapshot, &entry)) {
        do {
            printf("ModuleName : %s\n", entry.szModule);
            if (stricmp(entry.szModule, moduleName) == 0) {
                CloseHandle(snapshot);
                return (uint64_t) entry.modBaseAddr;
            }
        } while (Module32Next(snapshot, &entry) == TRUE);
    }

    printf("No module found with name %s\n", moduleName);

    CloseHandle(snapshot);
    return -1;
}
*/




FILE* outputFile;

int main()
{
    char* pathToDllToInject = "C:\\Users\\sully\\source\\repos\\D2LootDropLooper\\Release\\D2LootDropLooper.dll";
    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
    int i = 0;
    int processId = 0;
    if (Process32First(snapshot, &entry) == TRUE)
    {
        do {
            i++;
            if (stricmp(entry.szExeFile, "Game.exe") == 0)
            {
                processId = entry.th32ProcessID;
                break;
            }
        } while (Process32Next(snapshot, &entry) == TRUE);
    }

    CloseHandle(snapshot);

    if (processId == 0) { return 0; }
    std::cout << "Found d2 process id : " << processId << std::endl;


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

    uintptr_t localDllBase = (uintptr_t) LoadLibraryA(pathToDllToInject);
    if (localDllBase == NULL) {
        printf("Injecting DLL to our process failed\n");
        std::cout << GetLastErrorStdStr() << std::endl;
        return 1;
    }
    else {
        printf("Local address of injected dll %i\n", localDllBase);
    }

    MODULEINFO moduleInfo;
    BOOL moduleInfoCallResult = GetModuleInformation(GetCurrentProcess(), (HMODULE)localDllBase, &moduleInfo, sizeof(MODULEINFO));
    if (moduleInfoCallResult == 0) {
        printf("GetModuleInformation failed\n");
        return 1;
    }
    printf("Address: %i\n", (uint32_t)moduleInfo.lpBaseOfDll);

    // GetModuleInfo(20400);

    uint32_t injectedDllAddressInOurProcess = GetModuleAddressWithinProcess(GetCurrentProcessId(), "D2LootDropLooper.dll");
    printf("injectedDllAddressInOurProcess %i\n", injectedDllAddressInOurProcess);

    uint32_t gameexeaddress = GetModuleAddressWithinProcess(20400 /* GetCurrentProcessId() */, "Game.exe");
    printf("game.exe address %i\n", gameexeaddress);


    /*

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);

    LPVOID addr = (LPVOID)GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");
    if (addr == NULL) {
        printf("Error: the LoadLibraryA function was not found inside kernel32.dll library.\n");
    }

    LPVOID arg = (LPVOID)VirtualAllocEx(hProcess, NULL, strlen(buffer), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (arg == NULL) {
        printf("Error: the memory could not be allocated inside the chosen process.\n");
        std::cout << GetLastErrorStdStr() << std::endl;
    }

    int n = WriteProcessMemory(hProcess, arg, buffer, strlen(buffer), NULL);
    if (n == 0) {
        printf("Error: there was no bytes written to the process's address space.\n");
    }

    HANDLE threadID = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)addr, arg, NULL, NULL);
    if (threadID == NULL) {
        printf("Error: the remote thread could not be created.\n");
    }
    else {
        printf("Success: the remote thread was successfully created.\n");
    }


    CloseHandle(hProcess);
    */

    return 0;
}



