/*
    author: 
    hasbiyama (@3xploitZero)
    github.com/hasbiyama

*/

#include "include\analysePROC.h"

// gcc -o cmdEPROC cmdEPROC.c -s -lpsapi

int main(int argc, char* argv[]) {
    LoadNtFunctions();

    // Determine wide process name based on OS version
    wchar_t* wideProcessName = NULL;
    if (IsWindows11()) {
        OSVERSIONINFOEX osvi;
        ZeroMemory(&osvi, sizeof(OSVERSIONINFOEX));
        osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
        if (GetVersionEx((LPOSVERSIONINFO)&osvi)) {
            printf("\n[+] Windows 11 detected (Build %lu)\n", osvi.dwBuildNumber);
        } else {
            printf("\n[+] Windows 11 detected!\n");
        }
        wideProcessName = ConvertToWideChar("OpenConsole.exe");
    } else {
        wideProcessName = ConvertToWideChar("conhost.exe");
    }

    if (wideProcessName == NULL) {
        fprintf(stderr, "\n[-] Failed to convert process name to wide char.\n");
        return 1;
    }

    ULONG bufferSize = 0;
    PSYSTEM_PROCESS_INFORMATION processInfo = GetProcessInformation(&bufferSize);

    DWORD_PTR parentPid = GetParentProcessId();
    printf("\n[>] Getting PPID\n");
    if (parentPid == 0) {
        printf("\n[-] Failed to retrieve parent process ID.\n");
        free(processInfo);
        return 1;
    }
    printf("\n\t[+] PPID Found!");
    printf("\n\t[*] %s PPID : [ %lu ]\n", argv[0], parentPid);
    printf("\n[>] Finding the correct %S\n", wideProcessName);

    FindAndProcessMatchingProcess(processInfo, wideProcessName, parentPid, argv[0]);

    free(processInfo);
    return 0;
}