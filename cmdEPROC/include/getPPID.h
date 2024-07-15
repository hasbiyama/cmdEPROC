/*
    author: 
    hasbiyama (@3xploitZero)
    github.com/hasbiyama

*/

#include "winstruct.h"

DWORD_PTR GetParentProcessId() {
    NtQuerySystemInformation_t NtQuerySystemInformation = (NtQuerySystemInformation_t)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");
    if (!NtQuerySystemInformation) {
        printf("\n[-] Failed to get address of NtQuerySystemInformation\n");
        return 0; // Return an appropriate error value
    }

    NTSTATUS status;
    ULONG bufferSize = 0;
    PVOID buffer = NULL;
    PSYSTEM_PROCESS_INFORMATION pCurrent = NULL;
    PSYSTEM_PROCESS_INFORMATION pNext = NULL;
    DWORD_PTR parentPid = 0;

    // First call to get required buffer size
    status = NtQuerySystemInformation(SystemProcessInformation, NULL, 0, &bufferSize);
    if (status != STATUS_INFO_LENGTH_MISMATCH) {
        printf("\n[-] Failed to get buffer size for process information (%#x)\n", status);
        return 0; // Return an appropriate error value
    }

    // Allocate buffer
    buffer = malloc(bufferSize);
    if (buffer == NULL) {
        printf("\n[-] Failed to allocate buffer\n");
        return 0; // Return an appropriate error value
    }

    // Second call to actually get the process information
    status = NtQuerySystemInformation(SystemProcessInformation, buffer, bufferSize, NULL);
    if (!NT_SUCCESS(status)) {
        printf("\n[-] Failed to query system information (%#x)\n", status);
        free(buffer);
        return 0; // Return an appropriate error value
    }

    // Traverse through the list to find our own process
    pCurrent = (PSYSTEM_PROCESS_INFORMATION)buffer;
    while (pCurrent != NULL) {
        if (GetCurrentProcessId() == (DWORD_PTR)pCurrent->ProcessId) {
            // Found our process, now get the parent process id
            parentPid = (DWORD_PTR)pCurrent->InheritedFromProcessId;
            break;
        }
        // Move to the next entry
        if (pCurrent->NextEntryOffset == 0)
            break;
        pNext = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)pCurrent + pCurrent->NextEntryOffset);
        if (pNext == NULL)
            break; // Add this check to avoid dereferencing a NULL pointer
        pCurrent = pNext;
    }

    free(buffer);
    return parentPid;
}