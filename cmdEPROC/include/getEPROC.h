/*
    author: 
    hasbiyama (@3xploitZero)
    github.com/hasbiyama

*/

#include "getPPID.h"

// Function to print handle information related to the EPROC addr
void printHandleOfEPROC(PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EPROC handleInfo, ULONG ppid)
{
    printf("\n\t[+] Address Found!\n");
    printf("\t[+] _EPROCESS (%u)   : [ 0x%p ]\n", ppid, (DWORD_PTR)handleInfo->Object);
}

// Function to retrieve handles for a specific process
int findHandlesForProcess(ULONG pid, ULONG ppid, USHORT HandleValue)
{
    ULONG returnLength = 0;
    ULONG SystemHandleInformationSize = INITIAL_SYSTEM_HANDLE_INFORMATION_SIZE;
    NtQuerySystemInformation_t NtQuerySystemInformation = (NtQuerySystemInformation_t)GetProcAddress(GetModuleHandle("ntdll"), "NtQuerySystemInformation");

    if (!NtQuerySystemInformation)
    {
        printf("\n[-] Failed to get address of NtQuerySystemInformation.\n");
        return 1;
    }

    NTSTATUS status;
    PSYSTEM_HANDLE_INFORMATION_EPROC handleTableInformation = NULL;

    do {
        if (handleTableInformation)
        {
            VirtualFree(handleTableInformation, 0, MEM_RELEASE);
            handleTableInformation = NULL;
        }

        handleTableInformation = (PSYSTEM_HANDLE_INFORMATION_EPROC)VirtualAlloc(NULL, SystemHandleInformationSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

        if (!handleTableInformation)
        {
            printf("\n[-] Failed to allocate memory for handle information.\n");
            return 1;
        }

        status = NtQuerySystemInformation(SystemHandleInformation, handleTableInformation, SystemHandleInformationSize, &returnLength);

        if (status == 0xc0000004 /* STATUS_INFO_LENGTH_MISMATCH */)
        {
            SystemHandleInformationSize *= 2;
        }
        else if (status != 0)
        {
            printf("\n[-] NtQuerySystemInformation failed with error code %08x.\n", status);
            VirtualFree(handleTableInformation, 0, MEM_RELEASE);
            return 1;
        }
    } while (status == 0xc0000004);

    int foundFirstMatch = 0;

    for (ULONG i = 0; i < handleTableInformation->NumberOfHandles; i++)
    {
        SYSTEM_HANDLE_TABLE_ENTRY_INFO_EPROC handleInfo = handleTableInformation->Handles[i];

        if (handleInfo.UniqueProcessId == pid && (handleInfo.ObjectTypeIndex == 7 && handleInfo.HandleValue == HandleValue))
        {
            printHandleOfEPROC(&handleInfo, ppid);
            foundFirstMatch = 1;
            break;
        }
    }

    if (!foundFirstMatch)
    {
        printf("\n[-] No matching handles found for PID %lu.\n", pid);
    }

    VirtualFree(handleTableInformation, 0, MEM_RELEASE);

    return 0;
}