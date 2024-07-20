/*
    author: 
    hasbiyama (@3xploitZero)
    github.com/hasbiyama

*/

#include "getEPROC.h"

HandleProcessInfo QueryHandleNamesByPid(PWSTR procName, DWORD processId, DWORD cmpProcessID) {
    HandleProcessInfo result = { 0 };

    // Allocate initial buffer for handle information
    ULONG handleInfoSize = 0x10000;
    PSYSTEM_HANDLE_INFORMATION handleInfo = (PSYSTEM_HANDLE_INFORMATION)malloc(handleInfoSize);
    if (!handleInfo) {
        printf("\n[-] Memory allocation failed.\n");
        return result;
    }

    ULONG returnLength;
    // Query system handle information, handling buffer size dynamically
    while (NtQuerySystemInformation(SystemHandleInformation, handleInfo, handleInfoSize, &returnLength) == STATUS_INFO_LENGTH_MISMATCH) {
        handleInfoSize *= 2;
        handleInfo = (PSYSTEM_HANDLE_INFORMATION)realloc(handleInfo, handleInfoSize);
        if (!handleInfo) {
            printf("\n[-] Memory reallocation failed.\n");
            free(handleInfo);
            return result;
        }
    }

    HANDLE processHandle = OpenProcess(PROCESS_DUP_HANDLE, FALSE, processId);
    printf("\n\t[+] Opening the process (PROCESS_DUP_HANDLE)");
    // if (!processHandle) {
    //     printf("\n[-] Failed to open process %lu. Error: %lu\n", processId, GetLastError());
    //     free(handleInfo);
    //     return result;
    // }

    int handleCount = 0;
    DWORD uniqueProcessId = 0;
    BOOL found = FALSE; // Flag to track if a match is found

    wprintf(L"\n");
    // Iterate through each handle in the system handle information
    for (ULONG i = 0; i < handleInfo->HandleCount; i++) {
        SYSTEM_HANDLE handle = handleInfo->Handles[i];

        // Filter handles for the specified process and object type number
        if (handle.ProcessId != processId || handle.ObjectTypeNumber != 0x7) {
            continue;
        }

        HANDLE dupHandle;
        printf("\t[+] Duplicating Handles (DUPLICATE_SAME_ACCESS)\n");
        // Duplicate the handle for querying
        if (!DuplicateHandle(processHandle, (HANDLE)(ULONG_PTR)handle.Handle, GetCurrentProcess(), &dupHandle, 0, FALSE, DUPLICATE_SAME_ACCESS)) {
            continue;
        }

        ULONG objectNameInfoSize = 0x1000;
        POBJECT_NAME_INFORMATION objectNameInfo = (POBJECT_NAME_INFORMATION)malloc(objectNameInfoSize);
        if (!objectNameInfo) {
            printf("\n[-] Memory allocation failed.\n");
            CloseHandle(dupHandle);
            continue;
        }

        NTSTATUS status;
        ULONG returnLength;
        do {
            status = NtQueryObject(dupHandle, ObjectNameInformation, objectNameInfo, objectNameInfoSize, &returnLength);
            printf("\t[+] Performing NtQueryObject on ObjectNameInformation (_OBJECT_NAME_INFORMATION)\n");
            if (status == STATUS_INFO_LENGTH_MISMATCH) {
                objectNameInfoSize = returnLength;
                POBJECT_NAME_INFORMATION temp = (POBJECT_NAME_INFORMATION)realloc(objectNameInfo, objectNameInfoSize);
                if (!temp) {
                    printf("\n[-] Memory allocation failed.\n");
                    free(objectNameInfo);
                    CloseHandle(dupHandle);
                    continue;
                }
                objectNameInfo = temp;
            }
        } while (status == STATUS_INFO_LENGTH_MISMATCH);

        POBJECT_TYPE_INFORMATION typeInfo = NULL;
        status = NtQueryObject(dupHandle, ObjectTypeInformation, NULL, 0, &returnLength);
        printf("\t[+] Performing NtQueryObject on ObjectTypeInformation (_OBJECT_TYPE_INFORMATION)\n");
        if (status == STATUS_INFO_LENGTH_MISMATCH) {
            typeInfo = (POBJECT_TYPE_INFORMATION)malloc(returnLength);
            if (!typeInfo) {
                printf("\n[-] Memory allocation failed.\n");
                free(objectNameInfo);
                CloseHandle(dupHandle);
                continue;
            }
            status = NtQueryObject(dupHandle, ObjectTypeInformation, typeInfo, returnLength, &returnLength);
            if (!NT_SUCCESS(status)) {
                free(typeInfo);
                typeInfo = NULL;
            }
        }

        handleCount++;
        // Check if the object type is "Process"
        if (typeInfo && wcsncmp(typeInfo->TypeName.Buffer, L"Process", typeInfo->TypeName.Length / sizeof(WCHAR)) == 0) {
            // Query process information
            PROCESS_BASIC_INFORMATION pbi;
            printf("\t[+] Performing NtQueryInformationProcess on ProcessBasicInformation (_PROCESS_BASIC_INFORMATION)\n");
            if (NT_SUCCESS(NtQueryInformationProcess(dupHandle, ProcessBasicInformation, &pbi, sizeof(pbi), NULL))) {
                uniqueProcessId = (DWORD)(ULONG_PTR)pbi.UniqueProcessId;
                WCHAR processName[MAX_PATH];
                printf("\t[+] Performing GetProcessImageFileNameW\n");
                if (GetProcessImageFileNameW(dupHandle, processName, MAX_PATH) > 0) {
                    // Extract just the process name from the full path
                    WCHAR* fileName = wcsrchr(processName, L'\\');
                    fileName = (fileName) ? fileName + 1 : processName;

                    // Check if the process name matches "cmd.exe" or "powershell.exe"
                    printf("\t[+] Comparing the ProcessName (cmd.exe or powershell.exe)\n");
                    if (wcsicmp(fileName, L"cmd.exe") == 0 || wcsicmp(fileName, L"powershell.exe") == 0) {
                        // Print the handle and process information
                        printf("\n\t[+] Process Found!\n\t[*] %S PID     : [ %lu ]\n", procName, processId);
                        wprintf(L"\n\t  [!] HANDLE            : 0x%04X | 0x%02X (%.*ls) | %S (PID: %lu) | (PPID: %lu)\n",
                            handle.Handle,
                            handle.ObjectTypeNumber,
                            typeInfo ? typeInfo->TypeName.Length / sizeof(WCHAR) : 0,
                            typeInfo ? typeInfo->TypeName.Buffer : L"(Unknown)",
                            fileName,
                            uniqueProcessId,
                            (DWORD)(ULONG_PTR)pbi.InheritedFromUniqueProcessId);

                        // Check if the uniqueProcessId matches the provided processId
                        printf("\n[>] Comparing UniqueProcessId (PID of CMD/PWSH in Handle) w/ PPID (%d)\n", cmpProcessID);
                        if (uniqueProcessId == cmpProcessID) {
                            printf("\n\t[+] The PID is Matched!\n");
                            result.HandleValue = handle.Handle;
                            result.ProcessId = processId;
                            free(typeInfo);
                            free(objectNameInfo);
                            CloseHandle(dupHandle);
                            CloseHandle(processHandle);
                            free(handleInfo);
                            return result;
                            found = TRUE; // Set found flag
                            break; // Exit loop since a match is found
                        } else {
                            printf("\n\t[x] The PID is NOT Matched!\n");
                            printf("\n[>] Trying other handles\n");
                        }
                    } else {
                        printf("\n\t[x] The ProcessName is NOT cmd.exe, but %S\n", fileName);
                    }
                }
            }
        }

        wprintf(L"\n");

        free(typeInfo);
        free(objectNameInfo);
        CloseHandle(dupHandle);
    }

    CloseHandle(processHandle);
    free(handleInfo);

    // If no match found and there's a need to continue searching in other processes with the same procName
    if (!found) {
        printf("\t[x] No matching handle found in process %lu\n\n[>] Trying other processes with the same procName\n", processId);

        // Find other processes with the same procName and repeat the process
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32 pe32;
            pe32.dwSize = sizeof(PROCESSENTRY32);
            if (Process32First(snapshot, &pe32)) {
                do {
                    // Convert pe32.szExeFile (char*) to wide character string
                    WCHAR szExeFile[MAX_PATH];
                    mbstowcs(szExeFile, pe32.szExeFile, MAX_PATH);

                    // Compare wide character strings
                    if (wcsicmp(szExeFile, procName) == 0 && pe32.th32ProcessID != processId) {
                        printf("\n\t[+] Found another process with the same procName (%S), PID: %lu\n", procName, pe32.th32ProcessID);
                        // Recursive call to search handles in the found process
                        HandleProcessInfo recursiveResult = QueryHandleNamesByPid(procName, pe32.th32ProcessID, cmpProcessID);
                        if (recursiveResult.HandleValue != 0) {
                            return recursiveResult; // Return the matched handle and process ID
                        }
                    }
                } while (Process32Next(snapshot, &pe32));
            }
            CloseHandle(snapshot);
        }
    }

    return result; // Return an empty result if no match is found
}

PSYSTEM_PROCESS_INFORMATION GetProcessInformation(ULONG* bufferSize) {
    NTSTATUS status = NtQuerySystemInformation(SystemProcessInformation, NULL, 0, bufferSize);
    if (status != STATUS_INFO_LENGTH_MISMATCH) {
        printf("\n[-] Initial call to NtQuerySystemInformation failed.\n");
        exit(1);
    }

    PSYSTEM_PROCESS_INFORMATION processInfo = (PSYSTEM_PROCESS_INFORMATION)malloc(*bufferSize);
    if (!processInfo) {
        printf("\n[-] Failed to allocate memory.\n");
        exit(1);
    }

    status = NtQuerySystemInformation(SystemProcessInformation, processInfo, *bufferSize, NULL);
    if (!NT_SUCCESS(status)) {
        printf("\n[-] Second call to NtQuerySystemInformation failed.\n");
        free(processInfo);
        exit(1);
    }

    return processInfo;
}

void FindAndProcessMatchingProcess(PSYSTEM_PROCESS_INFORMATION processInfo, wchar_t* wideProcessName, DWORD_PTR parentPid, const char* programName) {
    PSYSTEM_PROCESS_INFORMATION current = processInfo;

    while (TRUE) {
        if (current->ImageName.Buffer && wcsstr(current->ImageName.Buffer, wideProcessName)) {
            // Query handle information for the current process
            HandleProcessInfo handleProcessInfo = QueryHandleNamesByPid(current->ImageName.Buffer, (DWORD)(ULONG_PTR)current->ProcessId, parentPid);

            // Print information about the process and handle found
            printf("\n[>] Finding _EPROCESS Address (%S: %d)\n", wideProcessName, handleProcessInfo.ProcessId);
            findHandlesForProcess(handleProcessInfo.ProcessId, parentPid, handleProcessInfo.HandleValue); // Assuming you have a function to handle the found handle
            printf("\n");

            break;
        }

        if (current->NextEntryOffset == 0)
            break;

        current = (PSYSTEM_PROCESS_INFORMATION)((PBYTE)current + current->NextEntryOffset);
    }
}
