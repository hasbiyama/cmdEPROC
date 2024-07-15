/*
    author: 
    hasbiyama (@3xploitZero)
    github.com/hasbiyama

*/

#include <Windows.h>
#include <stdio.h>
#include <wchar.h> // for wcscmp
#include <psapi.h>
#include <tlhelp32.h>

#define STATUS_INFO_LENGTH_MISMATCH 0xc0000004
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#define INITIAL_SYSTEM_HANDLE_INFORMATION_SIZE (1024 * 1024)

/* =================== ENUM =================== */


typedef enum _SYSTEM_INFORMATION_CLASS 
{ 
    SystemProcessInformation = 0x5,
    SystemHandleInformation = 0x10
    // reducted for simplicity.
} SYSTEM_INFORMATION_CLASS;

typedef enum _THREADINFOCLASS
{ ThreadBasicInformation } THREADINFOCLASS; // reducted for simplicity.

typedef enum _PROCESSINFOCLASS
{ ProcessBasicInformation } PROCESSINFOCLASS; // reducted for simplicity.

typedef enum _OBJECT_INFORMATION_CLASS {
    ObjectBasicInformation,
    ObjectNameInformation,
    ObjectTypeInformation,
    ObjectAllInformation,
    ObjectDataInformation
} OBJECT_INFORMATION_CLASS, *POBJECT_INFORMATION_CLASS;


/* =================== STRUCT =================== */


typedef LONG KPRIORITY;

typedef struct _HandleProcessInfo {
    DWORD HandleValue;
    DWORD ProcessId;
} HandleProcessInfo; // this is a costum struct.

typedef struct _PEB 
{
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    // reducted for simplicity.
} PEB, *PPEB;

typedef struct _TEB 
{
    PVOID Reserved1[12];
    // reducted for simplicity.
} TEB, *PTEB;

typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID;

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _OBJECT_TYPE_INFORMATION {
    UNICODE_STRING TypeName;
    ULONG TotalNumberOfObjects;
    ULONG TotalNumberOfHandles;
    ULONG TotalPagedPoolUsage;
    ULONG TotalNonPagedPoolUsage;
    ULONG TotalNamePoolUsage;
    ULONG TotalHandleTableUsage;
    ULONG HighWaterNumberOfObjects;
    ULONG HighWaterNumberOfHandles;
    ULONG HighWaterPagedPoolUsage;
    ULONG HighWaterNonPagedPoolUsage;
    ULONG HighWaterNamePoolUsage;
    ULONG HighWaterHandleTableUsage;
    ULONG InvalidAttributes;
    GENERIC_MAPPING GenericMapping;
    ULONG ValidAccessMask;
    BOOLEAN SecurityRequired;
    BOOLEAN MaintainHandleCount;
    ULONG PoolType;
    ULONG DefaultPagedPoolCharge;
    ULONG DefaultNonPagedPoolCharge;
} OBJECT_TYPE_INFORMATION, *POBJECT_TYPE_INFORMATION;

typedef struct _SYSTEM_HANDLE {
    ULONG ProcessId;
    BYTE ObjectTypeNumber;
    BYTE Flags;
    USHORT Handle;
    PVOID Object;
    ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE, *PSYSTEM_HANDLE;

typedef struct _SYSTEM_HANDLE_INFORMATION {
    ULONG HandleCount;
    SYSTEM_HANDLE Handles[1];
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

// ==== [COSTUMISED] SYSTEM_HANDLE_TABLE_ENTRY_INFO & SYSTEM_HANDLE_INFORMATION

typedef struct _PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EPROC
{
    USHORT UniqueProcessId;
    USHORT CreatorBackTraceIndex;
    UCHAR ObjectTypeIndex;
    UCHAR HandleAttributes;
    USHORT HandleValue;
    PVOID Object;
    ULONG GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO_EPROC, *PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EPROC;

typedef struct _SYSTEM_HANDLE_INFORMATION_EPROC
{
    ULONG NumberOfHandles;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO_EPROC Handles[1]; // Flexible array member
} SYSTEM_HANDLE_INFORMATION_EPROC, *PSYSTEM_HANDLE_INFORMATION_EPROC;

// ===========================================================================

typedef struct _OBJECT_NAME_INFORMATION {
    UNICODE_STRING Name;
} OBJECT_NAME_INFORMATION, *POBJECT_NAME_INFORMATION;

typedef struct _PROCESS_BASIC_INFORMATION
{
    NTSTATUS ExitStatus;
    PPEB PebBaseAddress;
    KAFFINITY AffinityMask;
    KPRIORITY BasePriority;
    HANDLE UniqueProcessId;
    HANDLE InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION, *PPROCESS_BASIC_INFORMATION;

typedef struct _THREAD_BASIC_INFORMATION
{
    NTSTATUS ExitStatus;
    PTEB TebBaseAddress;
    CLIENT_ID ClientId;
    KAFFINITY AffinityMask;
    KPRIORITY Priority;
    KPRIORITY BasePriority;
} THREAD_BASIC_INFORMATION, *PTHREAD_BASIC_INFORMATION;

typedef struct _SYSTEM_PROCESS_INFORMATION {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER Reserved[3];
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ImageName;
    ULONG BasePriority;
    HANDLE ProcessId;
    HANDLE InheritedFromProcessId;
} SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;

typedef NTSTATUS(NTAPI* NtDuplicateObject_t)(HANDLE, HANDLE, HANDLE, PHANDLE, ACCESS_MASK, ULONG, ULONG);
typedef NTSTATUS(NTAPI* NtQueryObject_t)(HANDLE, OBJECT_INFORMATION_CLASS, PVOID, ULONG, PULONG);
typedef NTSTATUS(NTAPI* NtQueryInformationThread_t)(HANDLE, THREADINFOCLASS, PVOID, ULONG, PULONG);
typedef NTSTATUS(NTAPI* NtQueryInformationProcess_t)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
typedef NTSTATUS(NTAPI* NtQuerySystemInformation_t)(SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);

NtDuplicateObject_t NtDuplicateObject;
NtQueryObject_t NtQueryObject;
NtQueryInformationThread_t NtQueryInformationThread;
NtQueryInformationProcess_t NtQueryInformationProcess;
NtQuerySystemInformation_t NtQuerySystemInformation;

void LoadNtFunctions() {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    NtDuplicateObject = (NtDuplicateObject_t)GetProcAddress(ntdll, "NtDuplicateObject");
    NtQueryObject = (NtQueryObject_t)GetProcAddress(ntdll, "NtQueryObject");
    NtQueryInformationThread = (NtQueryInformationThread_t)GetProcAddress(ntdll, "NtQueryInformationThread");
    NtQueryInformationProcess = (NtQueryInformationProcess_t)GetProcAddress(ntdll, "NtQueryInformationProcess");
    NtQuerySystemInformation = (NtQuerySystemInformation_t)GetProcAddress(ntdll, "NtQuerySystemInformation");
}

wchar_t* ConvertToWideChar(const char* processName) {
    static wchar_t wideProcessName[MAX_PATH];
    mbstowcs(wideProcessName, processName, MAX_PATH);
    return wideProcessName;
}

// Check if running on Windows 11
BOOL IsWindows11() {
    OSVERSIONINFOEX osvi;
    ZeroMemory(&osvi, sizeof(OSVERSIONINFOEX));
    osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
    if (GetVersionEx((LPOSVERSIONINFO)&osvi)) {
        return (osvi.dwMajorVersion == 10 && osvi.dwMinorVersion == 0 && osvi.dwBuildNumber >= 22000);
    }
    return FALSE;
}