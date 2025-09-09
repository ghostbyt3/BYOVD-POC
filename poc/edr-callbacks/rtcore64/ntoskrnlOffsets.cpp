#include "ntoskrnlOffsets.h"
#include "PdbSymbols.h"



union NtoskrnlOffsets g_ntoskrnlOffsets;

// Function to print Ntoskrnl offsets with attribute names
void PrintNtoskrnlOffsets() {
    printf("\n\n\t===================== Ntoskrnl offsets =========================\n\n");
    
    printf("\n\n[+] Callback Routines Offset\n\n");
    printf(" - PspCreateProcessNotifyRoutine:        %llx\n", g_ntoskrnlOffsets.st.PspCreateProcessNotifyRoutine);
    printf(" - PspCreateThreadNotifyRoutine:        %llx\n", g_ntoskrnlOffsets.st.PspCreateThreadNotifyRoutine);
    printf(" - PspLoadImageNotifyRoutine:        %llx\n", g_ntoskrnlOffsets.st.PspLoadImageNotifyRoutine);
    printf(" - CallbackListHead:        %llx\n", g_ntoskrnlOffsets.st.CallbackListHead);
    printf(" - PsProcessType:        %llx\n", g_ntoskrnlOffsets.st.PsProcessType);
    printf(" - PsThreadType:        %llx\n", g_ntoskrnlOffsets.st.PsThreadType);

}


void LoadNtoskrnlOffsetsFromInternet(BOOL delete_pdb) {
    symbol_ctx* sym_ctx = LoadSymbolsFromImageFile(GetNtoskrnlPath());
    if (sym_ctx == NULL) {
        return;
    }
    
    g_ntoskrnlOffsets.st.PspCreateProcessNotifyRoutine = GetSymbolOffset(sym_ctx, "PspCreateProcessNotifyRoutine");
    g_ntoskrnlOffsets.st.PspCreateThreadNotifyRoutine = GetSymbolOffset(sym_ctx, "PspCreateThreadNotifyRoutine");
    g_ntoskrnlOffsets.st.PspLoadImageNotifyRoutine = GetSymbolOffset(sym_ctx, "PspLoadImageNotifyRoutine");
    g_ntoskrnlOffsets.st.CallbackListHead = GetSymbolOffset(sym_ctx, "CallbackListHead");
    g_ntoskrnlOffsets.st.PsProcessType = GetSymbolOffset(sym_ctx, "PsProcessType");
    g_ntoskrnlOffsets.st.PsThreadType = GetSymbolOffset(sym_ctx, "PsThreadType");
    UnloadSymbols(sym_ctx, delete_pdb);
    
    // PrintNtoskrnlOffsets();
}



TCHAR g_ntoskrnlPath[MAX_PATH] = { 0 };
LPTSTR GetNtoskrnlPath() {
    if (_tcslen(g_ntoskrnlPath) == 0) {
        // Retrieves the system folder (eg C:\Windows\System32).
        GetSystemDirectory(g_ntoskrnlPath, _countof(g_ntoskrnlPath));

        // Compute ntoskrnl.exe path.
        PathAppend(g_ntoskrnlPath, TEXT("\\ntoskrnl.exe"));
    }
    return g_ntoskrnlPath;
}



void GetFileVersion(TCHAR* buffer, SIZE_T bufferLen, TCHAR* filename) {
    DWORD verHandle = 0;
    UINT size = 0;
    LPVOID lpBuffer = NULL;

    DWORD verSize = GetFileVersionInfoSize(filename, &verHandle);

    if (verSize != 0) {
        LPTSTR verData = (LPTSTR)calloc(verSize, 1);

        if (!verData) {
            printf("[!] Couldn't allocate memory to retrieve version data");
            return;
        }

        if (GetFileVersionInfo(filename, 0, verSize, verData)) {
            if (VerQueryValue(verData, TEXT("\\"), &lpBuffer, &size)) {
                if (size) {
                    VS_FIXEDFILEINFO* verInfo = (VS_FIXEDFILEINFO*)lpBuffer;
                    if (verInfo->dwSignature == 0xfeef04bd) {
                        DWORD majorVersion = (verInfo->dwFileVersionLS >> 16) & 0xffff;
                        DWORD minorVersion = (verInfo->dwFileVersionLS >> 0) & 0xffff;
                        _stprintf_s(buffer, bufferLen, TEXT("%ld-%ld"), majorVersion, minorVersion);
                        // _tprintf_or_not(TEXT("File Version: %d.%d\n"), majorVersion, minorVersion);
                    }
                }
            }
        }
        free(verData);
    }
}


TCHAR g_ntoskrnlVersion[256] = { 0 };
LPTSTR GetNtoskrnlVersion() {
    if (_tcslen(g_ntoskrnlVersion) == 0) {

        LPTSTR ntoskrnlPath = GetNtoskrnlPath();
        TCHAR versionBuffer[256] = { 0 };
        GetFileVersion(versionBuffer, _countof(versionBuffer), ntoskrnlPath);
        _stprintf_s(g_ntoskrnlVersion, 256, TEXT("ntoskrnl_%s.exe"), versionBuffer);
    }
    return g_ntoskrnlVersion;
}

