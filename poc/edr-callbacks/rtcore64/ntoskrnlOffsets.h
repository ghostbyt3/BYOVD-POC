/*

--- ntoskrnl Notify Routines' offsets from CSV functions.
--- Hardcoded patterns, with offsets for 350+ ntoskrnl versions provided in the CSV file.

*/

#pragma once

#include <Windows.h>

extern union NtoskrnlOffsets g_ntoskrnlOffsets;

enum NtoskrnlOffsetType {
    ETW_THREAT_INT_PROV_REG_HANDLE = 0,
    ETW_REG_ENTRY_GUIDENTRY,
    ETW_GUID_ENTRY_PROVIDERENABLEINFO,
    _SUPPORTED_NTOSKRNL_OFFSETS_END
};

union NtoskrnlOffsets {
    // structure version of ntoskrnl.exe's offsets
    struct {
        DWORD64 PspCreateProcessNotifyRoutine;
        DWORD64 PspCreateThreadNotifyRoutine;
        DWORD64 PspLoadImageNotifyRoutine;
        DWORD64 CallbackListHead;
        DWORD64 PsProcessType;
        DWORD64 PsThreadType;
    } st;

    // array version (usefull for code factoring)
    DWORD64 ar[_SUPPORTED_NTOSKRNL_OFFSETS_END];
};

// Print the Ntosknrl offsets.
void PrintNtoskrnlOffsets();

void LoadNtoskrnlOffsetsFromInternet(BOOL delete_pdb);

LPTSTR GetNtoskrnlPath();