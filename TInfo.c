/*
	Usermode hidden process detection, using Thread-id enumeration on parent processes
	Aims at detecting Peter Silberman's FUto rootkit which defeated the McAfee Blacklight Rootkit detection
*/
#define _WIN32_WINNT	0x0501
#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <psapi.h>
#include <shlwapi.h>
#include <conio.h>
#include "ex.h"
#define IOCTL_TDI_QUERY_INFORMATION		CTL_CODE(FILE_DEVICE_TRANSPORT, 4, METHOD_OUT_DIRECT, FILE_ANY_ACCESS)
typedef VOID *POBJECT;
typedef struct _SYSTEM_HANDLE {
	ULONG		uIdProcess;
	UCHAR		ObjectType;    // OB_TYPE_* (OB_TYPE_TYPE, etc.)
	UCHAR		Flags;         // HANDLE_FLAG_* (HANDLE_FLAG_INHERIT, etc.)
	USHORT		Handle;
	POBJECT		pObject;
	ACCESS_MASK	GrantedAccess;
} SYSTEM_HANDLE, *PSYSTEM_HANDLE;
typedef struct _SYSTEM_HANDLE_INFORMATION {
	ULONG			uCount;
	SYSTEM_HANDLE	Handles[1];
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;
typedef UNICODE_STRING *PUNICODE_STRING;
typedef const UNICODE_STRING *PCUNICODE_STRING;
#define SystemHandleInformation			16
#define STATUS_INFO_LENGTH_MISMATCH		((NTSTATUS)0xC0000004L)
#define STATUS_BUFFER_OVERFLOW			((NTSTATUS)0x80000005L)
void EnableDebugPrivilege()
{
	HANDLE hToken;
	TOKEN_PRIVILEGES tokenPriv;
	LUID luidDebug;
	if(OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken) != FALSE) {
		if(LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luidDebug) != FALSE)
		{
			tokenPriv.PrivilegeCount           = 1;
			tokenPriv.Privileges[0].Luid       = luidDebug;
			tokenPriv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
			AdjustTokenPrivileges(hToken, FALSE, &tokenPriv, sizeof(tokenPriv), NULL, NULL);
		}
	}
}
LPWSTR GetObjectInfo(HANDLE hObject, OBJECT_INFORMATION_CLASS objInfoClass)
{
	NTSTATUS ntReturn;
	HANDLE tHeap ;
	HANDLE wHeap ;
	LPWSTR lpwsReturn = NULL;
	HANDLE hHeap = GetProcessHeap();	
	DWORD dwSize = sizeof(OBJECT_NAME_INFORMATION);
	POBJECT_NAME_INFORMATION pObjectInfo;
	EnableDebugPrivilege();		
	hHeap = GetProcessHeap();
		pObjectInfo = (POBJECT_NAME_INFORMATION)HeapAlloc(hHeap,HEAP_ZERO_MEMORY,dwSize);
		ntReturn = NtQueryObject(hObject, objInfoClass, pObjectInfo, dwSize, &dwSize);
		if((ntReturn == STATUS_BUFFER_OVERFLOW) || (ntReturn == STATUS_INFO_LENGTH_MISMATCH)){
			pObjectInfo = NULL;
			wHeap = GetProcessHeap();
			pObjectInfo = (POBJECT_NAME_INFORMATION) HeapAlloc(wHeap,HEAP_ZERO_MEMORY,dwSize);
			ntReturn = NtQueryObject(hObject, objInfoClass, pObjectInfo, dwSize, &dwSize);
		}
		if((ntReturn >= STATUS_SUCCESS) && (pObjectInfo->Buffer != NULL))
		{
			tHeap = GetProcessHeap();			

			lpwsReturn = (LPWSTR)HeapAlloc(tHeap,HEAP_ZERO_MEMORY,sizeof(WCHAR) + pObjectInfo->Length);
			ZeroMemory(lpwsReturn, pObjectInfo->Length + sizeof(WCHAR));
			CopyMemory(lpwsReturn, pObjectInfo->Buffer, pObjectInfo->Length);
		}
		pObjectInfo = NULL;
	return lpwsReturn;
}
int _cdecl main(int argc, char *argv[])
{	
	CHAR lpszProcess[MAX_PATH] ;	
	NTSTATUS ntReturn;
	DWORD dwIdx = 0;
	HANDLE hHeap;
	ULONG ulSize=sizeof(SYSTEM_HANDLE_INFORMATION);	
	PSYSTEM_HANDLE_INFORMATION pHandleInfo;
	DWORD dwSize = sizeof(SYSTEM_HANDLE_INFORMATION);			
	EnableDebugPrivilege();
	hHeap  = GetProcessHeap();
	pHandleInfo = (PSYSTEM_HANDLE_INFORMATION)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, ulSize);
		ntReturn = NtQuerySystemInformation(SystemHandleInformation, pHandleInfo, ulSize, &ulSize);
		if(pHandleInfo) HeapFree(hHeap, 0, pHandleInfo);
		if(ntReturn == STATUS_INFO_LENGTH_MISMATCH){
			pHandleInfo = NULL;			
			pHandleInfo = (PSYSTEM_HANDLE_INFORMATION)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, ulSize);
			if(pHandleInfo == NULL)
				return NULL;
			ntReturn = NtQuerySystemInformation(SystemHandleInformation, pHandleInfo, ulSize, &ulSize);
		}
		if(ntReturn != STATUS_SUCCESS){
			HeapFree(hHeap, 0, pHandleInfo);
		return NULL;
		}			
		if(ntReturn == STATUS_SUCCESS){
			printf(" Found %d Handles.\n\n", pHandleInfo->uCount);
			printf("  PID\tHandle\t%-16s%-18sHandle Name\n", "Type", "Process Name");
			for(dwIdx = 0; dwIdx < pHandleInfo->uCount; dwIdx++)
			{
				HANDLE hProcess = OpenProcess(PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
					FALSE, pHandleInfo->Handles[dwIdx].uIdProcess);
				if(hProcess != INVALID_HANDLE_VALUE)
				{
					HANDLE hObject = NULL;
					if(DuplicateHandle(hProcess, (HANDLE)pHandleInfo->Handles[dwIdx].Handle,
						GetCurrentProcess(), &hObject, STANDARD_RIGHTS_REQUIRED, FALSE, 0) != FALSE)
					{
						LPWSTR lpwsName = GetObjectInfo(hObject, ObjectNameInformation);
						if(lpwsName != NULL){
							LPWSTR lpwsType = GetObjectInfo(hObject, ObjectTypeInformation);
							ZeroMemory(lpszProcess, MAX_PATH);
							GetModuleFileNameEx(hProcess, NULL, (LPWSTR)lpszProcess, MAX_PATH);
							wprintf(L"%5d\t%-18s%s",
								pHandleInfo->Handles[dwIdx].uIdProcess,
								((lstrlenW((LPCWSTR)lpszProcess) > 0)?PathFindFileName((LPCWSTR)lpszProcess):(LPCWSTR)"[System]"));
							printf("\n");
								lpwsName = NULL;
								lpwsType = NULL;								
						}						
						CloseHandle(hObject);
					}
					CloseHandle(hProcess);			
				}	
			}
			printf("\n\n");
		}else{
			printf("Error while trying to allocate memory for System Handle Information.\n");
			pHandleInfo = NULL;
	}
	_getch();
	return 0;

}
