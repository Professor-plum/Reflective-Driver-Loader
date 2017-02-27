#include <ntifs.h>

#define CONVERT_RVA(base, offset) ((PVOID)((PUCHAR)(base) + (ULONG)(offset)))
#define TAG 0x6D756C50

typedef PVOID(NTAPI * EXALLOCATEPOOLWITHTAG)(_In_ POOL_TYPE PoolType, _In_ SIZE_T NumberOfBytes, _In_ ULONG Tag);
typedef VOID(NTAPI *EXFREEPOOLWITHTAG)(_In_ PVOID P, _In_ ULONG Tag);
typedef NTSTATUS(NTAPI * IOCREATEDRIVER)(_In_ PUNICODE_STRING DriverName, _In_opt_ PDRIVER_INITIALIZE InitializationFunction);
typedef PVOID(NTAPI * MMGETSYSTEMROUTINEADDRESS)(_In_ PUNICODE_STRING SystemRoutineName);
typedef PIMAGE_NT_HEADERS(NTAPI *RTLIMAGENTHEADER)(IN PVOID ModuleAddress);
typedef PVOID(NTAPI *RTLIMAGEDIRECTORYENTRYTODATA)(IN PVOID Base, IN BOOLEAN MappedAsImage, IN USHORT DirectoryEntry, OUT PULONG Size);
typedef NTSTATUS(NTAPI *RTLQUERYMODULEINFORMATION)(ULONG *InformationLength, ULONG SizePerModule, PVOID InformationBuffer);

typedef struct _LDRFUNCS
{
	EXALLOCATEPOOLWITHTAG ExAllocatePoolWithTag;
	EXFREEPOOLWITHTAG ExFreePoolWithTag;
	IOCREATEDRIVER IoCreateDriver;
	MMGETSYSTEMROUTINEADDRESS MmGetSystemRoutineAddress;
	RTLIMAGEDIRECTORYENTRYTODATA RtlImageDirectoryEntryToData;
	RTLIMAGENTHEADER RtlImageNtHeader;
	RTLQUERYMODULEINFORMATION RtlQueryModuleInformation;
} LDRFUNCS, *PLDRFUNCS;

typedef struct _RTL_MODULE_EXTENDED_INFO
{
	PVOID ImageBase;
	ULONG ImageSize;
	USHORT FileNameOffset;
	CHAR FullPathName[0x100];
} RTL_MODULE_EXTENDED_INFO, *PRTL_MODULE_EXTENDED_INFO;

NTSTATUS FindImports(PLDRFUNCS ft, PVOID hDriver);
NTSTATUS DoRelocation(PLDRFUNCS ft, PVOID hDriver);
NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath);
PVOID GetRoutineByName(PLDRFUNCS ft, PVOID hDriver, LPCSTR FunctionName);
PVOID GetModuleByName(PLDRFUNCS ft, LPCSTR driverName);
