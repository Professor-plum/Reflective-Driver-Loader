About
=====

Reflective Kernel Driver injection is a injection technique base off Reflective DLL injection by Stephen Fewer.
The technique bypasses Windows driver signing enforcement (KMCS).
Reflective programming is employed to perform the loading of a driver from memory into the kernel. As such the driver is responsible for loading itself by implementing a minimal Portable Executable (PE) file loader.
Injection works on Windows Vista up to Windows 10, running on x64.

An exploit for the Capcom driver is also included as a simple usage example.

Overview
========

The process of injecting a driver into the kernel is twofold. Firstly, the driver you wish to inject must be written into the kernel address space. Secondly the driver must be loaded into kernel in such a way that the driver's run time expectations are met, such as resolving its imports or relocating it to a suitable location in memory.

Assuming we have ring0 code execution and the driver we wish to inject has been written into an arbitrary location of memory kernel, Reflective Driver Injection works as follows.

* Execution is passed, either via PSCreateSystemThread() or a tiny bootstrap shellcode, to the driver's ReflectiveLoader function which is located at the beginning of the driver's code section (typically offset 0x400).
* As the driver's image will currently exists in an arbitrary location in memory the ReflectiveLoader will first calculate its own image's current location in memory so as to be able to parse its own headers for use later on.
* The ReflectiveLoader will then use MmGetSystemRoutineAddress (assumed to be passed in as arg0) to calculate the addresses of six functions required by the loader, namely ExAllocatePoolWithTag, ExFreePoolWithTag, IoCreateDriver, RtlImageDirectoryEntryToData, RtlImageNtHeader, and RtlQueryModuleInformation.
* The ReflectiveLoader will now allocate a continuous region of memory into which it will proceed to load its own image. The location is not important as the loader will correctly relocate the image later on.
* The driver's headers and sections are loaded into their new locations in memory.
* The ReflectiveLoader will then process the newly loaded copy of its image's relocation table.
* The ReflectiveLoader will then process the newly loaded copy of its image's import table, resolving any module dependencies (assuming they are already loaded into the kernel) and their respective imported function addresses.
* The ReflectiveLoader will then call IoCreateDriver passing the driver's DriverEntry exported function as the second parameter. The driver has now been successfully loaded into memory.
* Finally the ReflectiveLoader will return execution to the initial bootstrap shellcode which called it, or if it was called via PSCreateSystemThread, the thread will terminate.

Build
=====

Open the 'Reflective Driver Loading.sln' file in Visual Studio C++ and build the solution in Release mode to make Hadouken.exe and reflective_driver.sys

Usage
=====

To test load Capcom.sys into the kernel then use the Hadouken.exe to inject reflective_driver.sys into the kernel e.g.:

> Hadouken reflective_driver.sys
