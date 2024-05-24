
# AMSI Bypass via VEH
### Description:
A PowerShell AMSI Bypass technique via Vectored Exception Handler (VEH). This technique does not perform assembly instruction patching, function hooking or Import Address Table (IAT) modification.
_______________

### How it works:
For this technique to work, you must first inject the VEH DLL into the PowerShell process. This can be done either by injecting the DLL or via DLL hijacking .

This technique works by setting up a hardware breakpoint on the function `AmsiScanBuffer` on all PowerShell process threads, then installing a VEH to handle the trigger of this breakpoint.

When a thread calls `AmsiScanBuffer`, the VEH will make the thread to exit the function without executing anything and setting the result of the function to `AMSI_RESULT_CLEAN`. This is all done inside the VEH, without modifying the code of the process or without any PE modifications.
_____
### Usage:
 
For demonstration purposes, this repository contains a very basic DLL injector. Use it this way:

* 1.) Compile the DLL Injector and VEH DLL.
* 2.) Open an instance of PowerShell.
* 3.) Run the DLL injector by providing the FULL PATH to the DLL. Example:
```cmd
./DLL_Injector.exe C:\Windows\Temp\AMSI_VEH.DLL
```
* 4.) PowerShell will open a MessageBox window to confirm the VEH installation.
____
### Demo:

![](https://github.com/vxCrypt0r/AMSI_VEH/blob/main/poc.gif)

________

### Disclaimer
This repository is for academic purposes, the use of this software is your responsibility.

