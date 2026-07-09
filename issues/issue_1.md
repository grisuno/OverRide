# Issue #1: How was created the payload?

- **State:** open
- **Created:** 2025-10-31T08:20:58Z
- **Updated:** 2025-10-31T08:20:58Z
- **Labels:** None

---

I created an X86 payload executable using Visual Studio 2022 (v143) with CFG disabled, targeting C:\Windows\SysWOW64\mstsc.exe. The prompt shows [+] Done!, but no popup appears. However, when I use [process_overwriting](https://github.com/hasherezade/process_overwriting) demo.bin file, it works. Why is that?


C:\Users\Administrator\Desktop>injector.exe NoForm.exe C:\Windows\SysWOW64\mstsc.exe
[+] Payload: NoForm.exe
[+] Target:  C:\Windows\SysWOW64\mstsc.exe
[+] Payload mapped to virtual image of size: 110592 bytes
[+] Payload and Target architecture match (32-bit).
[+] Payload size (110592) is compatible with target size (1298432).
[+] Created suspended target process. PID: 23244
[+] Remote image base: 0x560000
[+] Payload written to remote process.
[+] Remote entry point updated.
[+] Process resumed. PID: 23244
[+] Done.



my payload code:

#pragma comment(linker, "/subsystem:"windows" /entry:"mainCRTStartup"")
//

#include <windows.h>

int main()
{
MessageBoxA(NULL,"1","1",1);
return 0;
}
