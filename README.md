# AMSI Patching for dummies

![](https://www.siliconera.com/wp-content/uploads/2022/11/FiDpzbCaYAINoN_.jpg)

If you are new to the world of Windows and are trying to learn some ways to learn new techniques to add to your arsenal, [AMSI Patching](https://rastamouse.me/memory-patching-amsi-bypass/) is one of the first things you should be learning.

# Hat-tip

This repository takes direct inspiration from [Rasta Mouse's Blog](https://rastamouse.me/memory-patching-amsi-bypass/)

# Compilation

Compiling the project is as easy as:
```bash
cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tc.\src\patch_amsi.c /link /OUT:patcher.exe /SUBSYSTEM:CONSOLE /MACHINE:x64
```