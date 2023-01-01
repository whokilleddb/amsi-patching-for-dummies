# AMSI Patching for babies
If you are new to the world of Windows and are trying to learn some ways to learn new techniques to add to your arsenal, [AMSI Patching](https://rastamouse.me/memory-patching-amsi-bypass/) is one of the first things you should be learning.

# Compilation

Compiling the project is as easy as:
```bash
cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tc.\src\patch_amsi.c /link /OUT:patcher.exe /SUBSYSTEM:CONSOLE /MACHINE:x64
```