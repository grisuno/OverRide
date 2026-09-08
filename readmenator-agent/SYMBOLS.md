# Symbols

| Symbol | Kind | File:Line | Signature |
|--------|------|-----------|-----------|
| `CloseHandle` | function | `injector.c:213` | `CloseHandle(h_file);` |
| `HeapFree` | function | `injector.c:217` | `HeapFree(GetProcessHeap(), 0, raw_buffer);` |
| `ReadFile` | function | `injector.c:212` | `ReadFile(h_file, raw_buffer, raw_size, &read, NULL);` |
| `ResumeThread` | function | `injector.c:180` | `ResumeThread(pi->hThread);` |
| `SetThreadContext` | function | `injector.c:109` | `return SetThreadContext(pi->hThread, &context);` |
| `TerminateProcess` | function | `injector.c:281` | `TerminateProcess(pi.hProcess, 1);` |
| `VirtualFree` | function | `injector.c:235` | `VirtualFree(payload_image, 0, MEM_RELEASE);` |
| `Wow64SetThreadContext` | function | `injector.c:98` | `return Wow64SetThreadContext(pi->hThread, &context);` |
| `create_suspended_process` | function | `injector.c:76` | `BOOL create_suspended_process(char* path, PROCESS_INFORMATION* pi)` |
| `get_entry_point_rva` | function | `injector.c:37` | `DWORD get_entry_point_rva(BYTE* buffer)` |
| `get_image_size` | function | `injector.c:29` | `DWORD get_image_size(BYTE* buffer)` |
| `get_nt_headers` | function | `injector.c:9` | `IMAGE_NT_HEADERS* get_nt_headers(BYTE* buffer)` |
| `get_remote_image_base` | function | `injector.c:113` | `ULONGLONG get_remote_image_base(PROCESS_INFORMATION* pi, BOOL is_32bit_target)` |
| `is_64bit` | function | `injector.c:21` | `BOOL is_64bit(BYTE* buffer)` |
| `main` | function | `injector.c:189` | `int main(int argc, char* argv[])` |
| `memcpy` | function | `injector.c:58` | `memcpy(virtual_image, raw_buffer, nt_headers->OptionalHeader.SizeOfHeaders);` |
| `memset` | function | `injector.c:80` | `memset(pi, 0, sizeof(PROCESS_INFORMATION));` |
| `overwrite_and_run` | function | `injector.c:151` | `BOOL overwrite_and_run(PROCESS_INFORMATION* pi, BYTE* payload_image, DWORD payload_image_size)` |
| `pe_buffer_to_virtual_image` | function | `injector.c:45` | `BYTE* pe_buffer_to_virtual_image(BYTE* raw_buffer, DWORD* out_size)` |
| `printf` | function | `injector.c:14` | `printf("[-] Invalid DOS signature.\n");` |
| `update_remote_entry_point` | function | `injector.c:90` | `BOOL update_remote_entry_point(PROCESS_INFORMATION* pi, ULONGLONG entry_point_va, BOOL is_32bit_t...` |
