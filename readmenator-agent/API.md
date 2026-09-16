# API

## injector.c

### get_nt_headers (function) `IMAGE_NT_HEADERS* get_nt_headers(BYTE* buffer)`
- Defined: `injector.c:9`
- Doc: Gets the NT Headers from a raw PE buffer.

### is_64bit (function) `BOOL is_64bit(BYTE* buffer)`
- Defined: `injector.c:21`
- Doc: Checks if the PE buffer is for a 64-bit executable.

### get_image_size (function) `DWORD get_image_size(BYTE* buffer)`
- Defined: `injector.c:29`
- Doc: Gets the SizeOfImage from the PE headers.

### get_entry_point_rva (function) `DWORD get_entry_point_rva(BYTE* buffer)`
- Defined: `injector.c:37`
- Doc: Gets the RVA of the Entry Point.

### pe_buffer_to_virtual_image (function) `BYTE* pe_buffer_to_virtual_image(BYTE* raw_buffer, DWORD* out_size)`
- Defined: `injector.c:45`
- Doc: Maps a raw PE file buffer into a virtual layout, similar to how the OS loader would map it.

### create_suspended_process (function) `BOOL create_suspended_process(char* path, PROCESS_INFORMATION* pi)`
- Defined: `injector.c:76`
- Doc: Creates a process in a suspended state.

### update_remote_entry_point (function) `BOOL update_remote_entry_point(PROCESS_INFORMATION* pi, ULONGLONG entry_point_va, BOOL is_32bit_t...`
- Defined: `injector.c:90`
- Doc: Updates the Entry Point of the remote process's main thread.

### get_remote_image_base (function) `ULONGLONG get_remote_image_base(PROCESS_INFORMATION* pi, BOOL is_32bit_target)`
- Defined: `injector.c:113`
- Doc: Gets the base address of the main module in the remote process.

### overwrite_and_run (function) `BOOL overwrite_and_run(PROCESS_INFORMATION* pi, BYTE* payload_image, DWORD payload_image_size)`
- Defined: `injector.c:151`
- Doc: Overwrites the remote process's main module with the payload.

### main (function) `int main(int argc, char* argv[])`
- Defined: `injector.c:189`
- Doc: ==================================================================== MAIN ==============================================

### printf (function) `printf("[-] Invalid DOS signature.\n");`
- Defined: `injector.c:14`

### memcpy (function) `memcpy(virtual_image, raw_buffer, nt_headers->OptionalHeader.SizeOfHeaders);`
- Defined: `injector.c:58`
- Doc: Copy headers

### memset (function) `memset(pi, 0, sizeof(PROCESS_INFORMATION));`
- Defined: `injector.c:80`

### Wow64SetThreadContext (function) `return Wow64SetThreadContext(pi->hThread, &context);`
- Defined: `injector.c:98`

### SetThreadContext (function) `return SetThreadContext(pi->hThread, &context);`
- Defined: `injector.c:109`
- Doc: endif

### ResumeThread (function) `ResumeThread(pi->hThread);`
- Defined: `injector.c:180`

### ReadFile (function) `ReadFile(h_file, raw_buffer, raw_size, &read, NULL);`
- Defined: `injector.c:212`

### CloseHandle (function) `CloseHandle(h_file);`
- Defined: `injector.c:213`

### HeapFree (function) `HeapFree(GetProcessHeap(), 0, raw_buffer);`
- Defined: `injector.c:217`

### VirtualFree (function) `VirtualFree(payload_image, 0, MEM_RELEASE);`
- Defined: `injector.c:235`

### TerminateProcess (function) `TerminateProcess(pi.hProcess, 1);`
- Defined: `injector.c:281`
