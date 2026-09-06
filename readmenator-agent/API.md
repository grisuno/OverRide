# API

## injector.c

### get_nt_headers `IMAGE_NT_HEADERS* get_nt_headers(BYTE* buffer)`
- Defined: `injector.c:9`
- Doc: Gets the NT Headers from a raw PE buffer.

### is_64bit `BOOL is_64bit(BYTE* buffer)`
- Defined: `injector.c:21`
- Doc: Checks if the PE buffer is for a 64-bit executable.

### get_image_size `DWORD get_image_size(BYTE* buffer)`
- Defined: `injector.c:29`
- Doc: Gets the SizeOfImage from the PE headers.

### get_entry_point_rva `DWORD get_entry_point_rva(BYTE* buffer)`
- Defined: `injector.c:37`
- Doc: Gets the RVA of the Entry Point.

### pe_buffer_to_virtual_image `BYTE* pe_buffer_to_virtual_image(BYTE* raw_buffer, DWORD* out_size)`
- Defined: `injector.c:45`
- Doc: Maps a raw PE file buffer into a virtual layout, similar to how the OS loader would map it.

### create_suspended_process `BOOL create_suspended_process(char* path, PROCESS_INFORMATION* pi)`
- Defined: `injector.c:76`
- Doc: Creates a process in a suspended state.

### update_remote_entry_point `BOOL update_remote_entry_point(PROCESS_INFORMATION* pi, ULONGLONG entry_point_va, BOOL is_32bit_t...`
- Defined: `injector.c:90`
- Doc: Updates the Entry Point of the remote process's main thread.

### get_remote_image_base `ULONGLONG get_remote_image_base(PROCESS_INFORMATION* pi, BOOL is_32bit_target)`
- Defined: `injector.c:113`
- Doc: Gets the base address of the main module in the remote process.

### overwrite_and_run `BOOL overwrite_and_run(PROCESS_INFORMATION* pi, BYTE* payload_image, DWORD payload_image_size)`
- Defined: `injector.c:151`
- Doc: Overwrites the remote process's main module with the payload.

### main `int main(int argc, char* argv[])`
- Defined: `injector.c:189`
- Doc: ==================================================================== MAIN ==============================================
