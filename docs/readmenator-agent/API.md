# API

## injector.c
- `get_nt_headers` (function) `injector.c:9` `IMAGE_NT_HEADERS* get_nt_headers(BYTE* buffer)` -- Gets the NT Headers from a raw PE buffer.
- `is_64bit` (function) `injector.c:21` `BOOL is_64bit(BYTE* buffer)` -- Checks if the PE buffer is for a 64-bit executable.
- `get_image_size` (function) `injector.c:29` `DWORD get_image_size(BYTE* buffer)` -- Gets the SizeOfImage from the PE headers.
- `get_entry_point_rva` (function) `injector.c:37` `DWORD get_entry_point_rva(BYTE* buffer)` -- Gets the RVA of the Entry Point.
- `pe_buffer_to_virtual_image` (function) `injector.c:45` `BYTE* pe_buffer_to_virtual_image(BYTE* raw_buffer, DWORD* out_size)` -- Maps a raw PE file buffer into a virtual layout, similar to how the OS loader would map it.
- `create_suspended_process` (function) `injector.c:76` `BOOL create_suspended_process(char* path, PROCESS_INFORMATION* pi)` -- Creates a process in a suspended state.
- `update_remote_entry_point` (function) `injector.c:90` `BOOL update_remote_entry_point(PROCESS_INFORMATION* pi, ULONGLONG entry_point_va, BOOL is_32bit_t...` -- Updates the Entry Point of the remote process's main thread.
- `get_remote_image_base` (function) `injector.c:113` `ULONGLONG get_remote_image_base(PROCESS_INFORMATION* pi, BOOL is_32bit_target)` -- Gets the base address of the main module in the remote process.
- `overwrite_and_run` (function) `injector.c:151` `BOOL overwrite_and_run(PROCESS_INFORMATION* pi, BYTE* payload_image, DWORD payload_image_size)` -- Overwrites the remote process's main module with the payload.
- `main` (function) `injector.c:190` `int main(int argc, char* argv[])`
