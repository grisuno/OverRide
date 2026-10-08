# root

*Community 0 | 3 files | cohesion 1.00*

## Definition

This community groups 3 file(s) rooted at `root` with dominant language py (cohesion 1.00). Central symbols: `create_suspended_process`, `get_entry_point_rva`, `get_image_size`, `get_nt_headers`, `get_remote_image_base`, `is_64bit`, `main`, `overwrite_and_run`. Core file: `injector.c` (10 symbols). Documented purpose: Autor: Gris Iscomeback Correo electrónico: grisiscomeback[at]gmail[dot]com Fecha de creación: xx/xx/xxxx Licencia: GPL v3  Descripción:.

## Files

| File | Language | Layer | Symbols | Doc |
|------|----------|-------|---------|-----|
| `app.py` | py | utility | 0 | yes |
| `injector.c` | c | infrastructure | 10 | yes |
| `install.sh` | sh | utility | 0 | no |

## Key Symbols

- `get_nt_headers` (function, `injector.c:9`) `IMAGE_NT_HEADERS* get_nt_headers(BYTE* buffer)` - Gets the NT Headers from a raw PE buffer.
- `is_64bit` (function, `injector.c:21`) `BOOL is_64bit(BYTE* buffer)` - Checks if the PE buffer is for a 64-bit executable.
- `get_image_size` (function, `injector.c:29`) `DWORD get_image_size(BYTE* buffer)` - Gets the SizeOfImage from the PE headers.
- `get_entry_point_rva` (function, `injector.c:37`) `DWORD get_entry_point_rva(BYTE* buffer)` - Gets the RVA of the Entry Point.
- `pe_buffer_to_virtual_image` (function, `injector.c:45`) `BYTE* pe_buffer_to_virtual_image(BYTE* raw_buffer, DWORD* out_size)` - Maps a raw PE file buffer into a virtual layout, similar to how the OS loader would map it.
- `create_suspended_process` (function, `injector.c:76`) `BOOL create_suspended_process(char* path, PROCESS_INFORMATION* pi)` - Creates a process in a suspended state.
- `update_remote_entry_point` (function, `injector.c:90`) `BOOL update_remote_entry_point(PROCESS_INFORMATION* pi, ULONGLONG entry_point_va` - Updates the Entry Point of the remote process's main thread.
- `get_remote_image_base` (function, `injector.c:113`) `ULONGLONG get_remote_image_base(PROCESS_INFORMATION* pi, BOOL is_32bit_target)` - Gets the base address of the main module in the remote process.
- `overwrite_and_run` (function, `injector.c:151`) `BOOL overwrite_and_run(PROCESS_INFORMATION* pi, BYTE* payload_image, DWORD paylo` - Overwrites the remote process's main module with the payload.
- `main` (function, `injector.c:190`) `int main(int argc, char* argv[])`

## Internal vs External Edges

- Internal resolved imports (EXTRACTED): 0
- Cross-boundary resolved imports (EXTRACTED): 0

## Connections

- No cross-community bridges recorded. This community is self-contained.

## Risks

- No scoped security, taint, cycle, or layer risks.

## Open Questions

- Why do 1 file(s) lack file-level docs (e.g. `install.sh`)? What purpose do they serve?
- What would break if the most connected file in root changed?
- Should root be split, given cohesion 1.00?

## Sources

- `app.py`
- `injector.c`
- `install.sh`
