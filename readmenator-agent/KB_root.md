# Subsystem: root

## app.py
- Layer: utility
- Doc: app.py  Autor: Gris Iscomeback Correo electrónico: grisiscomeback[at]gmail[dot]com Fecha de creación: xx/xx/xxxx Licenci
- Language: py

## injector.c
- Layer: infrastructure
- Doc: ==================================================================== PE PARSING HELPERS (REPLACING PECONV) =============
- Language: c
- Symbols:
  - `get_nt_headers` (function, line 9) `IMAGE_NT_HEADERS* get_nt_headers(BYTE* buffer)`
  - `is_64bit` (function, line 21) `BOOL is_64bit(BYTE* buffer)`
  - `get_image_size` (function, line 29) `DWORD get_image_size(BYTE* buffer)`
  - `get_entry_point_rva` (function, line 37) `DWORD get_entry_point_rva(BYTE* buffer)`
  - `pe_buffer_to_virtual_image` (function, line 45) `BYTE* pe_buffer_to_virtual_image(BYTE* raw_buffer, DWORD* out_size)`
  - `create_suspended_process` (function, line 76) `BOOL create_suspended_process(char* path, PROCESS_INFORMATION* pi)`
  - `update_remote_entry_point` (function, line 90) `BOOL update_remote_entry_point(PROCESS_INFORMATION* pi, ULONGLONG entry_point_va, BOOL is_32bit_t...`
  - `get_remote_image_base` (function, line 113) `ULONGLONG get_remote_image_base(PROCESS_INFORMATION* pi, BOOL is_32bit_target)`
  - `overwrite_and_run` (function, line 151) `BOOL overwrite_and_run(PROCESS_INFORMATION* pi, BYTE* payload_image, DWORD payload_image_size)`
  - `main` (function, line 190) `int main(int argc, char* argv[])`

## install.sh
- Layer: utility
- Language: sh
