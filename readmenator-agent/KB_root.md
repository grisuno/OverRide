# Subsystem: root

## app.py
- Layer: utility
- Doc: _*_ coding: utf8 _*_
- Language: py

## injector.c
- Layer: infrastructure
- Doc: include <windows.h> include <stdio.h>  ==================================================================== PE PARSING H
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
  - `main` (function, line 189) `int main(int argc, char* argv[])`
  - `printf` (function, line 14) `printf("[-] Invalid DOS signature.\n");`
  - `memcpy` (function, line 58) `memcpy(virtual_image, raw_buffer, nt_headers->OptionalHeader.SizeOfHeaders);`
  - `memset` (function, line 80) `memset(pi, 0, sizeof(PROCESS_INFORMATION));`
  - `Wow64SetThreadContext` (function, line 98) `return Wow64SetThreadContext(pi->hThread, &context);`
  - `SetThreadContext` (function, line 109) `return SetThreadContext(pi->hThread, &context);`
  - `ResumeThread` (function, line 180) `ResumeThread(pi->hThread);`
  - `ReadFile` (function, line 212) `ReadFile(h_file, raw_buffer, raw_size, &read, NULL);`
  - `CloseHandle` (function, line 213) `CloseHandle(h_file);`
  - `HeapFree` (function, line 217) `HeapFree(GetProcessHeap(), 0, raw_buffer);`
  - `VirtualFree` (function, line 235) `VirtualFree(payload_image, 0, MEM_RELEASE);`
  - `TerminateProcess` (function, line 281) `TerminateProcess(pi.hProcess, 1);`

## install.sh
- Layer: utility
- Language: sh
