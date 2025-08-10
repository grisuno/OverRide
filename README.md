# OverRide - Process Overwriting Injector

## Overview

This project provides a proof-of-concept implementation of the "Process Overwriting" (a form of Process Hollowing) technique in plain C. The injector launches a legitimate target process in a suspended state and then overwrites its main executable module in memory with a custom payload. The main thread's context is then updated to point to the payload's entry point, and the process is resumed.

This method allows the payload to run under the guise of a legitimate process, providing a layer of stealth.

## Technique

The core steps of the injection are as follows:

1.  **Create Suspended Target**: A specified target process (e.g., `calc.exe`) is created in a `CREATE_SUSPENDED` state.
2.  **Map Payload**: The payload executable is read from disk and mapped into a virtual memory layout that mirrors how the OS would load it.
3.  **Check Compatibility**: The injector verifies that the payload and target share the same architecture (32-bit or 64-bit) and that the payload's virtual size does not exceed the target's.
4.  **Overwrite Memory**: The injector gains access to the target process's memory space, overwriting the original executable's image with the payload's image.
5.  **Update Entry Point**: The entry point of the target process's main thread is modified to point to the entry point of the injected payload.
6.  **Resume Process**: The suspended main thread is resumed, causing the payload's code to be executed instead of the original program.

## Features

- Written in self-contained C with no external dependencies.
- Supports both 32-bit and 64-bit payloads.
- Automatically handles architecture differences between a 64-bit injector and a 32-bit target process (using Wow64 APIs).
- Includes compatibility checks to prevent common injection failures.

## Usage

The injector is a command-line tool.

```sh
injector.exe <path_to_payload> [path_to_target]
```

-   `<path_to_payload>`: (Required) The path to the executable file you want to inject.
-   `[path_to_target]`: (Optional) The path to the legitimate executable that will be used as the host process. If not provided, it defaults to `C:\Windows\System32\calc.exe`.

### Example (64-bit payload)

```sh
.\injector.exe .\my_payload_x64.exe C:\Windows\System32\svchost.exe
```

### Example (32-bit payload)

If your payload is 32-bit, you must provide a 32-bit target process when running on 64-bit Windows.

```sh
.\injector.exe .\my_payload_x86.exe C:\Windows\SysWOW64\calc.exe
```

## Compilation

The project can be compiled using the MinGW-w64 toolchain.

```sh
x86_64-w64-mingw32-gcc injector.c -o injector.exe
```

## Disclaimer

This tool is intended for educational and research purposes only. The techniques demonstrated here can be used for legitimate purposes, such as software testing and analysis, but can also be abused by malware. The author is not responsible for any misuse of this code. Always ensure you have permission to inject code into a process or system.


![Python](https://img.shields.io/badge/python-3670A0?style=for-the-badge&logo=python&logoColor=ffdd54) ![Shell Script](https://img.shields.io/badge/shell_script-%23121011.svg?style=for-the-badge&logo=gnu-bash&logoColor=white) ![Flask](https://img.shields.io/badge/flask-%23000.svg?style=for-the-badge&logo=flask&logoColor=white) [![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/Y8Y2Z73AV)
