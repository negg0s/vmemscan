# vmemscan

Windows Virtual Memory and Process Injection Forensics CLI.

Written in modern C++20 and pure Win32 / NT Native API. Zero external dependencies, static CRT (`/MT`), self-contained single binary.

## Features

- **Virtual Address Space Mapping**: Enumerates committed, reserved, and free memory blocks across 32-bit and 64-bit processes via `VirtualQueryEx`.
- **Mapped File & Image Resolution**: Resolves memory-backed executable files, DLLs, and sections using `GetMappedFileNameW`.
- **Unbacked Executable Memory Detection**: Identifies executable memory regions (`PAGE_EXECUTE`, `PAGE_EXECUTE_READ`, `PAGE_EXECUTE_READWRITE`) with `MEM_PRIVATE` or unmapped allocations, exposing reflective DLL loaders and shellcode stagers.
- **W^X Policy Violation Audit (RWX Memory)**: Detects memory pages marked `PAGE_EXECUTE_READWRITE`, flagging self-modifying code, stagers, and writable code sections.
- **Reflective PE Injection Discovery**: Inspects executable private memory pages for raw DOS/PE headers (`MZ` signature), detecting in-memory unlinked DLLs.
- **Shellcode Prologue Pattern Detection**: Cross-examines memory execution blocks against common shellcode prologue sequences (stack alignment, call-pop deltas, register clearings).
- **Thread Start Address Forensics**: Queries thread entry points via `NtQueryInformationThread(ThreadQuerySetWin32StartAddress)` and detects threads running from unbacked memory (remote thread injection targets).
- **Inline API Hook Detection**: Compares in-memory instruction bytes of critical system APIs in `ntdll.dll` against clean disk bytes, detecting relative jumps, indirect jumps, and user-mode rootkit hooks.
- **Security Telemetry Patch Detection**: Audits in-memory tampering of Event Tracing for Windows (ETW: `EtwEventWrite`, `EtwEventWriteFull`, `NtTraceEvent`) and Antimalware Scan Interface (AMSI: `AmsiScanBuffer`, `AmsiScanString`, `AmsiOpenSession`) security functions.
- **Process Hollowing & Header Stomping Forensics**: Queries the remote PEB to extract `ImageBaseAddress`, compares in-memory entry points and image size against on-disk PE headers, and inspects entry points for redirection stubs.
- **Virtual Memory Snapshot Baseline & Diffing**: Captures memory state baselines to JSON and detects late code injections, W^X protection escalations, and modified executable pages.
- **Memory Region Dumper & PE Fixup**: Dumps target memory regions to disk, automatically reconstructing PE section alignment and raw pointers for analysis in static disassemblers.
- **Memory Pattern & String Search**: Scans process virtual memory for wildcard byte patterns (e.g. `48 8B ?? ?? ?? E8`) and ASCII strings.
- **Process Memory Summary**: Calculates total virtual commit, private heap allocations, mapped memory, executable memory, and unbacked executable ratios.
- **Machine-Readable Export**: Generates formatted tables, JSON (`--json`), and CSV (`--csv`) for automation pipelines.

## System Requirements

- Windows 10, Windows 11, or Windows Server 2016+ (x64 or ARM64).
- Administrator elevation recommended for full process inspection (`SeDebugPrivilege`).

## Building from Source

Prerequisites: Visual Studio 2022 / 2026 with C++ Desktop Development and CMake 3.20+.

```powershell
# Clone the repository
git clone https://github.com/negg0s/vmemscan.git
cd vmemscan

# Configure and build
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release

# Run test suite
ctest --test-dir build -C Release --output-on-failure
```

## Usage

```text
Usage: vmemscan [options]

Target Selection:
  -p, --pid <PID>          Target process by Process ID
  -n, --name <pattern>     Target process by name or wildcard (e.g. notepad.exe, *chrome*)
  -l, --list               List running processes with architecture and memory usage
  --all                    Scan all running processes for code injection anomalies

Analysis Modes:
  -i, --injection          Audit target process for unbacked executable memory and injection
  -m, --map                Display virtual memory map of target process
  --hooks                  Audit inline API hooks in loaded system libraries
  --patches                Audit telemetry bypasses (ETW and AMSI in-memory patches)
  --hollowing              Audit process hollowing and PE entry point integrity
  --summary                Display virtual memory allocation statistics and breakdown

Memory Snapshot & Diffing:
  --save-snapshot <file>   Save process virtual memory snapshot baseline to JSON
  --diff-snapshot <file>   Compare current process memory against saved baseline

Memory Dumping & Carving:
  --dump <hex_addr>        Dump memory region starting at hexadecimal address
  --size <bytes>           Size in bytes to dump (default: region size)
  --out <path>             Destination path for dumped binary file
  --fixup-pe               Align section headers for dumped in-memory PE images

Memory Pattern Search:
  --pattern <hex_pattern>  Search hex pattern with wildcards (e.g. "48 8B ?? ?? ?? E8")
  --string <text>          Search ASCII string in process memory

Filters & Output:
  --only-unbacked          Filter memory map to unbacked executable memory only
  --only-rwx               Filter memory map to PAGE_EXECUTE_READWRITE only
  --limit <N>              Maximum rows to display in tables (default: 100)
  --json                   Export results in machine-readable JSON format
  --csv                    Export memory map in CSV format
  -h, --help               Display this help message
  -v, --version            Display version information
```

### Examples

```powershell
# List all running processes with memory usage and architecture
vmemscan -l

# Scan a target process for code injection and unbacked executable memory
vmemscan -p 1234 -i

# Scan all running processes on the system for injection anomalies
vmemscan --all -i

# Inspect virtual memory map of a process filtering to unbacked memory only
vmemscan -p 1234 -m --only-unbacked

# Inspect process for user-mode inline API hooks in system libraries
vmemscan -p 1234 --hooks

# Audit telemetry stubs (ETW / AMSI) for in-memory silencing patches
vmemscan -p 1234 --patches

# Verify PE headers and entry point against on-disk image to detect hollowing
vmemscan -p 1234 --hollowing

# Save process memory baseline snapshot to file
vmemscan -p 1234 --save-snapshot baseline.json

# Diff current process memory against saved baseline snapshot
vmemscan -p 1234 --diff-snapshot baseline.json

# Dump a suspicious memory region to disk and reconstruct PE headers
vmemscan -p 1234 --dump 0x7FFA120000 --out payload.bin --fixup-pe

# Search process memory for a byte pattern
vmemscan -p 1234 --pattern "48 8B ?? ?? ?? E8"

# Export memory map to JSON
vmemscan -p 1234 -m --json > memory_map.json
```

## License

MIT License. Copyright (c) 2026 Emir.
