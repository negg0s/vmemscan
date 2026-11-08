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
- **C2 Beacon Configuration Extraction**: Scans committed memory for Cobalt Strike v3/v4 configurations, parsing C2 endpoints, ports, sleep times, jitter, and named pipes.
- **PEB Process Parameters & Argument Spoofing Audit**: Compares remote PEB `ImagePathName` against disk image paths to expose command-line spoofing, and checks environment variables for CLR profiler hijacking (`COR_ENABLE_PROFILING`).
- **In-Memory IOC & String Classification**: Extracts ASCII and UTF-16LE strings from memory addresses and categorizes IOCs (URLs, Named Pipes, IPv4 addresses, lolbins, file paths).
- **Thread Context & Execution Forensics**: Queries thread entry points and active instruction pointers (RIP/EIP) to detect threads running from unbacked memory (remote thread injection targets and hijacked threads).
- **Shannon Entropy Analysis**: Computes byte distribution randomness to reveal packed binaries, encrypted payload buffers, and compressed code blocks (flags entropy >= 7.20).
- **Loaded Module & Stealth PEB Unlinking Audit**: Traverses remote PEB `InLoadOrderModuleList` and compares against Toolhelp snapshots, detecting unlinked stealth DLLs and libraries loaded from untrusted directories.
- **Inline API Hook Detection**: Compares in-memory instruction bytes of critical system APIs in `ntdll.dll` against clean disk bytes, detecting relative jumps, indirect jumps, and user-mode rootkit hooks.
- **Security Telemetry Patch Detection**: Audits in-memory tampering of Event Tracing for Windows (ETW: `EtwEventWrite`, `EtwEventWriteFull`, `NtTraceEvent`) and Antimalware Scan Interface (AMSI: `AmsiScanBuffer`, `AmsiScanString`, `AmsiOpenSession`) security functions.
- **Process Hollowing & Header Stomping Forensics**: Queries the remote PEB to extract `ImageBaseAddress`, compares in-memory entry points and image size against on-disk PE headers, and inspects entry points for redirection stubs.
- **Process Ghosting & Herpaderping Forensics**: Audits target backing executable files for Process Ghosting (`DeletePending` active on running executable) and Process Herpaderping (on-disk file overwritten with non-PE data or replaced after image mapping).
- **Module Stomping & Code Section Integrity**: Compares in-memory `.text` code section bytes of all loaded modules against clean on-disk files, detecting phantom DLL loading and unbacked code hidden in image sections.
- **Direct Syscall & EDR Bypass Audit**: Scans executable memory regions for direct syscall stubs (Syswhispers, Hell's Gate, Halo's Gate) and standalone syscall instructions residing outside `ntdll.dll` / `win32u.dll`, extracting System Service Numbers (SSN).
- **Indirect Syscall & Trampoline Audit**: Identifies indirect syscall trampolines (Syswhispers3, Tartarus' Gate, Hell's Hall) that set up SSN and jump into `ntdll.dll` / `win32u.dll` to evade call instruction inspection.
- **Import Address Table (IAT) Hook Detection**: Traverses remote PE import descriptors and IAT thunks, identifying pointers redirected to unbacked private memory or RWX pages.
- **Thread Call Stack & Return Address Audit**: Inspects thread stack memory at runtime to detect return addresses residing in unbacked private memory (shellcode stagers, sleeping beacons) and RWX pages.
- **Sleep Mask & Dormant Payload Forensics**: Scans sleeping thread stacks for return addresses pointing into private memory regions that were allocated as executable but demoted to non-executable (`PAGE_READWRITE`, `PAGE_READONLY`, `PAGE_NOACCESS`) during sleep intervals (Ekko, Foliage, Cobalt Strike Sleep Mask).
- **Anti-Debugging & Instrumentation Forensics**: Queries kernel debug ports (`ProcessDebugPort`), debug flags (`ProcessDebugFlags`), debug objects (`ProcessDebugObjectHandle`), PEB `BeingDebugged` and `NtGlobalFlag` heap validation flags, and scans thread hardware debug registers (`DR0`-`DR7`) for VEH hooking and analysis evasion.
- **Wiped & Obfuscated PE Header Forensics**: Scans committed private memory regions for in-memory PE images whose DOS headers (`MZ` magic) have been zeroed or whose section headers have been obfuscated to defeat memory carvers and naive PE scanners.
- **Process Security Mitigations & Exploit Defense Audit**: Queries `GetProcessMitigationPolicy` to assess DEP, Control Flow Guard (CFG), Arbitrary Code Guard (ACG), binary signature enforcement, remote image loading, and child process policies.
- **Vectored Exception Handling (VEH) & PAGE_GUARD Trap Forensics**: Audits memory regions for unexpected `PAGE_GUARD` modifiers on executable and private pages (used to catch execution via `STATUS_GUARD_PAGE_VIOLATION` for VEH hooks), and inspects top-level unhandled exception filter pointers for redirections to unbacked memory.
- **Thread Pool & Work Item Callback Forensics**: Inspects Windows Thread Pool worker threads (`TppWorkerThread`, `TppWaiterpThread`), auditing worker dispatch call stacks to uncover PoolParty callback injection (`TP_WORK`, `TP_TIMER`, `TP_WAIT` callbacks dispatched to unbacked private memory or RWX pages).
- **Unified Forensic Risk Scoring Engine**: Evaluates active indicators across injection, hollowing, direct syscalls, indirect syscalls, thread contexts, stack return addresses, and telemetry patches to assign a normalized 0-100 risk score and operational threat verdict.
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
  --ghosting               Audit process ghosting, herpaderping, and deleted backing file execution
  --stomping               Audit loaded modules for code section (.text) overwrites and stomping
  --threads                Audit thread start addresses and instruction pointers (RIP/EIP)
  --modules                Audit loaded modules for stealth PEB unlinking and suspicious paths
  --entropy                Audit memory entropy to uncover encrypted/packed payload buffers
  --c2                     Scan committed memory for Cobalt Strike C2 beacon configurations
  --peb                    Audit PEB parameters, argument spoofing, and CLR profiler hijacks
  --syscalls               Audit executable memory for direct syscall stubs and EDR bypasses
  --indirect-syscalls      Audit executable memory for indirect syscall trampolines (Syswhispers3 / Hell's Hall)
  --iat                    Audit Import Address Table (IAT) for pointer hijacking and inline hooks
  --stack                  Audit thread call stacks for unbacked return addresses and spoofing
  --sleep-mask             Audit sleeping threads for sleep mask demotion and dormant payloads
  --anti-debug             Audit kernel debug ports, PEB debug flags, and hardware breakpoints (DR0-DR7)
  --wiped-pe               Audit memory regions for wiped DOS headers and obfuscated PE structures
  --mitigations            Audit process exploit mitigations (DEP, ASLR, ACG, CFG, Child Process Policy)
  --veh                    Audit Vectored Exception Handling (VEH) hooks and PAGE_GUARD traps
  --pool                   Audit Windows Thread Pool worker threads for callback injection (PoolParty)
  --ldr                    Audit PEB loader module list and detect unlinked / hidden modules
  --tls                    Audit Thread Local Storage (TLS) callback directories and target memory
  --sections               Audit mapped section views and shared memory for anonymous shellcode
  --unwind                 Audit thread call stack return addresses for .pdata metadata and spoofing
  --score                  Compute unified forensic threat score (0-100) and risk assessment
  --iocs <hex_addr>        Extract and classify IOCs (URLs, pipes, IPs, lolbins) from address
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

# Audit backing executable file for Process Ghosting and Herpaderping
vmemscan -p 1234 --ghosting

# Audit loaded modules for in-memory code section stomping and phantom DLLs
vmemscan -p 1234 --stomping

# Audit thread execution pointers to detect unbacked and RWX execution
vmemscan -p 1234 --threads

# Audit loaded modules to detect stealth PEB unlinking and untrusted paths
vmemscan -p 1234 --modules

# Calculate Shannon entropy over memory regions to detect encrypted payloads
vmemscan -p 1234 --entropy

# Scan memory regions for embedded Cobalt Strike C2 beacon configurations
vmemscan -p 1234 --c2

# Audit PEB process parameters, command-line spoofing, and CLR profiler hijacking
vmemscan -p 1234 --peb

# Audit executable regions for direct syscall stubs and EDR bypasses
vmemscan -p 1234 --syscalls

# Audit executable memory for indirect syscall trampolines (Syswhispers3 / Hell's Hall)
vmemscan -p 1234 --indirect-syscalls

# Audit Import Address Table (IAT) for pointer hijacking and unbacked targets
vmemscan -p 1234 --iat

# Audit thread call stacks for unbacked return addresses (sleeping beacons, stagers)
vmemscan -p 1234 --stack

# Audit sleeping threads for sleep mask evasion (Ekko, Foliage, dormant beacons)
vmemscan -p 1234 --sleep-mask

# Audit process for anti-debugging flags, kernel debug ports, and hardware breakpoints
vmemscan -p 1234 --anti-debug

# Audit memory regions for wiped DOS headers and obfuscated PE structures
vmemscan -p 1234 --wiped-pe

# Audit process exploit mitigations (DEP, ASLR, ACG, CFG, Child Process Policy)
vmemscan -p 1234 --mitigations

# Audit process for Vectored Exception Handling (VEH) hooks and PAGE_GUARD traps
vmemscan -p 1234 --veh

# Audit Windows Thread Pool worker threads for callback injection (PoolParty)
vmemscan -p 1234 --pool

# Audit PEB loader module list to detect unlinked or phantom modules
vmemscan -p 1234 --ldr

# Audit Thread Local Storage (TLS) callback directories for injection and unbacked targets
vmemscan -p 1234 --tls

# Audit mapped section views and shared memory for anonymous shellcode
vmemscan -p 1234 --sections

# Audit thread call stack return addresses for missing .pdata metadata and stack spoofing
vmemscan -p 1234 --unwind

# Compute unified forensic threat score and operational verdict
vmemscan -p 1234 --score

# Extract and classify IOCs (URLs, pipes, IPv4, system commands) from memory region
vmemscan -p 1234 --iocs 0x7FFA120000

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
