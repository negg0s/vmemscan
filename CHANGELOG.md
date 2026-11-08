# Changelog

All notable changes to this project will be documented in this file.

## [1.4.0] - 2026-11-08

### Added
- Working set and Copy-On-Write page table forensics (--working-set, --ws): queries target process working set entries via K32QueryWorkingSetEx on all committed MEM_IMAGE executable code pages. Exposes code pages whose physical page table attributes transitioned from shared (PS_SHARED) to private copy-on-write (PS_PRIVATE), uncovering in-memory inline hooks, patches, and code section stomping without requiring on-disk file comparisons.
- In-memory Beacon Object File (BOF) and DFR forensics (--bof): scans unbacked memory regions for residual symbol tables and function call markers generated during BOF execution (Cobalt Strike, Havoc, Sliver). Recognizes internal Beacon API functions (BeaconPrintf, BeaconDataParse, BeaconOutput) and Dynamic Function Resolution (LIBRARY$Function) symbol patterns.
- Debugger suppression and anti-analysis patch detection: added auditing for ntdll!DbgBreakPoint and ntdll!DbgUiRemoteBreakin to catch anti-debugging patches that suppress debugger attachments and forensic memory inspection.
- Integrated working set image modifications (+40) and BOF payload artifacts (+50) into the unified forensic threat scoring model.
- Expanded automated unit test suite from 53 to 58 test suites.

## [1.3.0] - 2026-11-08

### Added
- Fiber execution context and Fiber Local Storage forensics (--fibers): traverses thread execution contexts via TEB.FiberData and PEB FLS structures. Audits fiber start routines, fiber stack boundaries, and registered FLS callbacks, uncovering fiber injection, unbacked fiber execution, and RWX fiber allocations used to evade thread call stack walking.
- In-memory CLR and .NET assembly injection forensics (--clr): detects native Win32 processes hosting the CLR runtime (execute-assembly / Donut injection) and scans committed private memory pages for in-memory loaded .NET assembly metadata headers (BSJB signature 0x424A5342), extracting metadata version strings and identifying unbacked .NET assemblies without on-disk file backing.
- Integrated fiber injection (+40) and unmanaged CLR injection (+45) into the unified forensic threat scoring model.
- Expanded automated unit test suite from 48 to 53 test suites.

## [1.2.0] - 2026-11-08

### Added
- Mapped section view and shared memory forensics (--sections): audits committed MEM_MAPPED virtual memory regions. Detects anonymous executable mapped sections (section view shellcode injection via NtMapViewOfSection without disk backing), executable sections backed by non-executable data files (.dat, .tmp, .txt, .bin, .png), RWX mapped sections (W^X breach), and section protection elevation (views allocated as non-executable and promoted to executable at runtime).
- Call stack unwind and RUNTIME_FUNCTION forensics (--unwind): inspects active thread stacks, identifying return addresses placed by CALL instructions and verifying them against each module's .pdata Exception Directory (IMAGE_DIRECTORY_ENTRY_EXCEPTION). Uncovers Call Stack Spoofing (synthetic return addresses and code cave execution lacking valid function unwind metadata) and return addresses in unbacked private memory or RWX pages.
- Integrated section-based code injection (+40) and call stack spoofing (+40) into the unified forensic risk scoring engine.
- Expanded automated unit test suite from 43 to 48 test suites.

## [1.1.0] - 2026-11-08

### Added
- PEB loader and unlinked module forensics (--ldr): traverses PEB loader data (InLoadOrderModuleList, InMemoryOrderModuleList, InInitializationOrderModuleList) and cross-references all committed MEM_IMAGE regions in process virtual memory. Identifies stealth unlinked modules (reflective DLLs unlinked from PEB), phantom LDR entries (DllBase pointing to non-image memory or freed addresses), and list desynchronization.
- Thread Local Storage (TLS) callback forensics (--tls): inspects IMAGE_DIRECTORY_ENTRY_TLS across loaded modules, reading callback function pointers in AddressOfCallBacks to detect TLS callback injection, callbacks pointing into unbacked private memory (MEM_PRIVATE), and callbacks targeting PAGE_EXECUTE_READWRITE memory.
- Integrated unlinked module detection (+40) and TLS callback anomalies (+35) into the unified forensic risk scoring engine.
- Expanded automated unit test suite from 39 to 43 test suites.

## [1.0.0] - 2026-11-08

### Added
- Vectored Exception Handling (VEH) and PAGE_GUARD trap forensics (--veh): audits committed memory regions for unexpected PAGE_GUARD trap modifiers on executable and private memory pages (used by memory hooking engines and VEH evasion to intercept code execution), and inspects top-level unhandled exception filter pointers for redirections to unbacked memory.
- Windows Thread Pool and asynchronous work item injection forensics (--pool): inspects thread pool worker threads (TppWorkerThread / TppWaiterpThread), auditing worker call stacks and dispatch frames to uncover PoolParty work item injection (TP_WORK, TP_TIMER, TP_WAIT callbacks executing in unbacked private memory or RWX pages).
- Integrated thread pool callback injection (+40) and VEH / PAGE_GUARD traps (+35) into the unified forensic risk scoring engine.
- Expanded automated unit test suite from 36 to 39 test suites.

## [0.9.0] - 2026-11-08

### Added
- Wiped and obfuscated PE header detector (--wiped-pe): scans committed private memory regions for in-memory PE structures whose DOS headers (MZ magic) have been erased or whose section names have been scrambled to defeat memory scanners and reflective PE carvers.
- Process security mitigations and exploit defense auditor (--mitigations): queries GetProcessMitigationPolicy to inspect Data Execution Prevention (DEP), Control Flow Guard (CFG), Arbitrary Code Guard (ACG), binary signature enforcement, child process restrictions, and strict handle checking.
- Integrated wiped PE headers (+40) and exploit mitigation inconsistencies (+15) into the unified forensic risk scoring engine.
- Expanded automated unit test suite from 33 to 36 test suites.

## [0.8.0] - 2026-11-08

### Added
- Sleep mask memory demotion and dormant payload detector (--sleep-mask): scans sleeping thread stacks for return addresses pointing into private memory regions that were allocated as executable but demoted to non-executable (PAGE_READWRITE, PAGE_READONLY, PAGE_NOACCESS) during sleep cycles (Ekko, Foliage, Cobalt Strike Sleep Mask).
- Anti-debugging and process instrumentation auditor (--anti-debug): queries kernel debug ports (ProcessDebugPort), debug flags (ProcessDebugFlags), debug object handles (ProcessDebugObjectHandle), PEB BeingDebugged / NtGlobalFlag heap validation flags, and scans thread hardware debug registers (DR0-DR7) for VEH hooking and analysis evasion.
- Integrated sleep mask demotion and anti-debug indicators into unified forensic risk scoring engine (+45 for sleep masked regions, +25 for anti-debugging / hardware breakpoints).
- Expanded automated unit test suite from 30 to 33 test suites.

## [0.7.0] - 2026-11-08

### Added
- Process ghosting and file tampering auditor (--ghosting): inspects target process backing executable files for Process Ghosting (DeletePending active while running in memory) and Process Herpaderping (disk binary overwritten with non-PE content or swapped after section mapping).
- Module stomping and code section integrity auditor (--stomping): scans all loaded modules, comparing in-memory .text code sections against on-disk PE binaries to uncover in-memory overwrites, phantom DLL loading, and code section tampering.
- Integrated process ghosting and module stomping metrics into unified forensic risk scoring engine (+45 for ghosting/herpaderping, +35 for stomped modules).
- Expanded automated unit test suite from 27 to 30 test suites.

## [0.6.0] - 2026-11-08

### Added
- Thread call stack and return address auditor (--stack): inspects active thread stacks at runtime, walking pointer slots to identify return addresses pointing to unbacked private memory (shellcode stagers, reflective DLLs, and sleeping beacons) and RWX pages.
- Indirect syscall and trampoline detector (--indirect-syscalls): scans executable regions for indirect syscall trampolines (Syswhispers3, Tartarus' Gate, Hell's Hall) that set up system service numbers and jump into ntdll.dll or win32u.dll to evade inline EDR telemetry hooks.
- Integrated stack anomaly and indirect syscall factors into unified forensic risk scoring engine (+40 for unbacked return addresses, +35 for indirect syscalls).
- Expanded automated unit test suite from 24 to 27 test suites.

## [0.5.0] - 2026-11-08

### Added
- Direct syscall and EDR bypass auditor (--syscalls): scans executable regions for direct syscall stubs (Syswhispers, Hell's Gate, Halo's Gate) and standalone syscall instructions residing outside legitimate system libraries (ntdll.dll, win32u.dll), extracting System Service Numbers (SSN).
- Import Address Table (IAT) hook and redirection detector (--iat): parses remote PE image import descriptors and IAT thunks, verifying that all imported API pointers resolve to valid disk-backed library code rather than unbacked private memory or RWX pages.
- Unified forensic risk scoring engine and threat verdict (--score): synthesizes memory indicators (C2 beacons, hollowing, direct syscalls, unbacked threads, telemetry patches, W^X violations, IAT hooks, PEB spoofing) into a normalized 0-100 score and operational forensic verdict (Clean, LowRisk, Suspicious, CriticalCompromised).
- Expanded automated unit test suite from 21 to 24 test suites.

## [0.4.0] - 2026-11-08

### Added
- Command and Control (C2) beacon configuration scanner (--c2): scans committed private memory for embedded Cobalt Strike v3/v4 beacon configurations (XOR 0x2E, 0x69, plaintext), extracting C2 server endpoints, ports, sleep times, jitter, user-agents, and named pipes.
- PEB process parameters and command line spoofing auditor (--peb): walks remote PEB ProcessParameters, comparing ImagePathName against physical disk paths to detect argument spoofing and scanning environment blocks for CLR profiler hijacks (COR_ENABLE_PROFILING).
- In-memory IOC and string extractor with automated categorization (--iocs): carves ASCII and UTF-16LE strings from target memory addresses, categorizing indicators into URLs, Named Pipes, IPv4 addresses, lolbins/system commands, and file paths.
- Expanded automated unit test suite from 18 to 21 test suites.

## [0.3.0] - 2026-11-08

### Added
- Shannon entropy memory analyzer (--entropy): calculates byte distribution randomness over virtual memory blocks to detect packed payloads, compressed assets, and encrypted shellcode stagers (highlighting entropy >= 7.20).
- Thread instruction pointer and context audit (--threads): inspects active thread RIP/EIP and start addresses to detect threads executing inside unbacked memory (MEM_PRIVATE) and RWX pages.
- Loaded module and stealth PEB unlinking auditor (--modules): walks remote PEB InLoadOrderModuleList and compares with Toolhelp snapshots to expose stealth unlinked modules and DLLs loaded from untrusted or temporary paths.
- Expanded automated unit test suite from 15 to 18 test suites.

## [0.2.0] - 2026-11-08

### Added
- Security telemetry patch detection (--patches): audits in-memory tampering of ETW (EtwEventWrite, EtwEventWriteFull, NtTraceEvent) and AMSI (AmsiScanBuffer, AmsiScanString, AmsiOpenSession) APIs.
- Process hollowing and module stomping verification (--hollowing): traverses remote PEB to extract ImageBaseAddress, compares in-memory entry point and SizeOfImage against on-disk PE headers, and inspects entry point instructions for inline redirection.
- Virtual memory snapshot baseline and diffing (--save-snapshot, --diff-snapshot): captures committed regions with FNV-1a content hashes to detect late injections, W^X protection escalations, and modified executable pages.
- Expanded automated unit test suite from 12 to 15 test suites.

## [0.1.0] - 2026-11-08

### Added
- Initial release of vmemscan.
- Virtual memory layout scanner using VirtualQueryEx and mapped file name resolution.
- Unbacked executable memory (W^X and private executable) anomaly detection.
- Process hollowing and modified PE header detection.
- User-mode API inline hook detection in core system libraries.
- Thread entry point verification for unbacked memory execution.
- Suspicious memory region binary carver and raw dumper.
- ASCII and hex pattern memory scanner with wildcards.
- Formatted console table, JSON, and CSV export modes.
