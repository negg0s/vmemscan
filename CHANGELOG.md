# Changelog

All notable changes to this project will be documented in this file.

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
