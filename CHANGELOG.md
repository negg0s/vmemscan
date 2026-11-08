# Changelog

All notable changes to this project will be documented in this file.

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
