# Changelog

All notable changes to this project will be documented in this file.

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
