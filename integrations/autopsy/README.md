# QNXProbe Autopsy integration

Target: Autopsy 4.23.1 on Windows.

## Architecture
- Jython Data Source Ingest Module as the Autopsy entry point.
- Launch QNXProbe via a configured CPython executable in a subprocess.
- Exchange results using a versioned JSON manifest, never parse GUI console output.
- Keep VLEAPP independent: it processes files already available in Autopsy.

## Manifest contract (proposal)
Each file entry contains: relative_path, extracted_path, size, filesystem, volume_offset, source_extents, recovery_status, and optional hashes.
Use byte offsets relative to the original evidence source, not a temporary partition file. Validate extracted paths to prevent traversal.

## Processing policy
1. Enumerate existing Autopsy files and filesystem volumes.
2. Probe only unsupported volumes by default; allow manual full scan.
3. Never classify unknown filesystem contents as free space solely because Autopsy does not recognize them.
4. Import validated recovered files as derived or logical content; preserve evidence provenance in an accompanying report.
5. Avoid duplicate imports with stable source identity (image, volume, native file identity/extents).
6. Unallocated and deleted content require explicit provenance labels.
7. Support cancellation, process exit codes, logs and per-case temporary directories.

## Implementation gates
- Confirm current QNXProbe CLI flags and JSON/report output contract.
- Confirm Autopsy 4.23.1 Jython API and import semantics against a running installation.
- Add fixture-based integration tests before enabling import by default.

This file is the initial integration specification, not a working ingest module.
