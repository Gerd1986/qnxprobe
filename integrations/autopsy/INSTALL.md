# QNXProbe Autopsy plugin (prototype 0.1.0)

Read-only **Data Source Ingest Module** for Autopsy 4.23.x. Currently produces a QNXProbe text report; it does **not** import files into the case or classify unallocated blocks. This avoids claiming a tested file-import capability prematurely.

## Installation
1. In Autopsy choose **Tools > Python Plugins** and create a folder `QNXProbe`.
2. Copy `QNXProbe.py` into that folder.
3. Set Windows environment variables `QNXPROBE_SCRIPT` (absolute path to qnxprobe.py) and optionally `QNXPROBE_PYTHON` (Python 3 interpreter path; defaults to `python`). Restart Autopsy after changing environment variables.
4. Enable **QNXProbe** in ingest for a disk-image data source.

Reports go to the case module directory under `QNXProbe/datasource_<id>_report.txt`. The source image is never modified. E01 and other acquisition containers require the corresponding qnxprobe reader support.

## Limitations / next steps
- Requires a filesystem path-backed Image data source. Not yet compatible with logical file sets or virtual content without an accessible image path.
- Does not import recovered files into the Autopsy tree. Implement this with a separately verified API adapter and provenance-aware deduplication.
- Does not invoke `--extract` yet; that will be a separate opt-in phase.
- The plugin has not yet been run inside a local Autopsy 4.23.1 installation.
- Validate process cancellation and multi-segment evidence with real fixtures before production forensic use.

## Experimental free-space export and ZIP extraction

The plugin runs `export_free_extents.py` using the same CPython interpreter and writes `datasource_<id>_free_extents.json`. Only walkers implementing `free_extents()` are included. Empty results do **not** prove that the filesystem has no free blocks. These extents are not automatically imported as Autopsy unallocated files.

Set `QNXPROBE_EXTRACT=1` before launching Autopsy to additionally run `qnxprobe.py --extract <zip> <image>`. This produces `datasource_<id>_recovered.zip` in the module output directory. Extracted files are **not yet inserted into the Autopsy file tree**. The ZIP may be large.

Do not use these outputs as evidence of deleted files without validating the filesystem's allocation metadata. Partition gaps and NAND stale pages are not yet covered.

This is an untested integration prototype: verify `qnxprobe.volumes()`, image handle semantics, the Autopsy Jython module lifecycle, and the exact extraction results on known fixtures before casework.
