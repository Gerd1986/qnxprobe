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
