"""JSON-profile NAND preprocessing shared by QNXProbe CLI and GUI.

The decoder and profile schema originate from Gerd1986/autopsy, Tools/nand.
"""
import json
from pathlib import Path
import tempfile
import shutil

from .preprocess_ubi import Profile, preprocess


def prepare(source, config, output_dir, *, progress=None):
    """Preserve a logical image, exact profile and audit report in a new run folder.

    Never reuse or overwrite a prior run. ECC is on, and uncorrectable BCH
    aborts processing. The configured mapping's duplicate/hole policies apply.
    """
    source, config = Path(source).resolve(), Path(config).resolve()
    raw_profile = config.read_bytes()
    output_dir = Path(output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    folder = Path(tempfile.mkdtemp(prefix='nand-', dir=output_dir))
    try:
        profile_path = folder / 'device-profile.json'
        profile_path.write_bytes(raw_profile)
        profile = Profile(profile_path)
        target = folder / 'logical.img'
        report = preprocess(source, target, profile, progress=progress)
        report['original_profile'] = str(config)
        report_path = folder / 'logical.img.report.json'
        report_path.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    except BaseException:
        # Only the newly created run folder belongs to this operation.
        shutil.rmtree(folder, ignore_errors=True)
        raise
    return str(target), report
