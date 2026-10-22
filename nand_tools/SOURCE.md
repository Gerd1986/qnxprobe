# NAND preprocessor provenance

Imported from Gerd1986/autopsy, `Tools/nand`, commit
`6b1a139dcda42035ec571e0855ca011c271822da` (MIT, see LICENSE.txt).

The BCH decoder, LBA mapping and JSON schema are retained. Package-relative
imports replace script-local imports. QNXProbe adds `prepare()` for unique
output folders, exact profile copies and audit sidecars shared by CLI and GUI.

Independent fixture/encoder test sources originate from Gerd1986/sleuthkit,
`tests/nand_lba_fixture.py` and `tests/flash_preprocess_regression.py`.
