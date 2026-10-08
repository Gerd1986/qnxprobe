#!/usr/bin/env python3
"""Export filesystem-declared free extents without reading or changing evidence."""
import argparse
import json
import os
import sys

def collect(image_path, min_bytes=4096):
    import qnxprobe as q
    fh = q.open_image(image_path)
    records = []
    try:
        for index, vol in enumerate(q.volumes(fh)):
            walker = vol.get("walker")
            if walker is None or not callable(getattr(walker, "free_extents", None)):
                continue
            for off, length in walker.free_extents(min_bytes=min_bytes):
                off, length = int(off), int(length)
                if off < 0 or length <= 0:
                    raise ValueError("Invalid free extent from walker")
                records.append({"volume_index": index, "filesystem": str(vol.get("kind", "unknown")),
                                "offset": off, "length": length,
                                "classification": "filesystem_declared_free"})
    finally:
        fh.close()
    return records

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("image")
    ap.add_argument("--output", required=True)
    ap.add_argument("--min-bytes", type=int, default=4096)
    args = ap.parse_args()
    if args.min_bytes < 1:
        ap.error("--min-bytes must be positive")
    entries = collect(args.image, args.min_bytes)
    # Do not coalesce across volumes; each entry retains its volume provenance.
    payload = {"schema": 1, "source_image": os.path.abspath(args.image),
               "interpretation": "filesystem_declared_free_not_verified_deleted",
               "extents": entries}
    with open(args.output, "w", encoding="utf-8") as fp:
        json.dump(payload, fp, indent=2)
    print("Exported %d free extents" % len(entries))

if __name__ == "__main__":
    main()
