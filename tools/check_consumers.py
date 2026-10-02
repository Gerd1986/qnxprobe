#!/usr/bin/env python3
"""Which repositories are carrying an out-of-date copy of a vendored file?

A per-repo vendoring check answers "does my copy match what I recorded". It
cannot answer the question that matters after an upstream release: the file
moved, so who is now behind? Nothing in the upstream repository knows its own
consumers, and nothing in a consumer notices the day upstream changes.

This reads tools/vendoring.json, takes the current bytes of each upstream file,
and compares them against the sha256 every consumer recorded in its own
vendored.json. A consumer that keeps no manifest names its copy instead: the
copy may carry a comment header above the upstream file, and is current when the
upstream bytes are its tail.

    python3 tools/check_consumers.py                    # over the network
    python3 tools/check_consumers.py --local ..         # from checkouts beside this one
    python3 tools/check_consumers.py --summary out.md   # also write a job summary

BEHIND and COULD NOT CHECK are reported separately and exit differently. They
are different results: one says a copy is stale, the other says nothing was
compared, and folding the second into the first turns an unreachable network
into a finding that reads like a defect.

A consumer marked external is a repository someone else owns. One that is
behind is listed on its own and does not fail the check: re-vendoring it is a
pull request its owner has to merge, and a job that stays red until a stranger
acts stops being read.

Exit 0 every consumer is current, 1 at least one of our own is behind, 3 only
external consumers are behind, 2 nothing was behind but something could not be
checked.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
REGISTRY = os.path.join(HERE, "vendoring.json")
API = "https://api.github.com/repos/{repo}/contents/{path}"
TIMEOUT = 30


def _token() -> str:
    """A GitHub token from the environment, or "".

    Without one the private repositories in the registry answer 404, which is
    reported as not compared rather than as up to date. A check that cannot see
    half its consumers must say so rather than call them current.
    """
    return (os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN") or "").strip()


class Unavailable(Exception):
    """The thing could not be fetched or read. Not a finding about the copy."""


def _fetch(repo: str, path: str) -> bytes:
    url = API.format(repo=repo, path=path)
    req = urllib.request.Request(url, headers={
        "Accept": "application/vnd.github.raw",
        "User-Agent": "qnxprobe-check-consumers",
    })
    token = _token()
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as fh:
            return fh.read()
    except urllib.error.HTTPError as exc:
        hint = "" if token else " (no GH_TOKEN set, so private repositories 404)"
        raise Unavailable(f"{url}: {exc}{hint}") from exc
    except (urllib.error.URLError, OSError, ValueError) as exc:
        raise Unavailable(f"{url}: {exc}") from exc


def _read_local(root: str, repo: str, path: str) -> bytes:
    # a checkout is expected to be named after the repository
    where = os.path.join(root, repo.split("/")[-1], path)
    try:
        with open(where, "rb") as fh:
            return fh.read()
    except OSError as exc:
        raise Unavailable(f"{where}: {exc}") from exc


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _recorded(manifest: bytes, name: str) -> dict:
    try:
        doc = json.loads(manifest)
    except ValueError as exc:
        raise Unavailable(f"the manifest is not JSON: {exc}") from exc
    for entry in doc.get("vendored", []):
        if entry.get("name") == name:
            return entry
    raise Unavailable(f"the manifest records no entry named {name!r}")


def _copy_state(copy: bytes, upstream: bytes) -> tuple[bool, str]:
    """(current, version) for a consumer that keeps the file under a header.

    The copy is current when the upstream bytes are its tail, so whatever the
    consumer wrote above them is its own business. The version is the tag its
    header names ("tag v1.38"), read from the top of the copy, or "?".
    """
    current = copy.endswith(upstream)
    head = copy[:len(copy) - len(upstream)] if current else copy[:4096]
    tag = re.search(rb"tag v([0-9][0-9.]*[0-9])", head)
    return current, tag.group(1).decode("ascii") if tag else "?"


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--local", metavar="DIR",
                    help="read every repository from checkouts under DIR instead of "
                         "over the network")
    ap.add_argument("--registry", default=REGISTRY)
    ap.add_argument("--summary", metavar="FILE",
                    help="also write the report to FILE as Markdown")
    args = ap.parse_args()

    with open(args.registry, encoding="utf-8") as fh:
        registry = json.load(fh)

    def get(repo: str, path: str) -> bytes:
        return _read_local(args.local, repo, path) if args.local else _fetch(repo, path)

    behind: list[str] = []
    behind_external: list[str] = []
    unknown: list[str] = []
    current: list[str] = []
    rows: list[tuple[str, str, str, str]] = []

    for up in registry["upstreams"]:
        name, repo, path = up["name"], up["repo"], up["file"]
        try:
            upstream = get(repo, path)
            want = _sha256(upstream)
        except Unavailable as exc:
            unknown.append(f"{name}: the upstream file could not be read ({exc})")
            rows.append((name, repo, "?", "upstream unreadable"))
            continue
        for consumer in up["consumers"]:
            crepo = consumer["repo"]
            external = bool(consumer.get("external"))
            label = f"{name} in {crepo}"
            try:
                if "copy" in consumer:
                    same, ver = _copy_state(get(crepo, consumer["copy"]), upstream)
                    got = "its copy does not end with the upstream file"
                else:
                    entry = _recorded(get(crepo, consumer["manifest"]), name)
                    got = entry.get("sha256", "")
                    ver = entry.get("version", "?")
                    same = got == want
                    got = got[:12] or "no sha"
            except Unavailable as exc:
                unknown.append(f"{label}: {exc}")
                rows.append((name, crepo, "?", "not compared"))
                continue
            if same:
                current.append(f"{label}: {ver}")
                rows.append((name, crepo, ver, "current"))
            elif external:
                behind_external.append(f"{label}: has {ver} ({got}), "
                                       f"upstream is {want[:12]}")
                rows.append((name, crepo, ver, "behind (external)"))
            else:
                behind.append(f"{label}: has {ver} ({got}), "
                              f"upstream is {want[:12]}")
                rows.append((name, crepo, ver, "**BEHIND**"))

    out = []
    if behind:
        out.append("Consumers carrying an out-of-date copy:\n")
        out += [f"  {b}" for b in behind]
        out.append("")
        out.append("Re-vendor each of those, then update its vendored.json.")
    elif behind_external:
        if current:
            out.append(f"No consumer of ours is behind ({len(current)} copies current).")
    elif current:
        out.append(f"Every consumer is current ({len(current)} checked).")
    else:
        # nothing was behind because nothing was looked at, which is not the
        # same sentence and must not be printed as though it were
        out.append("Nothing was compared.")
    if behind_external:
        if out:
            out.append("")
        out.append("Behind, in a repository someone else owns:\n")
        out += [f"  {b}" for b in behind_external]
        out.append("")
        out.append("Each of those takes a pull request to its owner.")
    if unknown:
        out.append("")
        out.append("Not compared, so nothing is claimed about these:\n")
        out += [f"  {u}" for u in unknown]
    report = "\n".join(out)
    print(report)

    if args.summary:
        md = ["# Vendored copies", "",
              "| file | consumer | version | state |", "| --- | --- | --- | --- |"]
        md += [f"| {a} | {b} | {c} | {d} |" for a, b, c, d in rows]
        md += ["", "```", report, "```"]
        with open(args.summary, "w", encoding="utf-8") as fh:
            fh.write("\n".join(md) + "\n")

    if behind:
        return 1
    if behind_external:
        return 3
    return 2 if unknown else 0


if __name__ == "__main__":
    sys.exit(main())
