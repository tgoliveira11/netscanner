#!/usr/bin/env python3
"""Build pfSense-pkg-NetScanner on FreeBSD / pfSense."""

from __future__ import annotations

import argparse
import os
import pathlib
import platform
import subprocess
import sys

PKG_DIR_NAME = "pfSense-pkg-NetScanner"


def parse_tag(value: str) -> tuple[str, str]:
    if value.startswith("v"):
        value = value[1:]
    parts = value.split(".")
    if len(parts) == 3 and "_" not in parts[2]:
        parts[2] = f"_{parts[2]}"
        value = ".".join(parts)
    if "_" in value:
        version, revision = value.split("_", 1)
    else:
        version, revision = value, "0"
    return version, revision


def main() -> int:
    parser = argparse.ArgumentParser(description="Build pfSense-pkg-NetScanner")
    parser.add_argument(
        "--tag",
        "-t",
        required=True,
        help="Package version, e.g. 0.1.0 or 0.1.0_1",
    )
    parser.add_argument(
        "--output",
        "-o",
        default=".",
        help="Directory for the built .pkg file",
    )
    parser.add_argument(
        "--pfsense-version",
        help="Rename output to pfSense-<ver>-pkg-NetScanner.pkg (e.g. 2.8.1)",
    )
    args = parser.parse_args()

    version, revision = parse_tag(args.tag)
    root = pathlib.Path(__file__).resolve().parent.parent
    pkg_dir = root / PKG_DIR_NAME
    makefile = pkg_dir / "Makefile"

    if not makefile.exists():
        print(f"Missing {makefile}", file=sys.stderr)
        return 1

    text = makefile.read_text()
    text = text.replace(
        "PORTVERSION=\t0.1.0",
        f"PORTVERSION=\t{version}",
    )
    text = text.replace(
        "PORTREVISION=\t0",
        f"PORTREVISION=\t{revision}",
    )
    makefile.write_text(text)

    os.environ["ALLOW_UNSUPPORTED_SYSTEM"] = "yes"
    if platform.system() != "FreeBSD":
        print(
            "WARNING: not FreeBSD — updated Makefile only; run `make package` on pfSense.",
            file=sys.stderr,
        )
        return 0

    subprocess.check_call(
        ["make", "package", "-C", str(pkg_dir), "DISABLE_VULNERABILITIES=yes"]
    )

    built = next((pkg_dir / "work" / "pkg").glob("*.pkg"))
    suffix = f"_{revision}" if revision != "0" else ""
    release_name = (
        f"pfSense-{args.pfsense_version}-pkg-NetScanner.pkg"
        if args.pfsense_version
        else f"{PKG_DIR_NAME}-{version}{suffix}.pkg"
    )
    out = pathlib.Path(args.output).resolve() / release_name
    out.write_bytes(built.read_bytes())
    print(out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
