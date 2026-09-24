#!/usr/bin/env python3
"""RagShield CLI — scan untrusted text for prompt injection, sanitize documents.

    python -m ragshield scan [--file FILE]      # stdin if no --file
    python -m ragshield sanitize --in FILE [--out FILE]

scan exit codes: 0 clean, 1 suspicious, 2 blocked.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .pipeline import RagShield


def _scan(args: argparse.Namespace) -> int:
    if args.file is not None:
        text = Path(args.file).read_text(encoding="utf-8", errors="ignore")
        source = str(args.file)
    else:
        text = sys.stdin.read()
        source = "<stdin>"

    scan = RagShield().scan_document(text)
    print("RagShield scan — prompt-injection report")
    print(f"source : {source}")
    print(scan.summary())
    return {"clean": 0, "suspicious": 1, "blocked": 2}[scan.verdict]


def _sanitize(args: argparse.Namespace) -> int:
    text = Path(args.infile).read_text(encoding="utf-8", errors="ignore")
    result = RagShield().sanitize_document(text)
    if args.outfile is not None:
        Path(args.outfile).write_text(result.text, encoding="utf-8")
        print(f"sanitized {args.infile} → {args.outfile}", file=sys.stderr)
    else:
        sys.stdout.write(result.text)
    for action in result.actions:
        print(f"  action: {action}", file=sys.stderr)
    return 0


def _demo(_args) -> int:
    from . import demo
    demo.main()
    return 0


def main(argv: list = None) -> int:
    ap = argparse.ArgumentParser(
        prog="ragshield",
        description="untrusted documents in, a RAG pipeline that doesn't get played")
    sub = ap.add_subparsers(dest="command", required=True)

    scan_p = sub.add_parser("scan", help="scan untrusted text for prompt injection")
    scan_p.add_argument("--file", type=Path, default=None,
                        help="file to scan (default: stdin)")
    scan_p.set_defaults(func=_scan)

    san_p = sub.add_parser("sanitize", help="sanitize an untrusted document")
    san_p.add_argument("--in", dest="infile", type=Path, required=True,
                       help="untrusted input file")
    san_p.add_argument("--out", dest="outfile", type=Path, default=None,
                       help="sanitized output file (default: stdout)")
    san_p.set_defaults(func=_sanitize)

    demo_p = sub.add_parser("demo", help="run the 6-document walkthrough")
    demo_p.set_defaults(func=_demo)

    args = ap.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
