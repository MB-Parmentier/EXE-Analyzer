#!/usr/bin/env python3
"""
pe_headers.py
Simple extractor of PE headers and section table using pefile.
Usage:
    pip install pefile
    python pe_headers.py path/to/binary.exe
    python pe_headers.py path/to/binary.exe --json report.json
"""

import argparse
import json
import sys
from pathlib import Path
import pe_headers_function as phf
import pe_headers_analyzer as pha

scores = []
explanations = []

def main():
    p = argparse.ArgumentParser(description="Extract PE headers & section table")
    p.add_argument("file", help="Path to PE (exe/dll)")
    p.add_argument("--json", help="Write JSON report to this path", default=None)
    args = p.parse_args()

    path = Path(args.file)
    if not path.exists():
        print("File not found:", path, file=sys.stderr)
        sys.exit(2)

    summary = phf.pe_summary(path)
    #phf.pretty_print(summary) <---------------- Affichage d'un résumé du fichier PE
    for fun in pha.check_list:
        elem = fun(summary)
        if elem != 0:
            scores.append(elem[0])
            explanations.append(elem[1])

    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(summary, fh, indent=2)
        print(f"\nWrote JSON report to {args.json}")


if __name__ == "__main__":
    main()
