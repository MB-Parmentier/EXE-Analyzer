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

import pefile


def flags_to_text(characteristics):
    flags = []
    # IMAGE_SCN_* values commonly used (subset)
    if characteristics & 0x20000000:
        flags.append("MEM_EXECUTE")
    if characteristics & 0x40000000:
        flags.append("MEM_READ")
    if characteristics & 0x80000000:
        flags.append("MEM_WRITE")
    return ",".join(flags) if flags else "NONE"


def pe_summary(path: Path):
    pe = pefile.PE(str(path), fast_load=True)
    summary = {}

    # DOS header
    summary["DOS_Header"] = {
        "e_magic": hex(pe.DOS_HEADER.e_magic),
        "e_lfanew": hex(pe.DOS_HEADER.e_lfanew),
    }

    # NT headers / File header
    summary["File_Header"] = {
        "Machine": hex(pe.FILE_HEADER.Machine),
        "NumberOfSections": pe.FILE_HEADER.NumberOfSections,
        "TimeDateStamp": pe.FILE_HEADER.TimeDateStamp,
        "Characteristics": hex(pe.FILE_HEADER.Characteristics),
    }

    # Optional header (Image base, EntryPoint, sizes)
    oh = pe.OPTIONAL_HEADER
    summary["Optional_Header"] = {
        "ImageBase": hex(oh.ImageBase),
        "AddressOfEntryPoint": hex(oh.AddressOfEntryPoint),
        "SizeOfImage": oh.SizeOfImage,
        "SizeOfHeaders": oh.SizeOfHeaders,
        "SectionAlignment": oh.SectionAlignment,
        "FileAlignment": oh.FileAlignment,
    }

    # Sections
    sections = []
    for s in pe.sections:
        sections.append(
            {
                "Name": s.Name.decode(errors="ignore").rstrip("\x00"),
                "VirtualSize": s.Misc_VirtualSize,
                "VirtualAddress": hex(s.VirtualAddress),
                "SizeOfRawData": s.SizeOfRawData,
                "PointerToRawData": s.PointerToRawData,
                "Characteristics": hex(s.Characteristics),
                "Flags": flags_to_text(s.Characteristics),
            }
        )
    summary["Sections"] = sections

    # Basic file metrics
    try:
        file_size = path.stat().st_size
    except Exception:
        file_size = None
    summary["File"] = {"Path": str(path), "Size": file_size}

    return summary


def pretty_print(summary):
    print("=== DOS Header ===")
    for k, v in summary["DOS_Header"].items():
        print(f"  {k}: {v}")
    print("\n=== File Header ===")
    for k, v in summary["File_Header"].items():
        print(f"  {k}: {v}")
    print("\n=== Optional Header ===")
    for k, v in summary["Optional_Header"].items():
        print(f"  {k}: {v}")
    print("\n=== Sections ===")
    for s in summary["Sections"]:
        print(
            f"  {s['Name']}: VA={s['VirtualAddress']} VSize={s['VirtualSize']} RawSize={s['SizeOfRawData']} RawOff={s['PointerToRawData']} Flags={s['Flags']}"
        )
    if summary["File"]["Size"] is not None:
        print(f"\nFile size: {summary['File']['Size']} bytes")


def main():
    p = argparse.ArgumentParser(description="Extract PE headers & section table")
    p.add_argument("file", help="Path to PE (exe/dll)")
    p.add_argument("--json", help="Write JSON report to this path", default=None)
    args = p.parse_args()

    path = Path(args.file)
    if not path.exists():
        print("File not found:", path, file=sys.stderr)
        sys.exit(2)

    summary = pe_summary(path)
    pretty_print(summary)

    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(summary, fh, indent=2)
        print(f"\nWrote JSON report to {args.json}")


if __name__ == "__main__":
    main()
