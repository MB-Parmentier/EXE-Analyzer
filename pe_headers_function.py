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
    try:
        pe = pefile.PE(str(path), fast_load=True)
    except pefile.PEFormatError as peErr:
        print(f"Invalid file type: {peErr}")
        exit(1)
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

