"""PE identification and structural analysis.

Two layers:
  * a dependency-free minimal parser (DOS/PE headers, sections, overlay) that
    always works, and
  * an optional `pefile`-backed deep analysis (imports, exports, resources,
    DLL characteristics, TLS callbacks) used when pefile is installed.

Usage:
    python -m tools.pe_analyzer <file>
"""

from __future__ import annotations

import json
import struct
import sys
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional

from .common import human_size

MACHINE_TYPES = {
    0x014C: "i386 (x86)",
    0x8664: "x86-64 (AMD64)",
    0x01C0: "ARM",
    0xAA64: "ARM64",
    0x0200: "IA-64",
}

SUBSYSTEMS = {
    1: "NATIVE", 2: "WINDOWS_GUI", 3: "WINDOWS_CUI", 7: "POSIX_CUI",
    9: "WINDOWS_CE_GUI", 10: "EFI_APPLICATION", 14: "XBOX",
}

# Directories in the optional-header data directory table (index -> name).
DATA_DIRECTORIES = (
    "EXPORT", "IMPORT", "RESOURCE", "EXCEPTION", "SECURITY", "BASERELOC",
    "DEBUG", "ARCHITECTURE", "GLOBALPTR", "TLS", "LOAD_CONFIG", "BOUND_IMPORT",
    "IAT", "DELAY_IMPORT", "COM_DESCRIPTOR", "RESERVED",
)


@dataclass
class Section:
    name: str
    virtual_address: int
    virtual_size: int
    raw_size: int
    raw_offset: int
    characteristics: int
    entropy: float = 0.0

    @property
    def flags(self) -> List[str]:
        c = self.characteristics
        flags = []
        if c & 0x20000000: flags.append("EXECUTE")
        if c & 0x40000000: flags.append("READ")
        if c & 0x80000000: flags.append("WRITE")
        if c & 0x02000000: flags.append("DISCARDABLE")
        if c & 0x00000020: flags.append("CODE")
        if c & 0x00000040: flags.append("INITIALIZED_DATA")
        return flags


@dataclass
class PEInfo:
    path: str
    is_pe: bool = False
    format: str = "unknown"
    arch: str = "unknown"
    bits: int = 0
    subsystem: str = "unknown"
    entry_point: int = 0
    image_base: int = 0
    timestamp: int = 0
    characteristics: int = 0
    dll_characteristics: int = 0
    sections: List[Section] = field(default_factory=list)
    data_directories: Dict[str, int] = field(default_factory=dict)
    overlay_offset: Optional[int] = None
    overlay_size: int = 0
    imports: Dict[str, List[str]] = field(default_factory=dict)
    exports: List[str] = field(default_factory=list)
    compiler_hints: List[str] = field(default_factory=list)
    is_dotnet: bool = False
    tls_callbacks: List[int] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["sections"] = [
            {**asdict(s), "flags": s.flags} for s in self.sections
        ]
        return d


def _parse_minimal(path: str) -> PEInfo:
    """Dependency-free parse of DOS header, COFF header, optional header and
    the section table. Enough to classify any PE without third-party libs."""
    info = PEInfo(path=path)
    with open(path, "rb") as fh:
        dos = fh.read(0x40)
        if len(dos) < 0x40 or dos[:2] != b"MZ":
            return info
        (e_lfanew,) = struct.unpack_from("<I", dos, 0x3C)
        fh.seek(e_lfanew)
        sig = fh.read(4)
        if sig != b"PE\x00\x00":
            return info
        info.is_pe = True
        coff = fh.read(20)
        machine, num_sections, timestamp, _sym, _nsym, opt_size, chars = (
            struct.unpack("<HHIIIHH", coff)
        )
        info.timestamp = timestamp
        info.characteristics = chars
        info.arch = MACHINE_TYPES.get(machine, f"unknown (0x{machine:04X})")
        opt = fh.read(opt_size)
        if len(opt) < 2:
            info.warnings.append("truncated optional header")
            return info
        magic = struct.unpack_from("<H", opt, 0)[0]
        if magic == 0x10B:      # PE32
            info.format, info.bits = "PE32", 32
            entry = struct.unpack_from("<I", opt, 16)[0]
            image_base = struct.unpack_from("<I", opt, 28)[0]
            num_dirs = struct.unpack_from("<I", opt, 92)[0]
            dir_off = 96
        elif magic == 0x20B:    # PE32+
            info.format, info.bits = "PE32+", 64
            entry = struct.unpack_from("<I", opt, 16)[0]
            image_base = struct.unpack_from("<Q", opt, 24)[0]
            num_dirs = struct.unpack_from("<I", opt, 108)[0]
            dir_off = 112
        else:
            info.warnings.append(f"unknown optional-header magic 0x{magic:04X}")
            return info
        subsystem = struct.unpack_from("<H", opt, 68)[0]
        dll_chars = struct.unpack_from("<H", opt, 70)[0]
        info.entry_point = entry
        info.image_base = image_base
        info.subsystem = SUBSYSTEMS.get(subsystem, f"unknown ({subsystem})")
        info.dll_characteristics = dll_chars
        n = min(num_dirs, len(DATA_DIRECTORIES))
        for i in range(n):
            rva, size = struct.unpack_from("<II", opt, dir_off + 8 * i)
            if rva or size:
                info.data_directories[DATA_DIRECTORIES[i]] = rva
        info.is_dotnet = "COM_DESCRIPTOR" in info.data_directories

        # Section table.
        sec_off = e_lfanew + 4 + 20 + opt_size
        fh.seek(sec_off)
        raw = fh.read(40 * num_sections)
        max_end = 0
        for i in range(num_sections):
            hdr = raw[i * 40:(i + 1) * 40]
            if len(hdr) < 40:
                break
            name = hdr[:8].rstrip(b"\x00").decode("ascii", "replace")
            vsize, vaddr, rsize, roff = struct.unpack_from("<IIII", hdr, 8)
            chars_s = struct.unpack_from("<I", hdr, 36)[0]
            sec = Section(name, vaddr, vsize, rsize, roff, chars_s)
            if roff and rsize:
                fh.seek(roff)
                data = fh.read(min(rsize, 8 * 1024 * 1024))
                from .common import shannon_entropy
                sec.entropy = shannon_entropy(data)
            info.sections.append(sec)
            if roff + rsize > max_end:
                max_end = roff + rsize
        import os
        fsize = os.path.getsize(path)
        if fsize > max_end:
            info.overlay_offset = max_end
            info.overlay_size = fsize - max_end
    return info


def _deep_analyze(info: PEInfo) -> PEInfo:
    """Enrich with pefile when available (imports/exports/TLS/overlay)."""
    try:
        import pefile
    except ImportError:
        info.warnings.append(
            "pefile not installed; deep analysis (imports/exports) skipped"
        )
        return info
    try:
        pe = pefile.PE(info.path, fast_load=False)
    except Exception as exc:  # malformed PE
        info.warnings.append(f"pefile failed to parse: {exc}")
        return info
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll = entry.dll.decode("ascii", "replace")
            funcs = [imp.name.decode("ascii", "replace") if imp.name else
                     f"ord_{imp.ordinal}" for imp in entry.imports]
            info.imports[dll] = funcs
    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        info.exports = [
            s.name.decode("ascii", "replace") if s.name else f"ord_{s.ordinal}"
            for s in pe.DIRECTORY_ENTRY_EXPORT.symbols
        ]
    if hasattr(pe, "DIRECTORY_ENTRY_TLS") and pe.DIRECTORY_ENTRY_TLS:
        cb = pe.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks
        addr = cb - pe.OPTIONAL_HEADER.ImageBase
        info.warnings.append(
            f"TLS callback present at RVA 0x{addr:X} (code runs before entry point)"
        )
        while True:
            info.tls_callbacks.append(addr)
            break
    overlay = pe.get_overlay()
    if overlay:
        import os
        info.overlay_size = len(overlay)
        info.overlay_offset = os.path.getsize(info.path) - len(overlay)
    pe.close()
    return info


def _compiler_hints(info: PEInfo, path: str) -> List[str]:
    """Coarse compiler/toolchain hints from section names + data directories."""
    hints = []
    names = {s.name for s in info.sections}
    if any(n.startswith(".MPRESS") for n in names): hints.append("MPRESS packer")
    if "UPX0" in names or "UPX1" in names: hints.append("UPX packer")
    if any(n in (".aspack", ".adata") for n in names): hints.append("ASPack")
    if ".themida" in names or ".winlice" in names: hints.append("Themida/WinLicense")
    if any(n.startswith(".vmp") for n in names): hints.append("VMProtect")
    if ".enigma" in names: hints.append("Enigma Protector")
    if ".ndata" in names: hints.append("NSIS installer")
    if info.is_dotnet: hints.append(".NET / C# (CLR header present)")
    if any(n.startswith("_pyi") or n == "PYZ" for n in names): hints.append("PyInstaller")
    if not info.imports and info.is_pe and not hints:
        hints.append("no import table (packed or hand-crafted?)")
    return hints


def analyze(path: str, deep: bool = True) -> PEInfo:
    """Full PE analysis. Returns a PEInfo dataclass."""
    info = _parse_minimal(path)
    if not info.is_pe:
        return info
    if deep:
        info = _deep_analyze(info)
    info.compiler_hints = _compiler_hints(info, path)
    return info


def main(argv=None) -> int:
    argv = argv or sys.argv[1:]
    if not argv:
        print(__doc__)
        return 2
    info = analyze(argv[0])
    print(json.dumps(info.to_dict(), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
