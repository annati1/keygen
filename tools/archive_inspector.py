"""Embedded-archive / SFX / overlay detection and safe inspection.

Scans a file for well-known container signatures anywhere in the byte stream
(archives are often appended as overlays in self-extracting installers), and
classifies them. Inspection is *read-only*: archives are listed, never
extracted to disk by this module. Extraction, when authorized, should be done
in an isolated VM with up-to-date tools (7-Zip, unrar) with archive-entropy
and path-traversal checks.

Usage:
    python -m tools.archive_inspector <file>
"""

from __future__ import annotations

import json
import os
import struct
import sys
from dataclasses import dataclass, asdict
from typing import List, Optional

from .common import iter_chunks, shannon_entropy

# (signature, name, format family) — matched at any offset.
SIGNATURES = [
    (b"7z\xbc\xaf\x27\x1c", "7-Zip archive", "7z"),
    (b"Rar!\x1a\x07\x00", "RAR archive (v4)", "rar4"),
    (b"Rar!\x1a\x07\x01\x00", "RAR archive (v5)", "rar5"),
    (b"MSCF", "Microsoft Cabinet (CAB)", "cab"),
    (b"PK\x03\x04", "ZIP archive (local header)", "zip"),
    (b"PK\x05\x06", "ZIP end-of-central-directory", "zip-eocd"),
    (b"\xfd7zXZ\x00", "XZ stream", "xz"),
    (b"\x1f\x8b\x08", "gzip stream", "gzip"),
    (b"BZh", "bzip2 stream", "bzip2"),
    (b"ustar", "POSIX tar (at offset 257)", "tar"),
    (b"\x28\xb5\x2f\xfd", "Zstandard frame", "zstd"),
    (b"\x04\x22\x4d\x18", "LZ4 frame", "lz4"),
    (b"SZDD", "Microsoft Compress (SZDD)", "szdd"),
    (b"!<arch>\n", "ar archive", "ar"),
]

# Installer / packer strings commonly embedded in SFX stubs.
INSTALLER_MARKERS = [
    (b"Nullsoft Install System", "NSIS installer"),
    (b"Inno Setup", "Inno Setup installer"),
    (b"Wise Installation", "Wise installer"),
    (b"Setup Factory", "Setup Factory installer"),
    (b"7zSFX", "7-Zip SFX module"),
    (b"WinRAR SFX", "WinRAR SFX module"),
    (b"sfxcab", "CAB SFX module"),
    (b"PYINSTALLER", "PyInstaller bundle"),
    (b"_MEIPASS", "PyInstaller extraction dir"),
    (b"InstallShield", "InstallShield installer"),
]


@dataclass
class ArchiveHit:
    offset: int
    kind: str
    family: str

    def to_dict(self):
        return asdict(self)


@dataclass
class InspectionResult:
    path: str
    size: int
    hits: List[ArchiveHit]
    installer_markers: List[str]
    overlay: Optional[dict]
    notes: List[str]

    def to_dict(self):
        return {
            "path": self.path,
            "size": self.size,
            "hits": [h.to_dict() for h in self.hits],
            "installer_markers": self.installer_markers,
            "overlay": self.overlay,
            "notes": self.notes,
        }


def _scan_signatures(path: str, max_hits: int = 64) -> List[ArchiveHit]:
    """Sliding-window scan for container signatures at any file offset."""
    hits: List[ArchiveHit] = []
    window = 8 * 1024 * 1024
    overlap = 64
    offset = 0
    prev_tail = b""
    for chunk in iter_chunks(path, window):
        buf = prev_tail + chunk
        base = offset - len(prev_tail)
        for sig, name, family in SIGNATURES:
            if family == "tar":
                continue  # handled specially below
            start = 0
            while len(hits) < max_hits:
                idx = buf.find(sig, start)
                if idx < 0:
                    break
                hits.append(ArchiveHit(base + idx, name, family))
                start = idx + 1
        # tar magic lives at offset 257 within its header block.
        idx = buf.find(b"ustar")
        if idx >= 0:
            hits.append(ArchiveHit(base + idx - 257 if idx >= 257 else base + idx,
                                   "POSIX tar", "tar"))
        prev_tail = buf[-overlap:]
        offset += len(chunk)
    # Deduplicate (overlapping windows) and sort by offset.
    seen = set()
    uniq = []
    for h in sorted(hits, key=lambda h: h.offset):
        key = (h.offset, h.family)
        if key not in seen:
            seen.add(key)
            uniq.append(h)
    return uniq


def _scan_markers(path: str, limit: int = 256 * 1024 * 1024) -> List[str]:
    found = set()
    read = 0
    for chunk in iter_chunks(path):
        for marker, label in INSTALLER_MARKERS:
            if marker in chunk:
                found.add(label)
        read += len(chunk)
        if read >= limit:
            break
    return sorted(found)


def _overlay_info(path: str, pe_info=None) -> Optional[dict]:
    """Describe trailing data beyond the last PE section, if any."""
    try:
        from .pe_analyzer import analyze
        info = pe_info or analyze(path, deep=False)
        if info.is_pe and info.overlay_size:
            off = info.overlay_offset or 0
            with open(path, "rb") as fh:
                fh.seek(off)
                head = fh.read(64)
            return {
                "offset": off,
                "size": info.overlay_size,
                "first_bytes_hex": head.hex(),
                "entropy": shannon_entropy(head),
            }
    except Exception:
        pass
    return None


def inspect(path: str) -> InspectionResult:
    """Read-only inspection: find embedded archives, installer markers, overlay."""
    size = os.path.getsize(path)
    hits = _scan_signatures(path)
    markers = _scan_markers(path)
    overlay = _overlay_info(path)
    notes = []
    if overlay:
        notes.append(
            f"Overlay of {overlay['size']} bytes at offset {overlay['offset']} "
            "(data appended after the last PE section) — typical of SFX archives."
        )
    if any(h.family in ("7z", "zip", "rar4", "rar5", "cab") for h in hits):
        notes.append(
            "Embedded archive signature(s) found. If extraction is authorized, do it "
            "in an isolated VM and treat contents as untrusted."
        )
    if markers:
        notes.append("Installer/packer markers: " + ", ".join(markers))
    return InspectionResult(path, size, hits, markers, overlay, notes)


def main(argv=None) -> int:
    argv = argv or sys.argv[1:]
    if not argv:
        print(__doc__)
        return 2
    print(json.dumps(inspect(argv[0]).to_dict(), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
