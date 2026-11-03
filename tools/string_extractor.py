"""String extraction (ASCII and UTF-16LE), similar in spirit to Sysinternals
Strings / FLOSS, for triage of suspicious files.

Usage:
    python -m tools.string_extractor <file> [--min 6] [--limit 500]
"""

from __future__ import annotations

import json
import re
import sys
from dataclasses import dataclass, asdict
from typing import Iterator, List, Optional

from .common import iter_chunks

# Patterns of triage interest (URLs, paths, registry keys, commands...).
INTERESTING_PATTERNS = {
    "url": re.compile(rb"https?://[^\s\"'<>]+"),
    "ipv4": re.compile(rb"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "UNC_path": re.compile(rb"\\\\[A-Za-z0-9_.-]+\\"),
    "windows_path": re.compile(rb"[A-Za-z]:\\[^\x00-\x1f\"<>|]+"),
    "registry_key": re.compile(rb"(?:HKEY_(?:LOCAL_MACHINE|CURRENT_USER|USERS|CLASSES_ROOT)"
                               rb"|HKLM|HKCU)\\[^\x00-\x1f]+"),
    "powershell": re.compile(rb"powershell[^\x00]{0,80}", re.IGNORECASE),
    "cmd_shell": re.compile(rb"cmd\.exe[^\x00]{0,60}", re.IGNORECASE),
    "base64_blob": re.compile(rb"[A-Za-z0-9+/]{120,}={0,2}"),
    "pem_key": re.compile(rb"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
}


@dataclass
class StringHit:
    offset: int
    encoding: str
    value: str

    def to_dict(self):
        return asdict(self)


def _extract(buf: bytes, base_offset: int, min_len: int) -> Iterator[StringHit]:
    ascii_re = re.compile(rb"[\x20-\x7e]{%d,}" % min_len)
    utf16_re = re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % min_len)
    for m in ascii_re.finditer(buf):
        yield StringHit(base_offset + m.start(), "ascii",
                        m.group(0).decode("ascii"))
    for m in utf16_re.finditer(buf):
        yield StringHit(base_offset + m.start(), "utf-16le",
                        m.group(0).decode("utf-16le"))


def extract(path: str, min_len: int = 5, limit: int = 100000,
            window: int = 4 * 1024 * 1024) -> List[StringHit]:
    """Stream the file and yield extracted strings (deduplicated)."""
    hits: List[StringHit] = []
    seen = set()
    offset = 0
    tail = b""
    for chunk in iter_chunks(path, window):
        buf = tail + chunk
        base = offset - len(tail)
        for hit in _extract(buf, base, min_len):
            key = (hit.encoding, hit.value)
            if key not in seen:
                seen.add(key)
                hits.append(hit)
                if len(hits) >= limit:
                    return hits
        tail = buf[-(2 * min_len):]
        offset += len(chunk)
    return hits


def triage(hits: List[StringHit]) -> dict:
    """Match extracted strings against patterns of triage interest."""
    blob = "\n".join(h.value for h in hits)
    out = {}
    for name, rx in INTERESTING_PATTERNS.items():
        matches = sorted(set(m.group(0).decode("ascii", "replace") for m in rx.finditer(blob.encode("ascii", "replace"))))
        # regex above ran on encoded blob; simpler: run on original bytes joined
        out[name] = matches[:50]
    return out


def main(argv=None) -> int:
    argv = argv or sys.argv[1:]
    if not argv:
        print(__doc__)
        return 2
    path = argv[0]
    min_len = 5
    limit = 100000
    if "--min" in argv:
        min_len = int(argv[argv.index("--min") + 1])
    if "--limit" in argv:
        limit = int(argv[argv.index("--limit") + 1])
    hits = extract(path, min_len=min_len, limit=limit)
    print(json.dumps([h.to_dict() for h in hits[:limit]], indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
