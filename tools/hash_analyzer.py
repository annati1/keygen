"""Hash calculation and hash-based identification metadata.

Computes MD5 / SHA-1 / SHA-256 / SHA-512 (plus imphash when pefile is
available) so a sample can be looked up in public threat-intel databases
(VirusTotal, MalwareBazaar, ...). This module never phones home: you compare
the hashes yourself.

Usage:
    python -m tools.hash_analyzer <file>
"""

from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass, asdict

from .common import compute_hashes, human_size, file_entropy


@dataclass
class HashReport:
    path: str
    size: int
    size_human: str
    entropy: float
    md5: str
    sha1: str
    sha256: str
    sha512: str
    imphash: str = ""

    def to_dict(self):
        return asdict(self)


def analyze(path: str) -> HashReport:
    hashes = compute_hashes(path)
    imphash = ""
    try:
        import pefile
        pe = pefile.PE(path, fast_load=True)
        imphash = pe.get_imphash()
        pe.close()
    except Exception:
        pass
    size = os.path.getsize(path)
    return HashReport(
        path=path,
        size=size,
        size_human=human_size(size),
        entropy=round(file_entropy(path), 4),
        md5=hashes["md5"],
        sha1=hashes["sha1"],
        sha256=hashes["sha256"],
        sha512=hashes["sha512"],
        imphash=imphash,
    )


def main(argv=None) -> int:
    argv = argv or sys.argv[1:]
    if not argv:
        print(__doc__)
        return 2
    print(json.dumps(analyze(argv[0]).to_dict(), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
