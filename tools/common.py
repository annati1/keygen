"""Shared helpers: safe file reading, hashing, entropy.

All helpers stream the file in chunks so multi-gigabyte samples do not
exhaust memory.
"""

from __future__ import annotations

import hashlib
import math
import os
from typing import Dict, Iterator

CHUNK_SIZE = 1024 * 1024  # 1 MiB

# Hash algorithms exposed by hash_analyzer / report_generator.
HASH_ALGORITHMS = ("md5", "sha1", "sha256", "sha512")


def iter_chunks(path: str, chunk_size: int = CHUNK_SIZE) -> Iterator[bytes]:
    """Yield the file in chunks. Raises FileNotFoundError for missing files."""
    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(chunk_size)
            if not chunk:
                return
            yield chunk


def compute_hashes(path: str, algorithms=HASH_ALGORITHMS) -> Dict[str, str]:
    """Return {algorithm: hexdigest} for the given file."""
    hashers = {name: hashlib.new(name) for name in algorithms}
    for chunk in iter_chunks(path):
        for h in hashers.values():
            h.update(chunk)
    return {name: h.hexdigest() for name, h in hashers.items()}


def shannon_entropy(data: bytes) -> float:
    """Shannon entropy of a byte string, in bits per byte (0.0 - 8.0)."""
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    entropy = 0.0
    for c in counts:
        if c:
            p = c / n
            entropy -= p * math.log2(p)
    return entropy


def file_entropy(path: str, chunk_size: int = CHUNK_SIZE) -> float:
    """Approximate whole-file entropy (weighted by chunk size)."""
    total = 0
    weighted = 0.0
    for chunk in iter_chunks(path, chunk_size):
        total += len(chunk)
        weighted += shannon_entropy(chunk) * len(chunk)
    return weighted / total if total else 0.0


def safe_size(path: str) -> int:
    return os.path.getsize(path)


def human_size(num_bytes: int) -> str:
    """Format a byte count as a human-readable string."""
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if num_bytes < 1024 or unit == "TiB":
            return f"{num_bytes:.2f} {unit}" if unit != "B" else f"{num_bytes} B"
        num_bytes /= 1024
    return f"{num_bytes} B"
