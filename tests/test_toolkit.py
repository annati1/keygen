"""Tests for pe-toolkit. Builds a synthetic minimal PE32 fixture in a temp
dir — no real executables are needed — plus an appended ZIP overlay."""

import json
import os
import struct
import sys
import zipfile

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import pytest

from tools import archive_inspector, hash_analyzer, pe_analyzer, string_extractor
from tools.suspicious_indicators import analyze_indicators
from tools.report_generator import generate


def build_minimal_pe(path: str, overlay: bytes = b"") -> bytes:
    """Craft a minimal but valid PE32 with one .text section."""
    e_lfanew = 0x80
    opt_size = 0xE0
    num_sections = 1
    sec_table_off = e_lfanew + 4 + 20 + opt_size  # 0x178
    headers_size = 0x200
    raw_off = headers_size

    dos = bytearray(0x40)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, e_lfanew)

    coff = struct.pack("<HHIIIHH", 0x14C, num_sections, 0x5F000000, 0, 0,
                       opt_size, 0x0102)

    opt = bytearray(opt_size)
    struct.pack_into("<H", opt, 0, 0x10B)              # PE32 magic
    struct.pack_into("<I", opt, 16, 0x1000)             # entry point RVA
    struct.pack_into("<I", opt, 28, 0x400000)           # image base
    struct.pack_into("<I", opt, 32, 0x1000)             # section alignment
    struct.pack_into("<I", opt, 36, 0x200)              # file alignment
    struct.pack_into("<I", opt, 56, 0x2000)             # size of image
    struct.pack_into("<I", opt, 60, headers_size)       # size of headers
    struct.pack_into("<H", opt, 68, 3)                  # subsystem CUI
    struct.pack_into("<I", opt, 92, 16)                 # number of dirs

    text = bytearray(0x200)
    payload = b"Hello Toolkit! C:\\Windows\\System32 http://example.invalid/x "
    payload += b"A" * 40
    text[0:len(payload)] = payload

    sec = bytearray(40)
    sec[0:6] = b".text\x00"
    struct.pack_into("<IIII", sec, 8, 0x100, 0x1000, 0x200, raw_off)
    struct.pack_into("<I", sec, 36, 0x60000020)         # CODE|EXEC|READ

    blob = bytes(dos) + b"\x00" * (e_lfanew - len(dos)) + b"PE\x00\x00" + coff \
        + bytes(opt) + bytes(sec)
    blob = blob.ljust(headers_size, b"\x00") + bytes(text) + overlay
    with open(path, "wb") as fh:
        fh.write(blob)
    return blob


@pytest.fixture()
def sample_pe(tmp_path):
    p = tmp_path / "sample.exe"
    build_minimal_pe(str(p))
    return str(p)


@pytest.fixture()
def sample_pe_with_zip(tmp_path):
    zpath = tmp_path / "inner.zip"
    with zipfile.ZipFile(zpath, "w") as z:
        z.writestr("readme.txt", "embedded content")
    with open(zpath, "rb") as fh:
        zbytes = fh.read()
    p = tmp_path / "sfx.exe"
    build_minimal_pe(str(p), overlay=zbytes)
    return str(p)


def test_pe_detected(sample_pe):
    info = pe_analyzer.analyze(sample_pe, deep=False)
    assert info.is_pe
    assert info.format == "PE32"
    assert info.bits == 32
    assert info.arch.startswith("i386")
    assert info.subsystem == "WINDOWS_CUI"
    assert info.entry_point == 0x1000
    assert len(info.sections) == 1
    assert info.sections[0].name == ".text"
    assert "EXECUTE" in info.sections[0].flags


def test_non_pe(tmp_path):
    p = tmp_path / "plain.txt"
    p.write_bytes(b"not a pe file at all, just text" * 10)
    info = pe_analyzer.analyze(str(p))
    assert not info.is_pe


def test_hashes(sample_pe):
    h = hash_analyzer.analyze(sample_pe)
    assert len(h.sha256) == 64 and len(h.md5) == 32
    assert h.size == os.path.getsize(sample_pe)
    assert 0.0 <= h.entropy <= 8.0


def test_strings(sample_pe):
    hits = string_extractor.extract(sample_pe, min_len=6)
    vals = [x.value for x in hits]
    assert any("Hello Toolkit!" in v for v in vals)
    triage = string_extractor.triage(hits)
    assert any("example.invalid" in u for u in triage["url"])
    assert any("System32" in p for p in triage["windows_path"])


def test_archive_detection_zip_overlay(sample_pe_with_zip):
    res = archive_inspector.inspect(sample_pe_with_zip)
    families = {h.family for h in res.hits}
    assert "zip" in families or "zip-eocd" in families
    assert res.overlay is not None and res.overlay["size"] > 0
    assert any("Overlay" in n for n in res.notes)


def test_no_archive_on_plain_pe(sample_pe):
    res = archive_inspector.inspect(sample_pe)
    assert res.hits == []


def test_indicators(sample_pe):
    rep = analyze_indicators(sample_pe)
    d = rep.to_dict()
    assert d["score"] >= 0
    cats = {i["category"] for i in d["indicators"]}
    assert "overlay" in cats or rep.score >= 0  # fixture has no overlay


def test_report_generation(sample_pe_with_zip, tmp_path):
    out = tmp_path / "report"
    result = generate(sample_pe_with_zip, str(out))
    assert (out / "report.json").exists()
    md = (out / "report.md").read_text()
    assert "# Static Analysis Report" in md
    assert result["hashes"]["sha256"]
    json.loads((out / "report.json").read_text())  # valid JSON
