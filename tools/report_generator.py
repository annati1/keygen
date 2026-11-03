"""Aggregate module results into a JSON + Markdown analysis report."""

from __future__ import annotations

import datetime
import json
import os
from typing import Optional

from . import archive_inspector, hash_analyzer, pe_analyzer, string_extractor
from .suspicious_indicators import analyze_indicators


def generate(target: str, out_dir: str, max_strings: int = 200) -> dict:
    """Run every module against `target` and write report.json / report.md."""
    os.makedirs(out_dir, exist_ok=True)
    pe = pe_analyzer.analyze(target, deep=True)
    hashes = hash_analyzer.analyze(target)
    arch = archive_inspector.inspect(target)
    strings = string_extractor.extract(target, min_len=6, limit=max_strings)
    triage = string_extractor.triage(strings)
    indicators = analyze_indicators(target)

    result = {
        "tool": "pe-toolkit",
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "target": os.path.abspath(target),
        "hashes": hashes.to_dict(),
        "pe": pe.to_dict(),
        "archives": arch.to_dict(),
        "strings_sample": [s.to_dict() for s in strings],
        "string_triage": triage,
        "indicators": indicators.to_dict(),
    }
    with open(os.path.join(out_dir, "report.json"), "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2)
    with open(os.path.join(out_dir, "report.md"), "w", encoding="utf-8") as fh:
        fh.write(_to_markdown(result))
    return result


def _to_markdown(r: dict) -> str:
    h = r["hashes"]
    pe = r["pe"]
    lines = [
        "# Static Analysis Report",
        "",
        f"- **Target:** `{r['target']}`",
        f"- **Generated:** {r['generated_at']} (UTC) by pe-toolkit",
        f"- **Size:** {h['size_human']} ({h['size']} bytes), entropy {h['entropy']}",
        "",
        "## Hashes",
        "",
        f"- MD5: `{h['md5']}`",
        f"- SHA-1: `{h['sha1']}`",
        f"- SHA-256: `{h['sha256']}`",
        f"- SHA-512: `{h['sha512']}`",
        f"- imphash: `{h.get('imphash') or 'n/a'}`",
        "",
        "## PE Structure",
        "",
        f"- PE file: {pe['is_pe']} ({pe['format']}, {pe['arch']}, {pe['bits']}-bit)",
        f"- Subsystem: {pe['subsystem']}, entry point RVA: 0x{pe['entry_point']:X}",
        f"- Image base: 0x{pe['image_base']:X}, timestamp: {pe['timestamp']}",
        f"- .NET: {pe['is_dotnet']}, compiler/toolchain hints: "
        f"{', '.join(pe['compiler_hints']) or 'none'}",
        "",
        "### Sections",
        "",
        "| Name | VA | VSize | RawSize | Entropy | Flags |",
        "|---|---|---|---|---|---|",
    ]
    for s in pe["sections"]:
        lines.append(
            f"| {s['name']} | 0x{s['virtual_address']:X} | {s['virtual_size']} | "
            f"{s['raw_size']} | {s['entropy']:.2f} | {', '.join(s['flags'])} |")
    lines += ["", "### Imports", ""]
    for dll, funcs in pe["imports"].items():
        lines.append(f"- **{dll}** ({len(funcs)}): {', '.join(funcs[:25])}"
                     + (" ..." if len(funcs) > 25 else ""))
    if not pe["imports"]:
        lines.append("- (none resolved)")
    if pe["exports"]:
        lines += ["", "### Exports", "", "- " + ", ".join(pe["exports"][:50])]
    lines += ["", "## Embedded Archives / Overlay", ""]
    for hit in r["archives"]["hits"]:
        lines.append(f"- 0x{hit['offset']:X}: {hit['kind']}")
    if r["archives"]["overlay"]:
        ov = r["archives"]["overlay"]
        lines.append(f"- Overlay: {ov['size']} bytes at 0x{ov['offset']:X}, "
                     f"first bytes `{ov['first_bytes_hex'][:32]}...`")
    for n in r["archives"]["notes"]:
        lines.append(f"- {n}")
    if not r["archives"]["hits"] and not r["archives"]["overlay"]:
        lines.append("- (none detected)")
    lines += ["", "## Suspicious Indicators", "",
              f"**Score:** {r['indicators']['score']}", ""]
    for i in r["indicators"]["indicators"]:
        lines.append(f"- [{i['severity'].upper()}] **{i['category']}:** {i['detail']}")
    lines += ["", "## String Triage (top matches)", ""]
    for name, matches in r["string_triage"].items():
        if matches:
            lines.append(f"### {name}")
            for m in matches[:10]:
                lines.append(f"- `{m}`")
            lines.append("")
    lines += ["## Warnings / Limitations", ""]
    for w in pe["warnings"]:
        lines.append(f"- {w}")
    lines += [
        "- Heuristics are hypotheses, not verdicts; validate with dynamic analysis",
        "  in an isolated VM before drawing conclusions.",
        "",
    ]
    return "\n".join(lines)


def main(argv=None) -> int:
    import sys
    argv = argv or sys.argv[1:]
    if len(argv) < 2:
        print("usage: python -m tools.report_generator <target-file> <out-dir>")
        return 2
    result = generate(argv[0], argv[1])
    print(f"report written to {argv[1]}/report.json and report.md "
          f"(indicator score: {result['indicators']['score']})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
