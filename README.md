# keygen — pe-toolkit (authorized static PE analysis)

A modular, documented Python toolkit for **authorized** static analysis of
Windows PE files: identification, hashing, embedded-archive detection, string
extraction, import/section analysis, suspicious-indicator heuristics, and
automated report generation.

> ⚠️ **Scope & legal notice.** Use this toolkit only on files you own or are
> explicitly authorized to analyze. It must not be used to reverse engineer,
> document, or facilitate the bypass of licensing/copy protection in
> third-party commercial software, and it contains no key-generation, patching,
> or activation logic by design. See `docs/methodology.md`.
>
> ⚠️ **The file `AdskNLM.exe` in this repository's history is a known
> license-circumvention tool for Autodesk products.** It should not be
> redistributed. It is matched by `.gitignore` (`*.exe`) for any *new* files,
> but it already exists in the git history; removing it requires history
> rewriting (`git filter-repo` / BFG) on the owner's side, plus a DMCA-style
> takedown consideration. This toolkit was **not** used to analyze its
> internals, and no findings about its bypass mechanism are included here.

## Layout

```
tools/
  analyze.py                # one-shot CLI: run everything, write a report
  pe_analyzer.py            # PE identification, headers, sections, imports
  archive_inspector.py      # embedded archive / SFX / overlay detection (read-only)
  string_extractor.py       # ASCII/UTF-16 strings + triage patterns
  hash_analyzer.py          # MD5/SHA-1/SHA-256/SHA-512, entropy, imphash
  suspicious_indicators.py  # heuristic triage (hypotheses, not verdicts)
  report_generator.py       # JSON + Markdown report aggregation
docs/
  methodology.md            # safe & legal RE workflow (static + dynamic lab)
  report-template.md        # template for a technical report
tests/
  test_toolkit.py           # pytest suite using a synthetic PE fixture
requirements.txt
```

## Quick start

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# One-shot analysis of an authorized sample:
python -m tools.analyze path/to/sample.exe -o analysis-report/

# Individual modules:
python -m tools.pe_analyzer sample.exe
python -m tools.archive_inspector sample.exe
python -m tools.string_extractor sample.exe --min 6 --limit 500
python -m tools.hash_analyzer sample.exe
python -m tools.suspicious_indicators sample.exe

# Tests:
pytest -q
```

Without `pefile` installed, the toolkit still performs header-level PE
analysis (format, sections, overlay, entropy); imports/exports are skipped
with a warning.

## Methodology

See `docs/methodology.md` for the full workflow: legal prerequisites, static
analysis pipeline (hash → classify → strings → structure → disassembly →
capa), and how to run dynamic analysis safely in an isolated VM with Process
Monitor / Process Explorer / Wireshark.

## What this toolkit deliberately excludes

- No keygen / license-key generation or validation.
- No binary patching, hooking, or licensing-bypass helpers.
- No automatic extraction of embedded archives (detection only; extraction
  belongs in an isolated VM with proper tooling).
- Target binaries are never committed (`*.exe`, `samples/` in `.gitignore`).
