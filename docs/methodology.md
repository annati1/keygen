# Safe Reverse-Engineering Methodology

This document describes how to conduct static and dynamic binary analysis
**responsibly and legally**. It is target-agnostic.

## 1. Legal & ethical prerequisites

- Analyze only software you own, or for which you have **explicit written
  authorization** (employer-owned tooling, bug-bounty scope, academic
  contracts). Many jurisdictions criminalize circumvention of access controls
  (e.g. DMCA §1201 in the US, EU Directive 2009/24/EC) and ToS violations.
- Never analyze or redistribute tools whose purpose is to **defeat licensing
  or copy protection** of commercial software. Understanding them well enough
  to document a bypass is not "education" — it is the bypass.
- Do not commit target binaries, extracted proprietary components, keys, or
  credentials to version control. Commit scripts, docs, and *sanitized*
  metadata (hashes, section names) only.

## 2. Static analysis workflow

1. **Identify**: hashes (MD5/SHA-1/SHA-256), file type, PE headers — run
   `python -m tools.analyze <file> -o report/`.
2. **Classify**: packer/installer detection (`tools.archive_inspector`), section
   entropy, compiler hints (`tools.pe_analyzer`).
3. **Strings**: `tools.string_extractor` for URLs, paths, registry keys, and
   encoded blobs; use FLOSS for stack/obfuscated strings.
4. **Structure**: imports/exports (`pefile`), resources, TLS callbacks,
   overlays/embedded archives. If an archive is present and you are authorized,
   extract it **inside the VM only**, with 7-Zip/unrar, scanning first.
5. **Disassembly**: Ghidra or IDA/BinDiff. Rename functions as you understand
   them; export annotations to keep the project reusable.
6. **Capabilities**: run `capa` to map code to MITRE ATT&CK-style behaviors.

## 3. Dynamic analysis (isolated lab only)

- Use a dedicated VM (Windows 10/11 snapshot) with **no shared folders, no
  network bridging to production**, and revert to a clean snapshot after each
  run.
- Instrument with Process Monitor (file/registry), Process Explorer (DLLs,
  handles), Wireshark (network/DNS), and API Monitor.
- Expect anti-analysis tricks (VM detection, debugger checks, time bombs).
  Document them; do not defeat them on production systems.
- Never run untrusted samples on a host that holds credentials or access to
  real accounts.

## 4. Reporting

- Separate **confirmed findings** (evidence: offset, hash, disassembly) from
  **hypotheses**.
- Include hashes so others can reproduce; include tool versions.
- Include an execution-flow diagram (Graphviz/mermaid) of the main path.
- State limitations explicitly (what you could not parse, missing keys, etc.).

## 5. Practice targets (safe & legal)

- crackmes.one, Flare-On challenges, MalwareTech's challenges
- Your own compiled "hello world" variants
- Old abandonware explicitly released for analysis
- Public malware datasets for defenders (e.g. via academic/VirusTotal
  researcher access)

## 6. What this toolkit deliberately does NOT do

- It does not generate, validate, or patch license keys / activation codes.
- It does not patch or hook binaries to bypass licensing.
- It does not extract or repackage proprietary payloads for redistribution.
