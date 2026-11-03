# Technical Analysis Report — Template

> Fill every section with evidence (offsets, hashes, disassembly excerpts) or
> explicitly mark it "not determined". Distinguish confirmed vs. hypothesis.

## 1. Executive summary
- One paragraph: what the file is, what it does at a high level, main risks.

## 2. File identification & classification
- Size, MD5/SHA-1/SHA-256, file type, PE/PE32+/ELF/Mach-O, architecture,
  subsystem, signed? (by whom), hash lookups (VirusTotal/MalwareBazaar).

## 3. Internal structure
- Sections table (name, VA, size, entropy, flags), overlay, resources,
  embedded archives (format, offset, how detected).

## 4. Embedded components
- List extracted items with their own hashes. Note extraction environment.

## 5. Reverse-engineering findings
- Entry point and initialization path; key functions with renamed
  identifiers; API usage grouped by purpose (network, file, registry,
  process, crypto).

## 6. Execution flow
- Diagram (mermaid) or Graphviz of the main path and important branches.

## 7. Compression / encoding / obfuscation
- For each mechanism: format/algorithm, where it lives (function/offset),
  how it was identified, what could and could not be recovered. Never claim
  "encrypted" for data that is merely compressed or encoded.

## 8. Modification / patching mechanism (if any)
- Describe at architecture level what the sample changes and how it locates
  its target (signatures, versions, offsets). **Do not publish working
  offsets/patches for third-party commercial software.**

## 9. Dependencies & external communications
- DLLs, services, URLs/IPs, protocols, DNS.

## 10. Security risks & suspicious behavior
- Map indicators to intent where evidence allows.

## 11. Limitations & unresolved questions

## 12. Conclusions
