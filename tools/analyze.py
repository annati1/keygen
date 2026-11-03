"""One-shot CLI: run the whole toolkit against a file.

    python -m tools.analyze <target-file> [-o output-dir]

Writes report.json and report.md into the output directory (default:
./analysis-report).
"""

from __future__ import annotations

import sys

from .report_generator import generate


def main(argv=None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__)
        return 0 if argv else 2
    target = argv[0]
    out_dir = "analysis-report"
    if "-o" in argv:
        out_dir = argv[argv.index("-o") + 1]
    result = generate(target, out_dir)
    print(f"[+] target      : {result['target']}")
    print(f"[+] sha256      : {result['hashes']['sha256']}")
    print(f"[+] pe          : {result['pe']['is_pe']} "
          f"({result['pe']['format']}, {result['pe']['arch']})")
    print(f"[+] archives    : {len(result['archives']['hits'])} signature hit(s)")
    print(f"[+] indicators  : {len(result['indicators']['indicators'])} "
          f"(score {result['indicators']['score']})")
    print(f"[+] report      : {out_dir}/report.json, {out_dir}/report.md")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
