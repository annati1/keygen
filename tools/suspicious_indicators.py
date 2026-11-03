"""Heuristic suspicious-behavior indicators for PE triage.

These are *hypotheses, not verdicts*: each finding is a reason to look
closer, not proof of maliciousness. Many packers and DRM/licensing products
share traits with malware (RWX sections, process injection APIs, entropy).

Usage:
    python -m tools.suspicious_indicators <file>
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass, asdict, field
from typing import List

from .pe_analyzer import analyze

# Import names that frequently indicate injection / persistence / network
# staging in malware triage.
SUSPICIOUS_IMPORTS = {
    "kernel32.dll": {
        "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
        "SetThreadContext", "QueueUserAPC", "VirtualProtectEx",
        "LoadLibraryA", "LoadLibraryW", "GetProcAddress", "WinExec",
        "CreateProcessA", "CreateProcessW", "CreateServiceA",
        "OpenServiceA", "StartServiceA", "SetWindowsHookExA",
        "SetWindowsHookExW", "GetAsyncKeyState", "GetKeyState",
        "OpenProcess", "TerminateProcess",
    },
    "advapi32.dll": {
        "RegSetValueExA", "RegSetValueExW", "RegCreateKeyExA",
        "CreateServiceA", "ChangeServiceConfigA",
    },
    "wininet.dll": {"URLDownloadToFileA", "URLDownloadToFileW", "InternetOpenA"},
    "urlmon.dll": {"URLDownloadToFileA", "URLDownloadToFileW", "URLMoniker"},
    "ws2_32.dll": {"connect", "send", "recv", "WSAStartup"},
    "crypt32.dll": {"CryptDecrypt", "CryptAcquireContextA", "CryptGenKey"},
    "user32.dll": {"SetWindowsHookExA", "SetWindowsHookExW", "keybd_event"},
    "shell32.dll": {"ShellExecuteA", "ShellExecuteW"},
}

PACKER_SECTION_NAMES = {
    "UPX0", "UPX1", "UPX2", ".aspack", ".adata", ".themida", ".winlice",
    ".vmp0", ".vmp1", ".enigma1", ".enigma2", ".MPRESS1", ".MPRESS2",
    ".ndata", "_pyi", "PYZ",
}


@dataclass
class IndicatorReport:
    path: str
    indicators: List[dict] = field(default_factory=list)

    def add(self, severity: str, category: str, detail: str):
        self.indicators.append(
            {"severity": severity, "category": category, "detail": detail})

    @property
    def score(self) -> int:
        weights = {"info": 0, "low": 1, "medium": 2, "high": 3}
        return sum(weights.get(i["severity"], 0) for i in self.indicators)

    def to_dict(self):
        return {"path": self.path, "score": self.score,
                "indicators": self.indicators}


def analyze_indicators(path: str) -> IndicatorReport:
    rep = IndicatorReport(path=path)
    info = analyze(path, deep=True)
    if not info.is_pe:
        rep.add("info", "format", f"not a PE file (format={info.format})")
        return rep

    # Section-level checks.
    for s in info.sections:
        if s.name.strip("\x00") in PACKER_SECTION_NAMES or \
                any(s.name.startswith(p) for p in (".vmp", ".MPRESS", "_pyi")):
            rep.add("medium", "packer",
                    f"section '{s.name}' looks like a packer section")
        if s.entropy >= 7.5:
            rep.add("medium", "entropy",
                    f"section '{s.name}' entropy {s.entropy:.2f} (>=7.5 suggests "
                    "compression/encryption)")
        if {"EXECUTE", "WRITE"} <= set(s.flags) and "READ" in s.flags:
            rep.add("medium", "section-perms",
                    f"section '{s.name}' is RWX (read/write/execute)")

    # Import-level checks.
    for dll, funcs in info.imports.items():
        for f in funcs:
            if f in SUSPICIOUS_IMPORTS.get(dll.lower(), set()):
                rep.add("low", "import",
                        f"{dll}!{f} — commonly used for injection/persistence/staging")
    injected = ("VirtualAllocEx" in info.imports.get("kernel32.dll", []) or
                "WriteProcessMemory" in info.imports.get("kernel32.dll", []) or
                "CreateRemoteThread" in info.imports.get("kernel32.dll", []))
    if injected:
        rep.add("high", "process-injection",
                "combination of VirtualAllocEx/WriteProcessMemory/CreateRemoteThread "
                "present — classic remote-process injection pattern")

    if info.tls_callbacks or "TLS" in info.data_directories:
        rep.add("medium", "tls-callback", "TLS callback directory present; code may "
                "execute before the entry point")

    if info.overlay_size > 0:
        rep.add("low", "overlay",
                f"{info.overlay_size} bytes appended after last section "
                "(possible embedded archive/payload)")

    if not info.imports:
        rep.add("low", "imports", "no import table resolved (packed or crafted)")

    if info.is_dotnet:
        rep.add("info", "runtime", ".NET assembly — decompile with dnSpy/ILSpy "
                "instead of reading raw disassembly")
    return rep


def main(argv=None) -> int:
    argv = argv or sys.argv[1:]
    if not argv:
        print(__doc__)
        return 2
    print(json.dumps(analyze_indicators(argv[0]).to_dict(), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
