# REPLATFORM — Reverse-Engineering & Malware Analysis Platform

> Offline-first Windows platform for static analysis of PE and APK files, YARA
> scanning, disassembly, binary diffing, batch triage, constrained AI agents,
> and a local authenticated web dashboard.

**Version 1.3.1 · MIT License · Windows 10/11 · Python 3.11+**

---

## Why

Malware triage usually means juggling apktool, jadx, Ghidra, YARA, Rizin, and a
hex editor — while risking execution of samples on the analyst's workstation.
REPLATFORM unifies these tools behind one CLI, isolates every analysis in a
workspace, and makes risky operations (patching, execution, network) explicit
and confirmed rather than implicit.

---

## Quick start

```powershell
python repl.py tools                  # detect installed toolchain
python repl.py use sample.exe         # pin the current target
python repl.py analyze                # static analysis + HTML report
python repl.py analyze app.apk --open
python repl.py scan samples\ --pdf    # batch triage + PDF
python repl.py diff old.exe new.exe   # binary diff (CDC-based similarity)
python repl.py sandbox sample.exe     # Windows Sandbox plan (no execution)
python repl.py selftest --full        # 29 end-to-end checks
python -m unittest discover -s tests  # 112 regression tests
```

---

## Capabilities

| Area | What you get |
|---|---|
| PE | Architecture, sections & entropy, imports, ASLR/DEP/CFG, .NET, Authenticode |
| APK | Package, SDK levels, permissions, exported components, signing v1–v4, certificate |
| Strings | ASCII/UTF-16, URLs, IPs, registry paths, commands, crypto indicators |
| YARA | 19 bundled rules; drop your own `*.yar` into `rules/` |
| Disassembly | Rizin headless: function count, top functions, entry-point disassembly |
| Ghidra | Headless function export, pseudocode, renaming |
| Patching | Preview-first binary patching with automatic backup and rollback |
| Diff | CDC-resistant similarity, PE/APK-aware comparison, HTML/PDF/JSON |
| Sandbox | Windows Sandbox plan, network off by default, explicit `--run --yes` |
| Agents | Rule-based offline triage or OpenAI-compatible model over HTTPS only |
| Integrations | 12 read-only threat-intel connectors, HTTPS-only, keys from env |

---

## Safety model

- **No host execution of samples.** Dynamic analysis only via Windows Sandbox,
  with a watchdog that terminates the process tree.
- **Read-only agent tools** restricted to the analysis target.
- **Integrations never upload samples** — text indicators and queries only.
- **Secrets never in code or logs** — API keys come from environment variables;
  `config.json` is git-ignored.
- **Strict limits** on file size, archive expansion (zip bombs), entry counts,
  parser timeouts, and response sizes.
- **TLS verification always on** (certificate + hostname), with a modern CA bundle.

---

## Documentation

- `PLATFORM.md` — full Arabic reference (commands, architecture, security).
- `INTEGRATIONS.md` — connector catalog and key setup.
- `CHANGELOG.md` — release history.
- `PROJECT_REPORT.md` — current project status report.

---

## Development

```powershell
python -m pip install -e ".[dev]"
python -m ruff check replatform tests repl.py
python -m unittest discover -s tests -v
python -m coverage run -m unittest discover -s tests; python -m coverage report
```

CI runs on Windows with Python 3.12 and 3.13: lint, compile, unit tests,
coverage gate (45% for logic modules), and self-test.
