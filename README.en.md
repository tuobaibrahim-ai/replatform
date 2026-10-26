# REPLATFORM — Reverse-Engineering & Malware Analysis Platform

> Local-first Windows platform for static analysis of PE and APK files, YARA
> scanning, Ghidra/Rizin disassembly, binary diffing, batch triage, constrained
> AI agents, and a token-protected local web dashboard.

**Version 1.5.0 · MIT License · Windows 10/11 · Python 3.11+ · Beta**

[Arabic README](README.md) · [Full reference](PLATFORM.md) · [Deployment](docs/DEPLOYMENT.md) · [Architecture](docs/ARCHITECTURE.md) · [Quality](docs/QUALITY.md)

---

## Why

Malware triage usually means juggling apktool, jadx, Ghidra, YARA, Rizin, and a
hex editor — while risking execution of samples on the analyst's workstation.
REPLATFORM unifies these tools behind one CLI, isolates every analysis in a
workspace, and makes risky operations (patching, execution, network) explicit
and confirmed rather than implicit.

**Design invariants**

- **No host execution of samples.** Dynamic analysis only via Windows Sandbox,
  with an explicit `--run --yes` and a process-tree watchdog.
- **No sample uploads.** Integrations send text indicators/queries only, and are
  disabled by default.
- **No secrets in files.** API keys come from environment variables.
- **Every patch is recoverable.** Preview → backup → write → structural check →
  automatic rollback on failure.

---

## Install

### Portable bundle (recommended)

```powershell
Get-FileHash .\replatform-1.5.0-portable.zip -Algorithm SHA256
# compare with SHA256SUMS from the release page
cd replatform-1.5.0
powershell -ExecutionPolicy Bypass -File .\install.ps1
.\replatform.cmd version
```

### From source

```powershell
git clone https://github.com/tuobaibrahim-ai/replatform.git
cd replatform
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
python -m replatform version
```

The portable bundle and sdist include rules, skills, scripts, docs, and tests.
A wheel installed from PyPI provides the package/CLI only; run from the source
tree (or the portable bundle) for the full toolchain.

---

## Quick start

```powershell
python -m replatform tools                  # detect installed toolchain
python -m replatform use sample.exe         # pin the current target
python -m replatform analyze --open         # static analysis + HTML report
python -m replatform analyze app.apk --open
python -m replatform scan samples\ --pdf    # batch triage + PDF
python -m replatform diff old.exe new.exe   # binary diff
python -m replatform sandbox sample.exe     # Windows Sandbox plan (no execution)
python -m replatform serve --open           # local web UI with a token
python -m replatform selftest --full        # 29 end-to-end checks
```

---

## Capabilities

| Area | What you get |
|---|---|
| PE | Architecture, sections & entropy, imports, ASLR/DEP/CFG, .NET, Authenticode |
| APK | Package, SDK levels, permissions, exported components, debuggable, cleartext, ABI, signing v1–v4 |
| Strings | ASCII/UTF-16, URLs, IPs, registry paths, commands, crypto indicators |
| YARA | 19 bundled rules; drop your own `*.yar` into `rules/` |
| Disassembly | Rizin headless: function count, top functions, entry-point disassembly |
| Ghidra | Headless function export, pseudocode, renaming |
| Patching | Preview-first binary patching with unique backup and automatic rollback |
| APK lifecycle | `decode → build → sign → java → install`, with real v1–v4 verification |
| Diff | Shift-resistant similarity, PE/APK-aware comparison, HTML/PDF/JSON |
| Batch | `scan` a folder → HTML/JSON/CSV with CSV formula-injection neutralization |
| Sandbox | Windows Sandbox plan, network off by default, explicit `--run --yes` |
| Agents | Rule-based offline triage or OpenAI-compatible model over HTTPS only |
| Integrations | 12 read-only threat-intel connectors, HTTPS-only, keys from env |

---

## Safety model

| Control | Implementation |
|---|---|
| Execution | No host execution; Sandbox requires `--run --yes` |
| Network | HTTPS only, host allowlist, no redirects, response size cap |
| Secrets | Environment variables only; never written to `config.json` or logs |
| Data | `config.json`, `state.json`, `workspaces/` are git-ignored |
| Patching | Backup + PE/ZIP validation + automatic rollback |
| Web UI | `127.0.0.1` by default, Host allowlist, system paths rejected |
| Supply chain | 3 runtime dependencies + CycloneDX SBOM + `SHA256SUMS` per release |

See [`SECURITY.md`](SECURITY.md) for the threat model and reporting channel.

---

## Quality (verified)

| Metric | Value |
|---|---|
| `unittest` tests | **608** — no network, no real samples |
| Unit coverage | **94%** (CI gate: 90%) |
| Type checking | `mypy` — zero errors across 49 files |
| Static security scan | `flake8-bandit` (`S`) rules inside `ruff` — zero unjustified findings |
| Secret scan | `secretscan` — zero findings (high-confidence patterns, redacted output) |
| Fuzzing | 8 properties × 300 + 120 = 2,520 cases, fixed seed |
| `selftest --full` | 29/29 |
| `benchmark` | 5/5 |
| Deterministic build | `--reproducible` yields byte-identical hashes |
| CI | Windows 2022/2025 · Python 3.11–3.14 · lint + mypy + tests + coverage + audit + build + reproducible release dry-run |
| Release | CycloneDX 1.5 SBOM + `SHA256SUMS` + deterministic portable ZIP + Sigstore signature |

```powershell
python -m ruff check replatform tests repl.py
python -m unittest discover -s tests
python -m coverage run -m unittest discover -s tests; python -m coverage report
python -m replatform selftest --full
```

---

## Documentation

- [`PLATFORM.md`](PLATFORM.md) — full Arabic reference (commands, config, YARA, web, plugins).
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — layers, data flow, design decisions.
- [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md) — install, air-gapped setup, upgrades, troubleshooting.
- [`docs/QUALITY.md`](docs/QUALITY.md) — gates, test inventory, release checklist.
- [`docs/ROADMAP.md`](docs/ROADMAP.md) — priorities and non-goals.
- [`INTEGRATIONS.md`](INTEGRATIONS.md) — connectors, keys, read-only policy.
- [`CHANGELOG.md`](CHANGELOG.md) — release history.

---

## License & commercial

- **Core is MIT** — all analysis features work without a license, with no DRM and
  no license server call. See [`LICENSE`](LICENSE).
- **Open core since 1.5.0** — two *new* enterprise capabilities (`audit` and
  `fleet`) are subscription-licensed; no existing feature was removed. Plans and
  entitlements: [`COMMERCIAL.md`](COMMERCIAL.md) · sales runbook:
  [`docs/SALES.md`](docs/SALES.md).
- **Revenue**: Professional/Enterprise subscriptions, priority support,
  enterprise deployment, custom analyzers/rules, security review, and training.
- Third-party licenses: [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).

---

## Known limitations

- **Windows only** in 1.5.0.
- **External tools are not bundled** (Ghidra/JDK/apktool/jadx/YARA/Rizin);
  related analyzers report `skipped` when missing.
- **The three keyless connectors** (NVD/OSV/CISA KEV) passed live checks
  (TLSv1.3); the nine keyed connectors are untested live pending owner keys,
  but their response normalization is covered by fixtures and missing-key
  refusal is verified.
- **Behavioral monitoring is limited**: Sandbox captures `stdout` only.
- **No code-signing certificate yet**; distribution is ZIP + `SHA256SUMS` +
  keyless Sigstore signatures in CI (verifiable with `cosign verify-blob`).

---

## Contributing

Read [`CONTRIBUTING.md`](CONTRIBUTING.md) and [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).
For vulnerabilities use [`SECURITY.md`](SECURITY.md) — never a public issue.

---

© 2026 REPLATFORM contributors · MIT
