# CVE Report Generator (Linux kernel)

Give it a CVE number, get a detailed, well-structured report built entirely from
official / trusted sources. Optimized for Linux-kernel (kernel.org CNA) CVEs.

## Two ways to use it

### 1. `/cve` slash command (best — full analysis)

In Claude Code, in this directory:

```
/cve CVE-2026-53359
```

This runs the data engine **and** has Claude read the actual commit diffs to write
the analysis sections (root cause, impact, exploitation, mitigations, subsystem
primer) — matching the depth of a hand-written report. Output: `<CVE>_report.md`.

Add `--brief` for a short version:

```
/cve CVE-2026-53359 --brief
```

### 2. Standalone script (fast, deterministic, batchable)

No Claude needed — pure Python (stdlib only):

```
python3 cve_report.py CVE-2026-53359              # writes CVE-2026-53359_report.md
python3 cve_report.py CVE-2026-53359 --stdout     # print to stdout, write nothing
python3 cve_report.py CVE-2026-53359 --json       # also write CVE-2026-53359_data.json
python3 cve_report.py CVE-2026-53359 --json-only  # print the raw data pack (JSON) only
python3 cve_report.py CVE-2026-53359 --no-diff    # skip commit patches (faster, less detail)
python3 cve_report.py CVE-2026-53359 -o out.md    # custom output path
```

The standalone report is complete on data (every field, tables, references) but its
analysis prose is drawn straight from the upstream commit message. Use `/cve` when
you want reasoned root-cause / exploitation analysis.

Batch example:

```
for c in CVE-2024-50264 CVE-2024-53104 CVE-2025-21756; do
  python3 cve_report.py "$c";
done
```

## What goes in a report

- **At a glance** — CVSS (v3.1/v4.0), CWE, EPSS score, CISA KEV status, CISA SSVC
  (Exploitation / Automatable / Technical Impact), NVD status, publish/update dates.
- **Affected component** — subsystem, module (`.ko`), changed file(s) and
  function(s), derived `CONFIG_*`, source repo.
- **Affected & fixed versions** — introducing commit + version, and a per-branch
  table mapping every fix commit to its stable release (6.1.y, 6.6.y, …, mainline),
  plus the vulnerable CPE ranges.
- **Vulnerability details** — the full upstream commit message; `/cve` adds a
  subsystem primer, root-cause analysis, impact, and exploitation assessment.
- **The fix** — mainline commit, author, date, diffstat.
- **Mitigations & detection** and a categorized **References** list (official fix
  commits, CVE/NVD records, discussion threads, distro advisories).
- **Provenance** — exactly which sources were used.

## Data sources (all official / trusted)

| Source | Used for |
|---|---|
| [CVEProject/cvelistV5](https://github.com/CVEProject/cvelistV5) (raw JSON) | Authoritative CVE record: title, description, affected versions/commits, files, CVSS, references |
| [NVD 2.0 API](https://services.nvd.nist.gov) | CVSS (fallback), CWE, vuln status, extra references |
| [FIRST EPSS](https://www.first.org/epss/) | Exploit-prediction score & percentile |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Known-exploited status |
| [git.kernel.org](https://git.kernel.org) | Commit patches: dates, authors, diffs, changed functions; directory `Makefile` for CONFIG derivation |

## Notes

- **No third-party dependencies.** Pure Python 3 stdlib.
- **NVD rate limits:** anonymous NVD access is limited. Set `NVD_API_KEY` in your
  environment to raise the limit (get a free key at nvd.nist.gov).
- **Caching:** the CISA KEV catalog is cached for 6h under `$TMPDIR/cve_report_cache`.
- **How the version mapping works:** the per-branch fix→release table comes from
  the kernel security team's authoritative **dyad** file in
  [vulns.git](https://git.kernel.org/pub/scm/linux/security/vulns.git)
  (`vulnerable_ver:vulnerable_sha:fixed_ver:fixed_sha` pairs). This is used instead
  of order-zipping the CVE record's parallel arrays, which is unreliable when a CVE
  has EOL/unfixed branches, backport-of-bug commits, or a differing number of git
  commits vs. semver branch-caps. Mainline is taken from the dyad header; `:0:0`
  pairs are surfaced as "affected but not fixed (EOL)". Validated against the dyad
  for a diverse set of kernel CVEs (5–9 branches, multi-file, KEV-listed).
- **Scope:** built for kernel.org-assigned CVEs. Non-kernel or non-bippy records
  still produce a report, but without the kernel-specific enrichment.
