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

Pure Python (stdlib only). By default the report is written by a local **zLLM**
proxy (OpenAI-compatible) from a JSON data pack; use `--template` for the built-in
offline renderer.

```
python3 cve_report.py CVE-2026-53359              # writes CVE-2026-53359_report.md (via zLLM)
python3 cve_report.py CVE-2026-53359 --template   # built-in renderer, no LLM needed
python3 cve_report.py CVE-2026-53359 --stdout     # print to stdout, write nothing
python3 cve_report.py CVE-2026-53359 --json       # also write CVE-2026-53359_data.json
python3 cve_report.py CVE-2026-53359 --json-only  # print the raw data pack (JSON) only
python3 cve_report.py CVE-2026-53359 -o out.md    # custom output path
```

Options:

| Flag | Effect |
|---|---|
| `--template` | Use the built-in template renderer instead of zLLM |
| `--llm-model MODEL` | zLLM model id (default `gpt-5.4` or `$ZLLM_MODEL`) |
| `--no-diff` | Skip commit patches |
| `--no-vendor` | Skip Debian / Exploit-DB / linuxkernelcves / TuxCare lookups |
| `--no-media` | Skip Feedly / Hacker Wire / Hacker News / community coverage |
| `--linux-src PATH` | Local Linux git checkout (default `~/Linux_Stable/linux`) |
| `--configs-dir PATH` | Directory of `config-<version>` files (default `./configs`) |
| `--no-module-resolve` | Skip per-branch module resolution |
| `--module-stats-script PATH` | Path to `module_stats.py` (default `~/Server-Modules/Scripts/module_stats.py`) |
| `--no-module-stats` | Skip fleet exposure lookup |

zLLM environment variables: `ZLLM_BASE_URL` (default `http://127.0.0.1:8787/v1`),
`ZLLM_API_KEY` (default `unused`), `ZLLM_MODEL` (default `gpt-5.4`). Start the proxy
with `zllm start`; if it is unreachable the script exits with an error (no silent
fallback), so use `--template` for offline runs.

The LLM only uses facts from the data pack; missing fields are reported as such.

Batch example:

```
for c in CVE-2024-50264 CVE-2024-53104 CVE-2025-21756; do
  python3 cve_report.py "$c";
done
```

## What goes in a report

- **At a glance** — CVSS (v3.1/v4.0), CWE (all official IDs with source), EPSS,
  CISA KEV, CISA SSVC, NVD status, public exploit (Exploit-DB), dates.
- **Affected component** — subsystem, module (`.ko`), files, functions, `CONFIG_*`,
  plus a per-branch module resolution table (Branch | File | CONFIG_ symbol | Result)
  for 5.10.y / 6.1.y / 6.12.y from the local source tree and `.config` files.
- **Affected & fixed versions** — introducing commit/version, per-branch fixed
  releases with commit dates, EOL/unfixed branches, CPE ranges.
- **Fleet exposure** — per-region module usage from `module_stats.py` (Total IPs,
  Loaded, ZServices, VMs, Phys Srv, KVM Host, Cont Host, Containers).
- **Vulnerability details** — weakness class, upstream description, and a
  **TuxCare status** table (CVE link, Debian ELS / KernelCare fixes).
- **The fix** — mainline commit, subject, author, commit date, diffstat, patch link,
  stable backports table.
- **Mitigations & detection**, categorized **References**, **Debian** per-suite
  status, **Media & community coverage**, and **Provenance**.

Red Hat, Ubuntu, SUSE, Arch and OSV sections are intentionally not included.

### CWE

Only official CWE data is shown; nothing is guessed. Sources are checked in order
**CNA** (cvelistV5), then **NVD**, then **CISA-ADP** (cvelistV5 `adp` containers).
The first source with any CWE wins and **all** its CWEs are listed (e.g.
`CWE-362, CWE-416`) with the source named. If none has one, the report says
"No official record".

### Dates

Only the **commit date** is used (never the author date). It is read from the local
Linux tree with `git show -s --format=%cd <commit>`; if a commit is not in the local
tree, no date is shown.

### NVD status

NVD status is the `vulnStatus` field from the NVD API. It shows where the CVE is in
NVD's processing.

For example, CVE-2026-80844 has status **Received**: NVD has ingested the record
from the CVE list but hasn't analyzed it yet, so the report has no NVD CVSS score
and no NVD CWE for it.

Common values, in the usual order:

- **Received:** ingested, not yet reviewed.
- **Awaiting Analysis:** queued for an analyst.
- **Undergoing Analysis:** being scored and enriched.
- **Analyzed:** complete, with CVSS, CWE and CPE data.
- **Modified:** changed after analysis, so it needs re-review.
- **Deferred:** NVD will not analyze it for now.
- **Rejected:** withdrawn.

## Data sources (all official / trusted)

| Source | Used for |
|---|---|
| [CVEProject/cvelistV5](https://github.com/CVEProject/cvelistV5) (raw JSON) | Authoritative CVE record: title, description, affected versions/commits, files, CVSS, references |
| [NVD 2.0 API](https://services.nvd.nist.gov) | CVSS (fallback), CWE, vuln status, extra references |
| [FIRST EPSS](https://www.first.org/epss/) | Exploit-prediction score & percentile |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Known-exploited status |
| [kernel vulns.git](https://git.kernel.org/pub/scm/linux/security/vulns.git) | Authoritative dyad: vulnerable:fixed commit/release pairs |
| [git.kernel.org](https://git.kernel.org) | Commit patches (fallback when not in local tree), directory `Makefile` for CONFIG derivation |
| Local Linux tree + `find_module_new.py` | Commit dates/patches via `git show`; per-branch module resolution |
| `module_stats.py` (internal) | Fleet-wide module usage |
| [Debian Security Tracker](https://security-tracker.debian.org) | Per-suite status / fixed version |
| [TuxCare CVE tracker](https://tuxcare.com/cve-tracker/) | Debian ELS / KernelCare fix status |
| [Exploit-DB](https://www.exploit-db.com), [linuxkernelcves.com](https://github.com/nluedtke/linux_kernel_cves) | Public exploits, colloquial name |
| Feedly, The Hacker Wire, The Hacker News, CyberSecurityNews, SecurityOnline | Media & community coverage |

## Notes

- **No third-party dependencies.** Pure Python 3 stdlib.
- **NVD rate limits:** anonymous NVD access is limited. Set `NVD_API_KEY` in your
  environment to raise the limit (get a free key at nvd.nist.gov).
- **Caching:** the CISA KEV catalog (6h), Debian tracker and linuxkernelcves data
  (24h) are cached under `$TMPDIR/cve_report_cache`.
- **Large data packs:** the JSON sent to zLLM is slimmed (patch bodies, media
  chatter) to stay under the proxy's content-length limit.
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
