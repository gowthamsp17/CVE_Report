---
description: Generate a detailed Linux-kernel CVE report (data engine + deep code analysis)
argument-hint: <CVE-ID> [--brief]
allowed-tools: Bash, Read, Write, WebFetch, Edit
---

You are producing a **detailed, authoritative Linux-kernel CVE report** for: `$ARGUMENTS`

This combines a deterministic data engine (all official/trusted sources) with your
own deep analysis of the actual commit diffs. Follow every step.

## Step 1 — Run the data engine

```
python3 /Users/gowtham-23345/CVE_Report/cve_report.py $ARGUMENTS --json
```

This fetches cvelistV5 + NVD + EPSS + CISA KEV + git.kernel.org and writes
`<CVE>_report.md` (baseline) and `<CVE>_data.json` (full structured data pack) in
the current directory.

- If it errors (record not found / not yet published), report that verbatim and stop.
- If the assigner is **not** `Linux` (e.g. a kernel bug filed by another CNA with no
  bippy data), tell the user the deep kernel treatment won't fully apply, then produce
  the best generic report you can from whatever data exists.

## Step 2 — Absorb the data pack

`Read` the `<CVE>_data.json` file in full. It contains: title, upstream commit
message (`description`), `cvss`, `cwe`, `epss`, `kev`, `ssvc`, affected
`files`/`functions`/`modules`/`config`, the `versions` block (introduced commit +
per-branch fix→release mapping), `cpe_ranges`, categorized `references`, and
`patches` (subject/author/date/diffstat/functions for each fetched commit).

## Step 3 — Fetch the real code diffs (this is what makes the report good)

Get the actual patches so you can explain the bug from the code, not just the
commit message:

- **Mainline fix** (`versions.fixes[].commit` where `is_mainline` is true):
  `curl -s "https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/patch/?id=<commit>"`
- **Introducing commit** (`versions.intro_commits[0]`): same URL with that hash.

Read both diffs. Understand exactly what changed and why the old code was unsafe.
If the fix references a prior commit (e.g. "Commit abc123 fixed ..."), fetch that too
when it clarifies the root cause.

## Step 4 — Write the final report

Overwrite `<CVE>_report.md` with the structure below. **Keep every deterministic
table and fact from the engine's baseline** (version mapping, commit table, CVSS,
references, provenance) and **add** your analysis sections. Use clean Markdown.
Be precise and cite specific functions/lines/structs from the diff. Never invent a
CVSS, date, commit, or version — if the engine didn't find it, say "not available".

Required sections:

1. **Title** — `# <CVE-ID> — <title>`
2. **At a glance** — the engine's table (CVE, assigner, published, CVSS, CWE, EPSS,
   KEV, SSVC, NVD status).
3. **Executive summary** — 3–5 sentences: what the bug is, the affected
   subsystem/component, who can trigger it and from where, the worst-case impact,
   and how urgent patching is. Written for a security engineer skimming.
4. **Affected component** — subsystem, module (`.ko`), file(s), changed function(s),
   `CONFIG_*`, source repo. (from engine, refine if the diff reveals more functions.)
5. **Subsystem primer** — a short, accurate explanation of the relevant kernel
   mechanism so the reader has context (e.g. what shadow paging / the netfilter set
   / the socket lifecycle is). 1–2 tight paragraphs. This is the "context" section.
6. **Affected & fixed versions** — the engine's introduced line + per-branch
   fix→release table + CPE ranges. State plainly how many years the bug was latent.
7. **Root cause analysis** — the core section. Explain the defect from the code:
   the vulnerable code path, the incorrect assumption/missing check, the data
   structure involved, and the exact sequence that leads to the bug (UAF/OOB/race/etc).
   Reference the introducing commit and what changed since.
8. **Impact** — concrete consequences: crash/DoS (host or guest?), memory
   corruption, privilege escalation, info leak. Distinguish reliable vs worst-case.
9. **Exploitation** — prerequisites (privilege level, config such as nested virt,
   local vs remote), attack vector, difficulty, and whether a public PoC/exploit or
   KEV listing exists. Interpret the CVSS vector and the CISA SSVC (Exploitation /
   Automatable / Technical Impact) in plain language.
10. **The fix** — what the patch changes (the added check / reordering / free-path
    fix) and why it closes the hole. Include mainline commit, author, date, diffstat.
11. **Mitigations & detection** — patch guidance per branch; any config/runtime
    workaround if unpatched (derive from the trigger conditions — do not fabricate a
    workaround that doesn't exist); detection ideas (KEV/PoC-driven urgency, relevant
    audit points).
12. **References** — the engine's categorized list (fix commits, CVE/NVD records,
    discussion, advisories). Keep all official links.
13. **Provenance** — data sources + generation timestamp (from engine).

If `$ARGUMENTS` contains `--brief`, produce only sections 1–3, 6, and 12.

## Step 5 — Report back

Print the saved report path and a 2–3 line spoken summary (severity, who's affected,
patch urgency). Do not paste the whole report into chat unless asked.
