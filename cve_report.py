#!/usr/bin/env python3
"""
cve_report.py — Linux kernel CVE report generator.

Given a CVE ID, gathers everything known about it from official / trusted
sources and produces a detailed, well-structured report.

Data sources (all official / trusted):
  * CVEProject/cvelistV5      (authoritative CVE record, raw JSON; cveawg fallback)
  * kernel vulns.git dyad     (authoritative vulnerable:fixed commit<->release pairs)
  * NVD 2.0 API               (CVSS, CWE, vuln status, extra references)
  * FIRST EPSS API            (exploit-prediction score)
  * CISA KEV catalog          (known-exploited status)
  * git.kernel.org            (commit patches: dates, authors, diffs, functions)
  * Red Hat Security Data API (RHSA advisories, per-product fix state, mitigation)
  * Debian Security Tracker   (per-suite status/fixed_version, cached full dump)
  * Arch Linux Security       (package status + fixed version, when tracked)
  * OSV.dev                   (aggregator: commit ranges, related distro advisories)
  * linuxkernelcves.com data  (colloquial vuln name, affected/last-vulnerable version)
  * Exploit-DB                (public PoC-exploit availability)
  * Ubuntu / SUSE             (reference links only -- no public per-CVE API)

Optimized for Linux-kernel (kernel.org CNA) CVEs. The per-branch fix->release
mapping comes from the kernel security team's own dyad file, which authoritatively
pairs each fixed commit with its release and marks unfixed (EOL) branches.

Usage:
    python3 cve_report.py CVE-2026-53359
    python3 cve_report.py CVE-2026-53359 --stdout
    python3 cve_report.py CVE-2026-53359 --json            # also write *_data.json
    python3 cve_report.py CVE-2026-53359 --json-only       # data pack to stdout
    python3 cve_report.py CVE-2026-53359 -o /path/out.md
    python3 cve_report.py CVE-2026-53359 --no-diff         # skip commit patches
    python3 cve_report.py CVE-2026-53359 --no-vendor       # skip vendor/distro lookups

No third-party dependencies (stdlib only). Set NVD_API_KEY to raise NVD limits.
"""

from __future__ import annotations

import argparse
import gzip
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #

UA = "cve-report/1.1 (+https://github.com/CVEProject/cvelistV5)"
KERNEL_GIT = "https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git"
VULNS_GIT = "https://git.kernel.org/pub/scm/linux/security/vulns.git"
CACHE_DIR = os.path.join(os.environ.get("TMPDIR", "/tmp"), "cve_report_cache")
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)

# vendor / distro / aggregator sources (verified empirically: no auth, no API
# key, stdlib-fetchable -- see fetch_redhat/fetch_archlinux/fetch_osv/etc.)
REDHAT_CVE_API = "https://access.redhat.com/hydra/rest/securitydata/cve/%s.json"
REDHAT_CVE_PAGE = "https://access.redhat.com/security/cve/%s"
DEBIAN_TRACKER_JSON = "https://security-tracker.debian.org/tracker/data/json"
DEBIAN_CVE_PAGE = "https://security-tracker.debian.org/tracker/%s"
ARCH_ITEM_API = "https://security.archlinux.org/%s.json"
ARCH_CVE_PAGE = "https://security.archlinux.org/%s"
OSV_API = "https://api.osv.dev/v1/vulns/%s"
OSV_PAGE = "https://osv.dev/vulnerability/%s"
LKC_JSON = ("https://raw.githubusercontent.com/nluedtke/linux_kernel_cves/"
            "master/data/kernel_cves.json")
EXPLOITDB_SEARCH = "https://www.exploit-db.com/search?cve=%s"
EXPLOITDB_EXPLOIT_PAGE = "https://www.exploit-db.com/exploits/%s"
UBUNTU_CVE_PAGE = "https://ubuntu.com/security/%s"
SUSE_CVE_PAGE = "https://www.suse.com/security/cve/%s.html"

# tokens that appear in diff hunk context but are NOT the changed function
NOT_A_FUNCTION = re.compile(
    r"^(EXPORT_SYMBOL\w*|MODULE_\w+|DEFINE_\w+|DECLARE_\w+|LIST_HEAD|"
    r"BUILD_BUG_ON\w*|static_assert|BLOCKING_NOTIFIER\w*|ATOMIC_\w+|"
    r"DEVICE_ATTR\w*|SYSCALL_DEFINE\w*|TRACE_EVENT\w*|__setup|module_\w+)$"
)

CWE_KEYWORDS = [
    ("use-after-free", ("CWE-416", "Use After Free")),
    ("use after free", ("CWE-416", "Use After Free")),
    ("uaf", ("CWE-416", "Use After Free")),
    ("double-free", ("CWE-415", "Double Free")),
    ("double free", ("CWE-415", "Double Free")),
    ("out-of-bounds write", ("CWE-787", "Out-of-bounds Write")),
    ("out of bounds write", ("CWE-787", "Out-of-bounds Write")),
    ("out-of-bounds read", ("CWE-125", "Out-of-bounds Read")),
    ("out of bounds read", ("CWE-125", "Out-of-bounds Read")),
    ("out-of-bounds", ("CWE-787", "Out-of-bounds Write")),
    ("buffer overflow", ("CWE-120", "Buffer Copy without Checking Size of Input")),
    ("stack overflow", ("CWE-787", "Out-of-bounds Write")),
    ("null pointer", ("CWE-476", "NULL Pointer Dereference")),
    ("null-ptr-deref", ("CWE-476", "NULL Pointer Dereference")),
    ("null deref", ("CWE-476", "NULL Pointer Dereference")),
    ("race condition", ("CWE-362", "Race Condition")),
    ("race", ("CWE-362", "Race Condition")),
    ("deadlock", ("CWE-833", "Deadlock")),
    ("infinite loop", ("CWE-835", "Loop with Unreachable Exit Condition")),
    ("integer overflow", ("CWE-190", "Integer Overflow or Wraparound")),
    ("underflow", ("CWE-191", "Integer Underflow")),
    ("memory leak", ("CWE-401", "Missing Release of Memory")),
    ("uninitialized", ("CWE-457", "Use of Uninitialized Variable")),
    ("information leak", ("CWE-200", "Exposure of Sensitive Information")),
    ("info leak", ("CWE-200", "Exposure of Sensitive Information")),
    ("divide by zero", ("CWE-369", "Divide By Zero")),
    ("division by zero", ("CWE-369", "Divide By Zero")),
    ("refcount", ("CWE-911", "Improper Update of Reference Count")),
]


# --------------------------------------------------------------------------- #
# HTTP helpers
# --------------------------------------------------------------------------- #

def _http(url, timeout=30, headers=None, retries=3):
    hdrs = {"User-Agent": UA, "Accept": "*/*"}
    if headers:
        hdrs.update(headers)
    last = None
    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, headers=hdrs)
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = resp.read()
                if resp.headers.get("Content-Encoding", "").lower() == "gzip":
                    data = gzip.decompress(data)
                return data
        except urllib.error.HTTPError as e:
            last = e
            if e.code == 404:
                return None
            if e.code in (403, 429, 503) and attempt < retries - 1:
                time.sleep(2 * (attempt + 1))
                continue
        except Exception as e:  # noqa: BLE001
            last = e
            if attempt < retries - 1:
                time.sleep(1.5 * (attempt + 1))
                continue
    if last is not None:
        sys.stderr.write("  ! fetch failed: %s (%s)\n" % (url, last))
    return None


def _http_json(url, timeout=30, headers=None):
    raw = _http(url, timeout=timeout, headers=headers)
    if not raw:
        return None
    try:
        return json.loads(raw.decode("utf-8", "replace"))
    except Exception:  # noqa: BLE001
        return None


def _http_text(url, timeout=30, headers=None):
    raw = _http(url, timeout=timeout, headers=headers)
    return raw.decode("utf-8", "replace") if raw else None


def _cached(name, ttl, producer):
    try:
        os.makedirs(CACHE_DIR, exist_ok=True)
        path = os.path.join(CACHE_DIR, name)
        if os.path.exists(path) and (time.time() - os.path.getmtime(path)) < ttl:
            with open(path, "rb") as fh:
                return fh.read()
        data = producer()
        if data:
            with open(path, "wb") as fh:
                fh.write(data)
        return data
    except Exception:  # noqa: BLE001
        return producer()


# --------------------------------------------------------------------------- #
# URL helpers
# --------------------------------------------------------------------------- #

def _cve_parts(cve_id):
    m = re.match(r"^CVE-(\d{4})-(\d+)$", cve_id, re.IGNORECASE)
    if not m:
        return None, None, None
    year, num = m.group(1), m.group(2)
    bucket = num[:-3] + "xxx" if len(num) > 3 else "0xxx"
    return year, num, bucket


def cvelist_url(cve_id):
    year, num, bucket = _cve_parts(cve_id)
    if not year:
        return None
    return ("https://raw.githubusercontent.com/CVEProject/cvelistV5/main/"
            "cves/%s/%s/CVE-%s-%s.json" % (year, bucket, year, num))


def cvelist_blob_url(cve_id):
    year, num, bucket = _cve_parts(cve_id)
    if not year:
        return None
    return ("https://github.com/CVEProject/cvelistV5/blob/main/"
            "cves/%s/%s/CVE-%s-%s.json" % (year, bucket, year, num))


# --------------------------------------------------------------------------- #
# Source fetchers
# --------------------------------------------------------------------------- #

def fetch_cvelist(cve_id):
    """Fetch the record; validate the returned id (raw CDN can serve stale
    blobs) and fall back to the authoritative cveawg API on mismatch."""
    cve_id = cve_id.upper()

    def _ok(rec):
        return (isinstance(rec, dict)
                and _dig(rec, "cveMetadata", "cveId", default="").upper() == cve_id)

    rec = _http_json(cvelist_url(cve_id))
    if _ok(rec):
        return rec
    if rec is not None:
        sys.stderr.write("  ! raw cvelistV5 returned a mismatched record; "
                         "falling back to cveawg API\n")
    alt = _http_json("https://cveawg.mitre.org/api/cve/%s" % cve_id, timeout=25)
    if _ok(alt):
        return alt
    # last resort: return whatever the raw endpoint gave (may be None)
    return rec if _ok(rec) else (alt if isinstance(alt, dict) else None)


def fetch_dyad(cve_id):
    """kernel vulns.git dyad: authoritative vulnerable:fixed pairs."""
    year, _, _ = _cve_parts(cve_id)
    if not year:
        return None
    url = "%s/plain/cve/published/%s/%s.dyad" % (VULNS_GIT, year, cve_id.upper())
    return _http_text(url, timeout=25)


def fetch_nvd(cve_id):
    key = os.environ.get("NVD_API_KEY")
    headers = {"apiKey": key} if key else None
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=%s" % cve_id
    data = _http_json(url, timeout=35, headers=headers)
    if not data or not data.get("vulnerabilities"):
        return None
    return data["vulnerabilities"][0].get("cve")


def fetch_epss(cve_id):
    data = _http_json("https://api.first.org/data/v1/epss?cve=%s" % cve_id,
                      timeout=20)
    if data and data.get("data"):
        return data["data"][0]
    return None


def fetch_kev(cve_id):
    raw = _cached("kev.json", 6 * 3600, lambda: _http(
        "https://www.cisa.gov/sites/default/files/feeds/"
        "known_exploited_vulnerabilities.json", timeout=40))
    if not raw:
        return None
    try:
        cat = json.loads(raw.decode("utf-8", "replace"))
    except Exception:  # noqa: BLE001
        return None
    for v in cat.get("vulnerabilities", []):
        if v.get("cveID", "").upper() == cve_id.upper():
            return v
    return None


def fetch_redhat(cve_id):
    """Red Hat Security Data API: per-CVE JSON (RHSA advisories, CVSS3, CWE,
    per-product fix state, mitigation). 404 for CVEs irrelevant to Red Hat
    products -- that's a normal, expected outcome, not an error."""
    return _http_json(REDHAT_CVE_API % cve_id, timeout=15)


def fetch_archlinux(cve_id):
    """Arch Linux Security Tracker: per-CVE JSON, chained to its AVG group
    (which carries the actual affected/fixed package version + status).
    Coverage is partial -- Arch only tracks CVEs affecting shipped packages,
    so 404 (no data) is common and expected."""
    rec = _http_json(ARCH_ITEM_API % cve_id, timeout=15)
    if not rec:
        return None
    for group in rec.get("groups") or []:
        info = _http_json(ARCH_ITEM_API % group, timeout=15)
        if info:
            rec["group_info"] = info
            break
    return rec


def fetch_osv(cve_id):
    """OSV.dev: mirrors the full cvelistV5 dataset keyed by plain CVE ID.
    Useful mainly for git-commit-level introduced/fixed ranges and the list
    of related distro advisory IDs (USN-/SUSE-SU-/ALSA- etc.)."""
    return _http_json(OSV_API % cve_id, timeout=15)


def fetch_linuxkernelcves(cve_id):
    """linuxkernelcves.com data (community-maintained, no accuracy guarantee):
    single ~6MB JSON dump keyed by CVE ID, cached locally with a TTL. Adds
    colloquial vuln names (e.g. "Dirty Pipe") and affected/last-vulnerable
    kernel version ranges."""
    raw = _cached("linux_kernel_cves.json", 24 * 3600,
                  lambda: _http(LKC_JSON, timeout=45))
    if not raw:
        return None
    try:
        data = json.loads(raw.decode("utf-8", "replace"))
    except Exception:  # noqa: BLE001
        return None
    return data.get(cve_id)


def fetch_debian_entry(cve_id):
    """Debian Security Tracker has no per-CVE endpoint -- only a single large
    JSON dump (~80MB uncompressed, requesting gzip cuts the transfer to
    ~12MB), cached locally with a TTL and looked up by source package."""
    raw = _cached("debian_tracker.json", 24 * 3600, lambda: _http(
        DEBIAN_TRACKER_JSON, timeout=60, headers={"Accept-Encoding": "gzip"}))
    if not raw:
        return None
    try:
        data = json.loads(raw.decode("utf-8", "replace"))
    except Exception:  # noqa: BLE001
        return None
    pkg_data = data.get("linux") or {}
    if cve_id in pkg_data:
        return {"package": "linux", "data": pkg_data[cve_id]}
    for pkg, cves in data.items():  # fallback for non-kernel CVEs
        if cve_id in cves:
            return {"package": pkg, "data": cves[cve_id]}
    return None


def fetch_exploitdb(cve_id):
    """Exploit-DB's internal search AJAX endpoint (undocumented, but reliably
    returns JSON with the X-Requested-With header). Returns None on fetch
    failure vs. [] on a confirmed zero-hit lookup -- callers should treat
    those differently."""
    data = _http_json(EXPLOITDB_SEARCH % cve_id, timeout=15,
                       headers={"X-Requested-With": "XMLHttpRequest"})
    if data is None:
        return None
    return data.get("data") or []


def _unfold_headers(text):
    """RFC-2822 unfolding: join continuation lines (leading whitespace) onto
    the previous line, so folded Subject:/From: headers parse whole."""
    out = []
    for line in text.split("\n"):
        if out and line[:1] in (" ", "\t") and not out[-1].startswith("@@"):
            out[-1] += " " + line.strip()
        else:
            out.append(line)
    return "\n".join(out)


def fetch_patch(commit):
    """Fetch a commit patch from git.kernel.org; parse headers + per-file hunks."""
    url = "%s/patch/?id=%s" % (KERNEL_GIT, commit)
    raw = _http_text(url, timeout=30)
    if not raw:
        return None
    # unfold only the mail-header region (before the first diff)
    split = raw.split("\ndiff --git", 1)
    header_region = _unfold_headers(split[0])
    text = header_region + ("\ndiff --git" + split[1] if len(split) == 2 else "")

    out = {
        "commit": commit, "raw_url": url,
        "web_url": "https://git.kernel.org/stable/c/%s" % commit,
        "author": None, "date": None, "subject": None, "body": None,
        "files": [], "functions": [], "insertions": 0, "deletions": 0,
    }
    m = re.search(r"^From:\s*(.+)$", header_region, re.MULTILINE)
    if m:
        out["author"] = m.group(1).strip()
    m = re.search(r"^Date:\s*(.+)$", header_region, re.MULTILINE)
    if m:
        out["date"] = m.group(1).strip()
    m = re.search(r"^Subject:\s*(?:\[[^\]]*\]\s*)?(.+)$", header_region,
                  re.MULTILINE)
    if m:
        out["subject"] = m.group(1).strip()
    parts = re.split(r"\n---\n", header_region, maxsplit=1)
    if len(parts) == 2:
        bm = re.split(r"\n\n", parts[0], maxsplit=1)
        if len(bm) == 2:
            out["body"] = bm[1].strip()

    out["files"] = re.findall(r"^diff --git a/(\S+) b/\S+", text, re.MULTILINE)
    dm = re.search(r"(\d+) insertion", text)
    if dm:
        out["insertions"] = int(dm.group(1))
    dm = re.search(r"(\d+) deletion", text)
    if dm:
        out["deletions"] = int(dm.group(1))

    # functions: walk per-file, only trust hunk context in compiled sources
    funcs = []
    cur_src = False
    for line in text.split("\n"):
        dg = re.match(r"^diff --git a/(\S+) b/", line)
        if dg:
            cur_src = dg.group(1).endswith((".c", ".S"))
            continue
        if cur_src and line.startswith("@@"):
            hm = re.match(r"^@@ [^@]*@@\s*(.+)$", line)
            if hm:
                fn = _func_from_context(hm.group(1))
                if fn:
                    funcs.append(fn)
    seen = set()
    out["functions"] = [f for f in funcs if not (f in seen or seen.add(f))]
    return out


def _func_from_context(ctx):
    """Extract a plausible function name from a hunk context string."""
    # last identifier immediately followed by '(' is usually the function
    for m in re.finditer(r"([A-Za-z_][A-Za-z0-9_]*)\s*\(", ctx):
        name = m.group(1)
        if NOT_A_FUNCTION.match(name):
            continue
        if name.isupper():  # macro, not a kernel function
            continue
        return name
    return None


def fetch_makefile_config(files):
    """Best-effort: derive module + CONFIG symbols across compiled source files."""
    modules, configs, makefiles = [], [], []
    for filepath in files:
        if not filepath.endswith((".c", ".S")):
            continue  # headers aren't compiled into a module
        info = _makefile_for(filepath)
        if info.get("module") and info["module"] not in modules:
            modules.append(info["module"])
        for c in info.get("config", []):
            if c not in configs:
                configs.append(c)
        if info.get("makefile") and info["makefile"] not in makefiles:
            makefiles.append(info["makefile"])
    return {"modules": modules, "config": configs, "makefiles": makefiles}


def _makefile_for(filepath):
    directory = os.path.dirname(filepath)
    base = os.path.basename(filepath)
    obj = re.sub(r"\.[cS]$", ".o", base)
    result = {"config": [], "module": None, "makefile": None}
    for mkdir in (directory, os.path.dirname(directory)):
        if not mkdir:
            continue
        mk = _http_text("%s/plain/%s/Makefile" % (KERNEL_GIT, mkdir), timeout=20)
        if not mk:
            continue
        mk = re.sub(r"\\\n", " ", mk)  # join line continuations
        result["makefile"] = "%s/Makefile" % mkdir
        subobj = os.path.relpath(filepath, mkdir).replace(".c", ".o")
        want = {obj, subobj}

        def _has(line):
            return any(t.strip() in want for t in re.split(r"\s+", line))

        for line in mk.splitlines():
            if _has(line):
                cm = re.search(r"\$\((CONFIG_[A-Z0-9_]+)\)", line)
                if cm:
                    result["config"].append(cm.group(1))
                mm = re.match(r"\s*([A-Za-z0-9_-]+?)-(?:y|objs|\$)", line)
                if mm and mm.group(1) != "obj":
                    result["module"] = mm.group(1)
        if result["module"]:
            cm = re.search(r"obj-\$\((CONFIG_[A-Z0-9_]+)\)\s*\+=\s*[^\n]*%s\.o"
                           % re.escape(result["module"]), mk)
            if cm and cm.group(1) not in result["config"]:
                result["config"].append(cm.group(1))
        if result["config"] or result["module"]:
            break
    seen = set()
    result["config"] = [c for c in result["config"]
                        if not (c in seen or seen.add(c))]
    return result


# --------------------------------------------------------------------------- #
# Small utils
# --------------------------------------------------------------------------- #

def _dig(obj, *keys, default=None):
    cur = obj
    for k in keys:
        if isinstance(cur, dict) and k in cur:
            cur = cur[k]
        else:
            return default
    return cur


def _sev_from_score(score):
    try:
        s = float(score)
    except (TypeError, ValueError):
        return None
    if s == 0:
        return "NONE"
    if s < 4:
        return "LOW"
    if s < 7:
        return "MEDIUM"
    if s < 9:
        return "HIGH"
    return "CRITICAL"


def _branch_of(release):
    """Stable branch label for a release, e.g. '6.6.24' -> '6.6.y'."""
    if not release:
        return None
    m = re.match(r"^(\d+\.\d+)", release)
    return "%s.y" % m.group(1) if m else None


def classify_cwe(text):
    low = (text or "").lower()
    for kw, cwe in CWE_KEYWORDS:
        if kw in low:
            return {"id": cwe[0], "name": cwe[1],
                    "source": "derived (keyword)", "derived": True}
    return None


# --------------------------------------------------------------------------- #
# Parsing
# --------------------------------------------------------------------------- #

def parse_dyad(text):
    if not text:
        return None
    mainline = None
    m = re.search(r"pairs for git id\s+([0-9a-f]{8,40})", text)
    if m:
        mainline = m.group(1)
    pairs = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        p = line.split(":")
        if len(p) != 4:
            continue
        pairs.append({"vuln_ver": p[0], "vuln_commit": p[1],
                      "fix_ver": p[2], "fix_commit": p[3]})
    if not pairs:
        return None
    return {"mainline_commit": mainline, "pairs": pairs}


def _ver_key(v):
    parts = re.findall(r"\d+", v or "")
    return tuple(int(x) for x in parts) if parts else (0,)


def versions_from_dyad(dyad):
    mainline_commit = dyad["mainline_commit"]
    fixes, unfixed, intro_versions = [], [], set()
    intro_mainline = None
    for p in dyad["pairs"]:
        if p["fix_ver"] in ("0", "") or p["fix_commit"] in ("0", ""):
            unfixed.append({"version": p["vuln_ver"], "commit": p["vuln_commit"],
                            "branch": _branch_of(p["vuln_ver"])})
            continue
        is_ml = bool(mainline_commit) and p["fix_commit"] == mainline_commit
        fixes.append({
            "commit": p["fix_commit"], "release": p["fix_ver"],
            "branch": "mainline" if is_ml else _branch_of(p["fix_ver"]),
            "is_mainline": is_ml,
            "intro_version": p["vuln_ver"], "intro_commit": p["vuln_commit"],
        })
        intro_versions.add(p["vuln_ver"])
        if is_ml:
            intro_mainline = {"version": p["vuln_ver"], "commit": p["vuln_commit"]}
    if not intro_mainline and fixes:
        lo = min(fixes, key=lambda f: _ver_key(f["intro_version"]))
        intro_mainline = {"version": lo["intro_version"],
                          "commit": lo["intro_commit"]}
    ml = next((f for f in fixes if f["is_mainline"]), None)
    fixes.sort(key=lambda f: (not f["is_mainline"], _ver_key(f["release"])),
               reverse=False)
    # keep mainline first, then descending stable versions
    fixes.sort(key=lambda f: (0,) if f["is_mainline"]
               else (1,) + tuple(-x for x in _ver_key(f["release"])))
    return {
        "source": "kernel vulns.git dyad",
        "intro_version": intro_mainline["version"] if intro_mainline else None,
        "intro_commits": [intro_mainline["commit"]] if intro_mainline else [],
        "intro_backported": sorted(
            [v for v in intro_versions
             if intro_mainline and v != intro_mainline["version"]],
            key=_ver_key),
        "mainline_version": ml["release"] if ml else None,
        "mainline_commit": mainline_commit,
        "fixes": fixes,
        "unfixed": unfixed,
    }


def versions_from_record(cna):
    """Fallback when no dyad exists (non-Linux-CNA CVEs). Extracts affected
    ranges and any fix commits from references, WITHOUT a fragile per-branch
    commit<->release zip."""
    ranges = []
    for aff in cna.get("affected", []) or []:
        for v in aff.get("versions", []) or []:
            vt = v.get("versionType")
            if vt in ("semver", "custom") or vt is None:
                lo = v.get("version")
                hi = v.get("lessThan") or v.get("lessThanOrEqual")
                if (v.get("status") == "affected" and lo
                        and lo.lower() not in ("n/a", "unspecified", "unknown")):
                    ranges.append({"start": lo, "end": hi,
                                   "end_incl": bool(v.get("lessThanOrEqual"))})
    return {
        "source": "cvelistV5 record (no dyad)",
        "intro_version": None, "intro_commits": [], "intro_backported": [],
        "mainline_version": None, "mainline_commit": None,
        "fixes": [], "unfixed": [], "affected_ranges": ranges,
    }


def parse_cvss(cvelist, nvd):
    out = []

    def grab(metrics, source):
        for m in metrics or []:
            for k in ("cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0"):
                if k in m:
                    c = m[k]
                    out.append({"version": c.get("version"),
                                "vector": c.get("vectorString"),
                                "score": c.get("baseScore"),
                                "severity": c.get("baseSeverity")
                                or _sev_from_score(c.get("baseScore")),
                                "source": source})

    grab(_dig(cvelist, "containers", "cna", "metrics"),
         "CNA (%s)" % _dig(cvelist, "cveMetadata", "assignerShortName",
                           default="CNA"))
    for adp in _dig(cvelist, "containers", "adp", default=[]) or []:
        grab(adp.get("metrics"),
             "ADP (%s)" % _dig(adp, "providerMetadata", "shortName",
                               default="ADP"))
    if nvd:
        for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30",
                    "cvssMetricV2"):
            for e in nvd.get("metrics", {}).get(key, []):
                c = e.get("cvssData", {})
                out.append({"version": c.get("version"),
                            "vector": c.get("vectorString"),
                            "score": c.get("baseScore"),
                            "severity": c.get("baseSeverity")
                            or _sev_from_score(c.get("baseScore")),
                            "source": "NVD (%s)" % e.get("source", "")})
    seen, uniq = set(), []
    for m in out:
        k = (m["version"], m["vector"])
        if k not in seen:
            seen.add(k)
            uniq.append(m)
    return uniq


def parse_cwe(cvelist, nvd, title, desc):
    def from_problemtypes(container, source):
        for pt in container.get("problemTypes", []) or []:
            for d in pt.get("descriptions", []) or []:
                cid = d.get("cweId") or (d.get("description") if
                      str(d.get("description", "")).startswith("CWE-") else None)
                if cid and str(cid).startswith("CWE-"):
                    name = d.get("description")
                    if name and name.startswith("CWE-"):
                        name = name.split(" ", 1)[1] if " " in name else None
                    return {"id": cid, "name": name, "source": source,
                            "derived": False}
        return None

    cna = _dig(cvelist, "containers", "cna", default={}) or {}
    c = from_problemtypes(cna, "CNA")
    if c:
        return c
    if nvd:
        for w in nvd.get("weaknesses", []) or []:
            for d in w.get("description", []) or []:
                if d.get("value", "").startswith("CWE-"):
                    return {"id": d["value"], "name": None, "source": "NVD",
                            "derived": False}
    for adp in _dig(cvelist, "containers", "adp", default=[]) or []:
        c = from_problemtypes(adp, "CISA-ADP")
        if c:
            return c
    return classify_cwe(title + " " + desc)


def parse_ssvc(cvelist):
    for adp in _dig(cvelist, "containers", "adp", default=[]) or []:
        for m in adp.get("metrics", []) or []:
            other = m.get("other", {})
            if other.get("type") == "ssvc":
                content = other.get("content", {})
                opts = {}
                for o in content.get("options", []):
                    opts.update(o)
                return {"role": content.get("role"),
                        "exploitation": opts.get("Exploitation"),
                        "automatable": opts.get("Automatable"),
                        "technical_impact": opts.get("Technical Impact"),
                        "source": _dig(adp, "providerMetadata", "shortName",
                                       default="ADP")}
    return None


def summarize_redhat(rh):
    if not isinstance(rh, dict):
        return None
    advisories, seen = [], set()
    for rel in rh.get("affected_release", []) or []:
        adv = rel.get("advisory")
        if adv and adv not in seen:
            seen.add(adv)
            advisories.append({"id": adv, "product": rel.get("product_name")})
    return {
        "severity": rh.get("threat_severity"),
        "cvss3_score": _dig(rh, "cvss3", "cvss3_base_score"),
        "cvss3_vector": _dig(rh, "cvss3", "cvss3_scoring_vector"),
        "cwe": rh.get("cwe"),
        "advisories": advisories,
        "mitigation": _dig(rh, "mitigation", "value"),
        "link": REDHAT_CVE_PAGE % rh.get("name", ""),
    }


def summarize_debian(entry, cve_id):
    if not entry:
        return None
    d = entry["data"]
    releases = []
    for suite, info in (d.get("releases") or {}).items():
        releases.append({"suite": suite, "status": info.get("status"),
                         "fixed_version": info.get("fixed_version"),
                         "urgency": info.get("urgency")})
    releases.sort(key=lambda r: r["suite"])
    return {"package": entry["package"], "scope": d.get("scope"),
            "releases": releases, "link": DEBIAN_CVE_PAGE % cve_id}


def summarize_archlinux(rec, cve_id):
    if not rec:
        return None
    group = rec.get("group_info") or {}
    return {"severity": rec.get("severity"), "type": rec.get("type"),
            "status": group.get("status"), "affected": group.get("affected"),
            "fixed": group.get("fixed"),
            "advisories": rec.get("advisories") or [],
            "link": ARCH_CVE_PAGE % cve_id}


def summarize_osv(osv):
    if not osv:
        return None
    score = None
    for s in osv.get("severity") or []:
        if str(s.get("type", "")).upper().startswith("CVSS"):
            score = s.get("score")
            break
    return {"related": osv.get("related") or [], "cvss_vector": score,
            "link": OSV_PAGE % osv.get("id", "")}


def summarize_exploitdb(rows):
    if rows is None:
        return None
    out = []
    for row in rows or []:
        desc = row.get("description") or [None, None]
        out.append({
            "edb_id": row.get("id"),
            "title": desc[1] if len(desc) > 1 else None,
            "date": row.get("date_published"),
            "type": _dig(row, "type", "display"),
            "verified": bool(row.get("verified")),
            "link": EXPLOITDB_EXPLOIT_PAGE % row.get("id", ""),
        })
    return out


def parse_cpe_ranges(cvelist):
    ranges = []
    containers = [_dig(cvelist, "containers", "cna", default={}) or {}]
    containers += _dig(cvelist, "containers", "adp", default=[]) or []
    for cont in containers:
        for app in cont.get("cpeApplicability", []) or []:
            for node in app.get("nodes", []) or []:
                for cm in node.get("cpeMatch", []) or []:
                    if not cm.get("vulnerable"):
                        continue
                    ranges.append({
                        "start": cm.get("versionStartIncluding")
                        or cm.get("versionStartExcluding"),
                        "start_incl": "versionStartIncluding" in cm,
                        "end": cm.get("versionEndExcluding")
                        or cm.get("versionEndIncluding"),
                        "end_incl": "versionEndIncluding" in cm})
    # de-dup
    seen, uniq = set(), []
    for r in ranges:
        k = (r["start"], r["end"])
        if k not in seen:
            seen.add(k)
            uniq.append(r)
    return uniq


def categorize_refs(urls):
    cats = {"commits": [], "cve_records": [], "discussion": [],
            "advisories": [], "other": []}
    for u in urls:
        low = u.lower()
        if ("git.kernel.org" in low or "savannah.gnu.org" in low
                or "/commit/" in low or "/patch/" in low
                or "github.com" in low and "/commit/" in low):
            cats["commits"].append(u)
        elif ("nvd.nist.gov" in low or "cve.org" in low
              or "cve.mitre.org" in low or "cvelistv5" in low):
            cats["cve_records"].append(u)
        elif ("openwall.com" in low or "lore.kernel.org" in low
              or "marc.info" in low or "seclists.org" in low):
            cats["discussion"].append(u)
        elif ("access.redhat.com" in low or "ubuntu.com" in low
              or "debian.org" in low or "suse.com" in low
              or "security.archlinux" in low or "advisory" in low
              or "bugzilla" in low):
            cats["advisories"].append(u)
        else:
            cats["other"].append(u)
    return cats


def derive_subsystem(title, files):
    if title and ":" in title:
        parts = []
        for p in title.split(":")[:-1]:
            p = p.strip()
            if 0 < len(p) <= 25:
                parts.append(p)
            else:
                break
        if parts:
            return ": ".join(parts)
    if files:
        return os.path.dirname(files[0])
    return None


def _title_from_desc(desc):
    m = re.search(r"resolved:\s*\n+\s*(.+)", desc or "")
    if m:
        return m.group(1).strip()
    return (desc.split("\n")[0][:120] if desc else "(no title)")


# --------------------------------------------------------------------------- #
# Build record
# --------------------------------------------------------------------------- #

def build_record(cve_id, fetch_diffs=True, fetch_vendor=True):
    cve_id = cve_id.upper()
    sys.stderr.write("[*] %s: fetching cvelistV5 record ...\n" % cve_id)
    cvelist = fetch_cvelist(cve_id)
    if not cvelist:
        raise SystemExit(
            "ERROR: could not fetch a record for %s.\n"
            "       Check the ID, or it may not be published yet.\n"
            "       Tried: %s and cveawg API" % (cve_id, cvelist_url(cve_id)))
    cna = _dig(cvelist, "containers", "cna", default={}) or {}
    assigner = _dig(cvelist, "cveMetadata", "assignerShortName", default="") or ""
    is_kernel = assigner.lower() == "linux"

    sys.stderr.write("[*] fetching dyad / NVD / EPSS / KEV ...\n")
    dyad_txt = fetch_dyad(cve_id) if is_kernel else None
    nvd = fetch_nvd(cve_id)
    epss = fetch_epss(cve_id)
    kev = fetch_kev(cve_id)

    redhat = archlinux = osv = exploitdb = debian = lkc = None
    if fetch_vendor:
        sys.stderr.write("[*] fetching Red Hat / Arch / OSV / Exploit-DB ...\n")
        redhat = summarize_redhat(fetch_redhat(cve_id))
        archlinux = summarize_archlinux(fetch_archlinux(cve_id), cve_id)
        osv = summarize_osv(fetch_osv(cve_id))
        exploitdb = summarize_exploitdb(fetch_exploitdb(cve_id))
        if is_kernel:
            sys.stderr.write(
                "[*] fetching Debian tracker / linuxkernelcves.com "
                "(cached, first run may be slow) ...\n")
            debian = summarize_debian(fetch_debian_entry(cve_id), cve_id)
            lkc = fetch_linuxkernelcves(cve_id)

    desc = ""
    for d in cna.get("descriptions", []) or []:
        if d.get("lang", "en").startswith("en"):
            desc = d.get("value", "")
            break
    title = cna.get("title") or _title_from_desc(desc)

    files, routines, repos, vendor, product = [], [], [], None, None
    for aff in cna.get("affected", []) or []:
        vendor = vendor or aff.get("vendor")
        product = product or aff.get("product")
        for f in aff.get("programFiles", []) or []:
            if f not in files:
                files.append(f)
        for r in aff.get("programRoutines", []) or []:
            name = r.get("name") if isinstance(r, dict) else r
            if name and name not in routines:
                routines.append(name)
        if aff.get("repo") and aff["repo"] not in repos:
            repos.append(aff["repo"])

    dyad = parse_dyad(dyad_txt)
    versions = versions_from_dyad(dyad) if dyad else versions_from_record(cna)

    cvss = parse_cvss(cvelist, nvd)
    cwe = parse_cwe(cvelist, nvd, title, desc)
    ssvc = parse_ssvc(cvelist)
    cpe = parse_cpe_ranges(cvelist)

    # references
    ref_urls = []
    for r in cna.get("references", []) or []:
        if r.get("url"):
            ref_urls.append(r["url"])
    for adp in _dig(cvelist, "containers", "adp", default=[]) or []:
        for r in adp.get("references", []) or []:
            if r.get("url") and r["url"] not in ref_urls:
                ref_urls.append(r["url"])
    if nvd:
        for r in nvd.get("references", []) or []:
            if r.get("url") and r["url"] not in ref_urls:
                ref_urls.append(r["url"])
    for c in ("https://www.cve.org/CVERecord?id=%s" % cve_id,
              "https://nvd.nist.gov/vuln/detail/%s" % cve_id,
              cvelist_blob_url(cve_id)):
        if c and c not in ref_urls:
            ref_urls.append(c)
    refs = categorize_refs(ref_urls)

    # patches: mainline fix + mainline intro + every stable fix (for dates)
    patches = {}
    if fetch_diffs and is_kernel:
        want = set(versions.get("intro_commits", []))
        for fx in versions.get("fixes", []):
            if fx.get("commit"):
                want.add(fx["commit"])
        want = {c for c in want if c and re.match(r"^[0-9a-f]{8,40}$", c)}
        if want:
            sys.stderr.write("[*] fetching %d commit patch(es) ...\n" % len(want))
        for c in want:
            p = fetch_patch(c)
            if p:
                patches[c] = p

    # functions: CNA routines, else derived from mainline fix patch
    functions_derived = False
    if not routines:
        ml_commit = versions.get("mainline_commit")
        if ml_commit and ml_commit in patches and patches[ml_commit]["functions"]:
            routines = patches[ml_commit]["functions"]
            functions_derived = True
        else:
            for c, p in patches.items():
                if p.get("functions"):
                    routines = p["functions"]
                    functions_derived = True
                    break

    # module / CONFIG from all compiled source files
    modinfo = {"modules": [], "config": [], "makefiles": []}
    if files and is_kernel:
        sys.stderr.write("[*] deriving module / CONFIG ...\n")
        modinfo = fetch_makefile_config(files)

    sources = ["CVEProject/cvelistV5"]
    if dyad:
        sources.append("kernel vulns.git (dyad)")
    if nvd:
        sources.append("NVD 2.0 API")
    if epss:
        sources.append("FIRST EPSS")
    sources.append("CISA KEV" if kev else "CISA KEV (not listed)")
    if patches:
        sources.append("git.kernel.org (commits)")
    if redhat:
        sources.append("Red Hat Security Data API")
    if archlinux:
        sources.append("Arch Linux Security Tracker")
    if osv:
        sources.append("OSV.dev")
    if exploitdb is not None:
        sources.append("Exploit-DB")
    if debian:
        sources.append("Debian Security Tracker")
    if lkc:
        sources.append("linuxkernelcves.com")

    return {
        "cve_id": cve_id, "title": title, "assigner": assigner,
        "is_kernel": is_kernel, "vendor": vendor, "product": product,
        "state": _dig(cvelist, "cveMetadata", "state"),
        "published": _dig(cvelist, "cveMetadata", "datePublished"),
        "updated": _dig(cvelist, "cveMetadata", "dateUpdated"),
        "generator": _dig(cna, "x_generator", "engine"),
        "description": desc, "subsystem": derive_subsystem(title, files),
        "files": files, "functions": routines,
        "functions_derived": functions_derived,
        "modules": modinfo["modules"], "config": modinfo["config"],
        "makefiles": modinfo["makefiles"], "repos": repos,
        "cvss": cvss, "cwe": cwe, "epss": epss, "kev": kev, "ssvc": ssvc,
        "versions": versions, "cpe_ranges": cpe,
        "references": refs, "patches": patches, "sources_used": sources,
        "nvd_status": nvd.get("vulnStatus") if nvd else "Not in NVD",
        "redhat": redhat, "archlinux": archlinux, "osv": osv,
        "exploitdb": exploitdb, "debian": debian, "lkc": lkc,
        "ubuntu_link": UBUNTU_CVE_PAGE % cve_id if fetch_vendor else None,
        "suse_link": SUSE_CVE_PAGE % cve_id if fetch_vendor else None,
        "generated_at": datetime.now(timezone.utc).strftime(
            "%Y-%m-%d %H:%M:%S UTC"),
    }


# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #

def _fmt_date(iso):
    if not iso:
        return "unknown"
    try:
        return datetime.fromisoformat(iso.replace("Z", "+00:00")).strftime(
            "%Y-%m-%d")
    except Exception:  # noqa: BLE001
        return iso[:10]


def _short(c):
    return c[:12] if c else "?"


def render_markdown(r):
    L = []
    a = L.append
    v = r["versions"]

    a("# %s — %s" % (r["cve_id"], r["title"]))
    a("")
    a("> Auto-generated %s · sources: %s" %
      (r["generated_at"], ", ".join(r["sources_used"])))
    a("")

    # 1. at a glance
    a("## 1. At a glance")
    a("")
    a("| Field | Value |")
    a("|---|---|")
    a("| CVE | `%s` |" % r["cve_id"])
    a("| Assigner (CNA) | %s |" % (r["assigner"] or "—"))
    a("| State | %s |" % (r["state"] or "—"))
    a("| Published | %s |" % _fmt_date(r["published"]))
    a("| Last updated | %s |" % _fmt_date(r["updated"]))
    if r["cvss"]:
        t = r["cvss"][0]
        a("| CVSS | **%s %s** (v%s) — `%s` — _%s_ |" % (
            t.get("score"), t.get("severity"), t.get("version"),
            t.get("vector"), t.get("source")))
        for extra in r["cvss"][1:]:
            if extra.get("vector") != t.get("vector"):
                a("| CVSS (alt) | %s %s (v%s) — _%s_ |" % (
                    extra.get("score"), extra.get("severity"),
                    extra.get("version"), extra.get("source")))
    else:
        a("| CVSS | not scored |")
    if r["cwe"]:
        a("| Weakness | %s%s (%s) |" % (
            r["cwe"]["id"],
            (" — %s" % r["cwe"]["name"]) if r["cwe"].get("name") else "",
            r["cwe"]["source"]))
    if r["epss"]:
        a("| EPSS | %.2f%% (%.1fth percentile) |" % (
            float(r["epss"]["epss"]) * 100, float(r["epss"]["percentile"]) * 100))
    a("| CISA KEV | %s |" % (
        "⚠️ **LISTED — known exploited**" if r["kev"] else "not listed"))
    if r["ssvc"]:
        a("| CISA SSVC | Exploitation=**%s**, Automatable=%s, Tech-impact=%s |" % (
            r["ssvc"].get("exploitation"), r["ssvc"].get("automatable"),
            r["ssvc"].get("technical_impact")))
    a("| NVD status | %s |" % r["nvd_status"])
    if r.get("lkc") and r["lkc"].get("name"):
        a("| Known as | **%s** |" % r["lkc"]["name"])
    edb = r.get("exploitdb")
    if edb:
        top = edb[0]
        a("| Public exploit | ⚠️ **[Exploit-DB EDB-ID %s](%s)**%s |" % (
            top["edb_id"], top["link"],
            (" — %s" % top["title"]) if top.get("title") else ""))
    elif edb is not None:
        a("| Public exploit | not listed on Exploit-DB |")
    a("")

    # 2. affected component
    a("## 2. Affected component")
    a("")
    prod_bits = [x for x in (r["vendor"], r["product"])
                 if x and x.lower() not in ("n/a", "unknown")]
    # collapse "Linux Linux" -> "Linux"
    if len(prod_bits) == 2 and prod_bits[0] == prod_bits[1]:
        prod_bits = prod_bits[:1]
    if prod_bits:
        a("- **Product:** %s" % " ".join(prod_bits))
    if r["subsystem"]:
        a("- **Subsystem:** %s" % r["subsystem"])
    if r["modules"]:
        a("- **Module(s):** %s" % ", ".join("`%s.ko`" % m for m in r["modules"]))
    if r["files"]:
        a("- **File(s) changed:**")
        for f in r["files"]:
            a("  - `%s`" % f)
        dirs = []
        for f in r["files"]:
            d = os.path.dirname(f)
            if d and d not in dirs:
                dirs.append(d)
        a("- **Source path(s):** %s" % ", ".join("`%s/`" % d for d in dirs))
    if r["functions"]:
        note = " _(derived from diff — approximate)_" if r["functions_derived"] \
            else ""
        a("- **Function(s) changed:** %s%s" % (
            ", ".join("`%s()`" % fn for fn in r["functions"]), note))
    if r["config"]:
        src = (" _(derived from %s)_" % r["makefiles"][0]) if r["makefiles"] \
            else ""
        a("- **Kernel config:** %s%s" % (
            ", ".join("`%s`" % c for c in r["config"]), src))
    if r["repos"]:
        a("- **Source repo:** %s" % r["repos"][0])
    a("")

    # 3. affected & fixed versions
    a("## 3. Affected & fixed versions")
    a("")
    if v.get("intro_version") or v.get("intro_commits"):
        c = v["intro_commits"][0] if v.get("intro_commits") else None
        p = r["patches"].get(c) if c else None
        dt = (" — %s" % p["date"]) if p and p.get("date") else ""
        a("**Introduced:** %s%s%s" % (
            v.get("intro_version") or "?",
            (" (commit `%s`)" % _short(c)) if c else "", dt))
        if c:
            a("- https://git.kernel.org/stable/c/%s" % c)
        if v.get("intro_backported"):
            a("- Also present in stable branches from: %s (backported)" %
              ", ".join(v["intro_backported"]))
        a("")
    if v.get("fixes"):
        a("**Fixed in (per branch):**")
        a("")
        a("| Branch | Fixed release | Commit | Date |")
        a("|---|---|---|---|")
        for fx in v["fixes"]:
            p = r["patches"].get(fx["commit"], {}) if r["patches"] else {}
            date = _fmt_date_hdr(p.get("date")) if p else ""
            tag = " **(mainline)**" if fx.get("is_mainline") else ""
            a("| %s%s | %s | [`%s`](https://git.kernel.org/stable/c/%s) | %s |"
              % (fx.get("branch") or "?", tag, fx.get("release") or "?",
                 _short(fx["commit"]), fx["commit"], date or ""))
        a("")
    if v.get("unfixed"):
        a("**Affected but NOT fixed (EOL branches):** %s" %
          ", ".join(u["version"] for u in v["unfixed"]))
        a("")
    if v.get("affected_ranges"):
        a("**Affected version range(s):**")
        for rg in v["affected_ranges"]:
            a("- `%s` → %s%s" % (rg["start"], rg.get("end") or "onward",
              " (incl)" if rg.get("end_incl") else ""))
        a("")
    if r["cpe_ranges"]:
        a("**Vulnerable version ranges (CPE):**")
        for cr in r["cpe_ranges"]:
            a("- `%s` %s → %s %s" % (
                cr["start"] or "0", "(incl)" if cr["start_incl"] else "(excl)",
                cr["end"] or "*", "(incl)" if cr["end_incl"] else "(excl)"))
        a("")

    # 4. vulnerability details
    a("## 4. Vulnerability details")
    a("")
    if r["cwe"]:
        a("**Class:** %s%s" % (
            r["cwe"]["id"],
            (" — %s" % r["cwe"]["name"]) if r["cwe"].get("name") else ""))
        a("")
    a("**Upstream description:**")
    a("")
    for line in (r["description"] or "(none)").splitlines():
        a("> %s" % line if line.strip() else ">")
    a("")

    # 5. the fix
    a("## 5. The fix")
    a("")
    ml = next((f for f in v.get("fixes", []) if f.get("is_mainline")), None)
    if ml:
        p = r["patches"].get(ml["commit"], {}) if r["patches"] else {}
        a("- **Mainline commit:** `%s` (fixed in %s)" % (
            ml["commit"], ml.get("release") or "?"))
        if p.get("subject"):
            a("- **Subject:** %s" % p["subject"])
        if p.get("author"):
            a("- **Author:** %s" % p["author"])
        if p.get("date"):
            a("- **Date:** %s" % p["date"])
        a("- **Diffstat:** +%s / -%s across %s file(s)" % (
            p.get("insertions", 0), p.get("deletions", 0),
            len(p.get("files", []) or r["files"])))
        a("- **Patch:** %s" % p.get("web_url",
          "https://git.kernel.org/stable/c/%s" % ml["commit"]))
    else:
        # non-dyad: surface fix commits from references if any
        commits = [u for u in r["references"]["commits"]]
        if commits:
            a("Fix commit(s) referenced in the record:")
            for u in commits:
                a("- %s" % u)
        else:
            a("_No fix commit identified in the available data._")
    a("")

    # 6. mitigations
    a("## 6. Mitigations & detection")
    a("")
    if v.get("fixes"):
        a("- **Primary:** update to a fixed release for your branch "
          "(see the table in section 3).")
    elif v.get("mainline_version"):
        a("- **Primary:** upgrade past the fix (%s)." % v["mainline_version"])
    else:
        a("- **Primary:** apply the vendor fix / upgrade to a patched version.")
    if v.get("unfixed"):
        a("- ⚠️ Branches %s are EOL and will not receive a fix — migrate off them."
          % ", ".join(u["version"] for u in v["unfixed"]))
    if r["ssvc"] and r["ssvc"].get("exploitation") not in (None, "none"):
        a("- Exploitation status per CISA: **%s** — prioritize accordingly."
          % r["ssvc"]["exploitation"])
    if r["kev"]:
        kd = r["kev"].get("dueDate")
        a("- ⚠️ Listed in **CISA KEV** — patch urgently%s." % (
            " (federal due date %s)" % kd if kd else ""))
    a("- If patching is not immediately possible, review the trigger conditions "
      "in section 4 for a workload-specific mitigation.")
    a("")

    # 7. references
    a("## 7. References")
    a("")
    for key, label in (("commits", "Fix commits"),
                       ("cve_records", "CVE / NVD records"),
                       ("discussion", "Discussion & disclosure"),
                       ("advisories", "Vendor / distro advisories"),
                       ("other", "Other")):
        urls = r["references"].get(key) or []
        if urls:
            a("**%s**" % label)
            for u in urls:
                a("- %s" % u)
            a("")

    # 8. vendor / distro cross-references
    rh, arch, deb, osv = r.get("redhat"), r.get("archlinux"), \
        r.get("debian"), r.get("osv")
    lkc = r.get("lkc")
    if any((rh, arch, deb, osv, r.get("ubuntu_link"), r.get("suse_link"))):
        a("## 8. Vendor & distro cross-references")
        a("")
        a("| Tracker | Status | Notes | Link |")
        a("|---|---|---|---|")
        if rh:
            advs = ", ".join("[%s](https://access.redhat.com/errata/%s)"
                             % (x["id"], x["id"]) for x in rh["advisories"][:3])
            more = " (+%d more)" % (len(rh["advisories"]) - 3) \
                if len(rh["advisories"]) > 3 else ""
            a("| Red Hat | %s%s | %s%s | %s |" % (
                rh.get("severity") or "—",
                (" (CVSS3 %s)" % rh["cvss3_score"]) if rh.get("cvss3_score")
                else "",
                advs or "no RHSA advisory on file", more, rh["link"]))
        else:
            a("| Red Hat | not tracked | — | %s |" % (REDHAT_CVE_PAGE % r["cve_id"]))
        if deb:
            resolved = [x for x in deb["releases"] if x["status"] == "resolved"]
            open_ = [x for x in deb["releases"] if x["status"] != "resolved"]
            bits = []
            if resolved:
                bits.append("fixed: %s" % ", ".join(
                    "%s (%s)" % (x["suite"], x["fixed_version"] or "?")
                    for x in resolved))
            if open_:
                bits.append("open: %s" % ", ".join(x["suite"] for x in open_))
            a("| Debian | %s package | %s | %s |" % (
                deb["package"], "; ".join(bits) or "no per-suite data",
                deb["link"]))
        elif r["is_kernel"]:
            a("| Debian | not tracked | — | %s |" % (DEBIAN_CVE_PAGE % r["cve_id"]))
        else:
            a("| Debian | — | not queried (non-kernel CVE) | %s |"
              % (DEBIAN_CVE_PAGE % r["cve_id"]))
        a("| Ubuntu | — | not queried live (no reliable per-CVE API) | %s |"
          % (r.get("ubuntu_link") or "—"))
        a("| SUSE | — | not queried live (no public API, HTML only) | %s |"
          % (r.get("suse_link") or "—"))
        if arch:
            status = arch.get("status") or ("tracked" if arch.get("severity")
                                            else "—")
            fix = (" — fixed %s" % arch["fixed"]) if arch.get("fixed") else ""
            a("| Arch Linux | %s%s | severity: %s | %s |" % (
                status, fix, arch.get("severity") or "—", arch["link"]))
        else:
            a("| Arch Linux | not tracked | — | — |")
        if osv:
            rel = ", ".join(osv["related"][:5]) if osv["related"] else \
                "no related advisories listed"
            a("| OSV.dev | tracked | %s | %s |" % (rel, osv["link"]))
        else:
            a("| OSV.dev | not tracked | — | %s |" % (OSV_PAGE % r["cve_id"]))
        a("")
        if lkc:
            bits = []
            if lkc.get("affected_versions"):
                bits.append("affected %s" % lkc["affected_versions"])
            if lkc.get("last_affected_version"):
                bits.append("last known-vulnerable release %s" %
                            lkc["last_affected_version"])
            if bits:
                a("_Community cross-check (linuxkernelcves.com, "
                  "no accuracy guarantee):_ %s." % "; ".join(bits))
                a("")
        if rh and rh.get("mitigation"):
            a("**Red Hat mitigation notes:**")
            a("")
            a("> %s" % rh["mitigation"].replace("\n", "\n> "))
            a("")

    # 9. provenance
    a("## 9. Provenance")
    a("")
    a("- Data sources: %s" % ", ".join(r["sources_used"]))
    a("- Version mapping: %s" % v.get("source", "—"))
    if r["generator"]:
        a("- CVE record generated by: `%s`" % r["generator"])
    a("- Report generated: %s" % r["generated_at"])
    a("")
    return "\n".join(L)


def _fmt_date_hdr(hdr):
    """Format a git 'Date:' mail header (e.g. 'Fri, 12 Jun 2026 22:18:12 +0200')
    to YYYY-MM-DD."""
    if not hdr:
        return ""
    for fmt in ("%a, %d %b %Y %H:%M:%S %z", "%a %b %d %H:%M:%S %Y %z"):
        try:
            return datetime.strptime(hdr, fmt).strftime("%Y-%m-%d")
        except ValueError:
            continue
    return hdr


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #

def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Generate a detailed Linux-kernel CVE report.")
    ap.add_argument("cve", help="CVE ID, e.g. CVE-2026-53359")
    ap.add_argument("-o", "--output", help="output file (default <CVE>_report.md)")
    ap.add_argument("--stdout", action="store_true",
                    help="print report to stdout, write nothing")
    ap.add_argument("--json", action="store_true",
                    help="also write the data pack as <CVE>_data.json")
    ap.add_argument("--json-only", action="store_true",
                    help="print only the JSON data pack to stdout")
    ap.add_argument("--no-diff", action="store_true",
                    help="skip fetching commit patches (faster, less detail)")
    ap.add_argument("--no-vendor", action="store_true",
                    help="skip Red Hat/Debian/Arch/OSV/Exploit-DB lookups "
                         "(faster, less detail)")
    args = ap.parse_args(argv)

    cve = args.cve.strip().upper()
    if not CVE_RE.match(cve):
        ap.error("invalid CVE id: %s (expected CVE-YYYY-NNNNN)" % args.cve)

    record = build_record(cve, fetch_diffs=not args.no_diff,
                          fetch_vendor=not args.no_vendor)

    if args.json_only:
        sys.stdout.write(json.dumps(record, indent=2, ensure_ascii=False) + "\n")
        return 0

    md = render_markdown(record)
    if args.stdout:
        sys.stdout.write(md + "\n")
    else:
        out = args.output or ("%s_report.md" % cve)
        with open(out, "w", encoding="utf-8") as fh:
            fh.write(md + "\n")
        sys.stderr.write("[+] report written: %s\n" % out)

    if args.json:
        with open("%s_data.json" % cve, "w", encoding="utf-8") as fh:
            json.dump(record, fh, indent=2, ensure_ascii=False)
        sys.stderr.write("[+] data pack written: %s_data.json\n" % cve)
    return 0


if __name__ == "__main__":
    sys.exit(main())
