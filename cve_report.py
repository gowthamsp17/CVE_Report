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
  * Feedly.dev CVE pages      (cross-outlet media coverage aggregator)
  * thehackerwire.com         (per-CVE tracker page, embedded structured data)
  * thehackernews.com         (full-archive search, Blogger feed API)
  * cybersecuritynews.com     (WordPress REST API search)
  * securityonline.info       (WordPress REST API search)
  * Qualys blog / BleepingComputer (reference links only -- both block/lock
                                     out no-auth automated lookups)

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
    python3 cve_report.py CVE-2026-53359 --no-media        # skip media/community lookups

No third-party dependencies (stdlib only). Set NVD_API_KEY to raise NVD limits.

Report writing is delegated to a local zLLM proxy (OpenAI-compatible;
see `zllm start`). Configure with:
    ZLLM_BASE_URL   default http://127.0.0.1:8787/v1
    ZLLM_API_KEY    default "unused" (proxy ignores it unless --api-key was set)
    ZLLM_MODEL      default gpt-5.4
"""

from __future__ import annotations

import argparse
import gzip
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
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

# local Linux source tree + .config files, used to resolve per-branch module
# info (via find_module_new.py) and, when a commit is present locally, to
# read patch/commit details from `git show` instead of git.kernel.org.
LINUX_SRC_DEFAULT = os.path.expanduser("~/Linux_Stable/linux")
CONFIGS_DIR_DEFAULT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "configs")
MODULE_RESOLVE_BRANCHES = ["linux-5.10.y", "linux-6.1.y", "linux-6.12.y"]

# fleet module-usage reporting script (internal tool, not part of this repo):
# given a kernel module name, reports how widely it's loaded across the
# fleet (per-region IP counts, ZServices, server types, kernel versions).
MODULE_STATS_SCRIPT_DEFAULT = os.path.expanduser(
    "~/Server-Modules/Scripts/module_stats.py")

# local zLLM proxy (OpenAI-compatible; run `zllm start` beforehand)
ZLLM_BASE_URL = os.environ.get("ZLLM_BASE_URL", "http://127.0.0.1:8787/v1")
ZLLM_API_KEY = os.environ.get("ZLLM_API_KEY", "unused")
ZLLM_MODEL = os.environ.get("ZLLM_MODEL", "gpt-5.4")
ZLLM_REPORT_SYSTEM_PROMPT = (
    "You are a senior Linux kernel security analyst. You write detailed, "
    "precise CVE reports in Markdown for a technical security audience. "
    "You are given a JSON data pack collected from authoritative sources "
    "(cvelistV5, kernel vulns.git, NVD, EPSS, CISA KEV, git.kernel.org, "
    "Debian, Exploit-DB, and media coverage). "
    "Use ONLY the facts present in that JSON -- never invent CVE numbers, "
    "commits, versions, scores, or links that are not in the data. If a "
    "field is missing or null, say so plainly instead of guessing. "
    "Write clean, well-structured Markdown with headings, tables, and "
    "bullet lists as appropriate; do not wrap the whole answer in a code "
    "fence. The output must read as a formal, official vulnerability "
    "report/advisory: NEVER mention the JSON, the 'data pack', field or key "
    "names (e.g. 'cwe.ids', 'module_by_branch', 'functions_derived'), or "
    "that the text was generated from supplied data. Where information is "
    "missing, write 'Not available' or 'Not yet assessed' in the "
    "appropriate place instead of explaining what the data lacks."
)
ZLLM_REPORT_USER_TEMPLATE = (
    "Write a complete, detailed CVE report in Markdown for %s using only "
    "the JSON data pack below. Structure it with these sections in order: "
    "1. At a glance (key facts table: CVSS, CWE (list ALL ids in the JSON 'cwe.ids' list, comma-separated; always state its 'source' field from the JSON, e.g. CNA / NVD / CISA-ADP / derived (keyword), in the same cell), EPSS, CISA KEV/SSVC, NVD "
    "status, CVE Published date and CVE Last Updated date (from the JSON 'published' and 'updated' fields, formatted as YYYY-MM-DD HH:MM UTC), public exploit availability), 2. Affected component (product, "
    "subsystem, module, files, functions, kernel config; if the JSON has a "
    "'module_by_branch' field, include a per-branch/per-config module "
    "resolution table with columns Branch | File | CONFIG_ symbol "
    "| Result (no Config column; configs of the same branch give the same "
    "result, so emit one row per branch+file, deduplicated across "
    "versions), using exactly that data -- this tells you which .ko module "
    "or vmlinux the file builds into for each stable branch/config), "
    "3. Affected & "
    "fixed versions (introduced version/commit, per-branch fixed releases "
    "table including each commit's date, EOL/unfixed branches), "
    "3b. Fleet exposure (if the JSON has a non-empty 'module_builtin' "
    "list, state that those files are compiled into vmlinux (built-in, "
    "not a loadable module), so every kernel running a build with that "
    "CONFIG_ symbol enabled contains the code and fleet module-load "
    "statistics do not apply; do NOT say such a file's module is 'not "
    "loaded'; if the JSON has a non-empty 'module_not_loaded' "
    "list, state explicitly for each listed module that it is not loaded "
    "in any region of the fleet, so the fleet is not exposed via that "
    "module; and only if the JSON has a 'module_stats' field: for "
    "each module name, render its 'rows' list as a table with columns "
    "Region | Total IPs | Loaded | ZServices | VMs | Phys Srv | KVM Host | "
    "Cont Host | Containers, using exactly that per-region data, one row "
    "per entry including the 'All regions' aggregate row), "
    "4. Vulnerability details (weakness class and the upstream description; "
    "then, only if the JSON has a 'tuxcare' field, a '### TuxCare status' "
    "subheading with a Field | Value table: a 'CVE-link' row with the link, "
    "and a 'Fixed' row listing each entry of 'fixes' on its own line as "
    "'<os> - <kind> (<status>)', e.g. 'Debian11 - ELS FIX (2026-09-07)'), "
    "5. The fix (mainline commit, subject, author, date, diffstat, patch "
    "link, plus a stable-backports table with columns Branch | Commit | "
    "Date | Patch link -- always include the commit date column, taken "
    "from each patch's 'date' field in the JSON), 6. Mitigations & detection, "
    "7. References (grouped by commits/CVE records/discussion/advisories/"
    "other), 8. Debian (package, link, per-suite status/fixed version table; "
    "do NOT include Red Hat, Ubuntu, SUSE, Arch or OSV sections), 9. Media & community coverage, "
    "10. Provenance (data sources used, version-mapping source, generation "
    "timestamp). Omit any section entirely if there is nothing "
    "for it. Do not refer to any JSON or data pack in the report text."
    "\n\nJSON data pack:\n```json\n%s\n```"
)

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
TUXCARE_CVE_PAGE = "https://tuxcare.com/cve-tracker/cve/details/%s/"

# media / community coverage sources (verified empirically -- see
# fetch_feedly/fetch_hackerwire/fetch_hackernews_coverage/fetch_wp_coverage)
FEEDLY_CVE_PAGE = "https://feedly.com/cve/%s"
HACKERWIRE_VULN_PAGE = "https://www.thehackerwire.com/vulnerability/%s/"
HACKERNEWS_FEED_SEARCH = "https://thehackernews.com/feeds/posts/default?q=%s&alt=json"
CYBERSECURITYNEWS_BASE = "https://cybersecuritynews.com"
SECURITYONLINE_BASE = "https://securityonline.info"
QUALYS_BLOG_PAGE = "https://blog.qualys.com/"
BLEEPINGCOMPUTER_SEARCH_PAGE = "https://www.bleepingcomputer.com/search/?q=%s"
# redirect blobs / social mirrors in Feedly's chatter list that aren't a
# real article a reader could usefully click through to
FEEDLY_NOISY_CHATTER_HOSTS = ("news.google.com", "nitter.net", "t.co",
                             "twitter.com", "x.com")

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


def llm_chat(system, user, model=None, timeout=180, temperature=0.2):
    """Call the local zLLM OpenAI-compatible proxy's /chat/completions and
    return the assistant's message content. Raises SystemExit with a clear,
    actionable message on any failure (proxy down, auth, bad response) --
    by design there is no silent template fallback."""
    url = ZLLM_BASE_URL.rstrip("/") + "/chat/completions"
    body = json.dumps({
        "model": model or ZLLM_MODEL,
        "temperature": temperature,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
    }).encode("utf-8")
    req = urllib.request.Request(
        url, data=body, method="POST",
        headers={"Content-Type": "application/json",
                 "Authorization": "Bearer %s" % ZLLM_API_KEY,
                 "User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", "replace") if e.fp else ""
        raise SystemExit(
            "ERROR: zLLM request failed (%s %s) at %s.\n%s\n"
            "       Is the proxy running? Try: zllm start"
            % (e.code, e.reason, url, detail[:500]))
    except Exception as e:  # noqa: BLE001
        raise SystemExit(
            "ERROR: could not reach zLLM proxy at %s (%s).\n"
            "       Is the proxy running? Try: zllm start" % (url, e))
    choices = data.get("choices") or []
    content = _dig(choices[0], "message", "content") if choices else None
    if not content or not content.strip():
        raise SystemExit(
            "ERROR: zLLM proxy returned an empty response.\n%s"
            % json.dumps(data, indent=2)[:1000])
    return content.strip()


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


def fetch_wp_coverage(base, cve_id, colloquial_name=None, limit=3):
    """Generic WordPress REST API search (no auth, no scraping) used for
    cybersecuritynews.com and securityonline.info. Tries the bare CVE ID
    first, then the colloquial vuln name if that yields nothing. Returns
    [] on a confirmed no-hit search, None if the site couldn't be reached
    at all."""
    reached = False
    for term in [t for t in (cve_id, colloquial_name) if t]:
        url = "%s/wp-json/wp/v2/posts?search=%s" % (
            base, urllib.parse.quote(term))
        data = _http_json(url, timeout=15)
        if data is None:
            continue
        reached = True
        out = []
        for post in data[:limit]:
            out.append({"title": _dig(post, "title", "rendered"),
                       "url": post.get("link"), "date": post.get("date")})
        if out:
            return out
    return [] if reached else None


def fetch_hackernews_coverage(cve_id, colloquial_name=None, limit=3):
    """thehackernews.com (Blogger-hosted): full-archive keyword search via
    Blogger's public GData feed API. Returns [] on a confirmed no-hit
    search, None if the feed couldn't be reached at all."""
    reached = False
    for term in [t for t in (cve_id, colloquial_name) if t]:
        url = HACKERNEWS_FEED_SEARCH % urllib.parse.quote(term)
        data = _http_json(url, timeout=15)
        if data is None:
            continue
        reached = True
        entries = _dig(data, "feed", "entry", default=[]) or []
        out = []
        for e in entries[:limit]:
            link = next((l.get("href") for l in e.get("link", [])
                        if l.get("rel") == "alternate"), None)
            out.append({"title": _dig(e, "title", "$t"), "url": link,
                       "date": _dig(e, "published", "$t")})
        if out:
            return out
    return [] if reached else None


def fetch_tuxcare(cve_id):
    """TuxCare CVE tracker page (server-rendered HTML): Debian ELS fixes come
    from the embedded `allData` JSON, KernelCare (live-patch) state from the
    'KernelCare state' table. Returns None if the CVE isn't on TuxCare or has
    no Debian entries."""
    link = TUXCARE_CVE_PAGE % cve_id.lower()
    html = _http_text(link, timeout=20)
    if not html:
        return None
    fixes = []
    m = re.search(r"const allData = (\[.*?\]);", html, re.S)
    if m:
        try:
            for d in json.loads(m.group(1)):
                dm = re.match(r"^Debian (\d+) ELS$", d.get("product") or "")
                if dm and d.get("fix_status") == "released":
                    fixes.append({"os": "Debian%s" % dm.group(1), "kind": "ELS FIX",
                                  "status": d.get("last_update")})
        except Exception:  # noqa: BLE001
            pass
    sec = re.search(r"KernelCare state(.*?)</table>", html, re.S)
    if sec:
        for row in re.findall(r"<tr[^>]*>(.*?)</tr>", sec.group(1), re.S):
            cells = [re.sub(r"<[^>]+>", "", c).strip()
                     for c in re.findall(r"<td[^>]*>(.*?)</td>", row, re.S)]
            dm = re.match(r"^Debian\s*(\d+)$", cells[0]) if len(cells) >= 2 else None
            if dm:
                fixes.append({"os": "Debian%s" % dm.group(1), "kind": "KCARE FIX",
                              "status": cells[1]})
    if not fixes:
        return None
    fixes.sort(key=lambda x: (int(re.sub(r"\D", "", x["os"])), x["kind"]))
    return {"link": link, "fixes": fixes}


def fetch_hackerwire(cve_id):
    """thehackerwire.com auto-generated CVE tracker page: extract the
    embedded JSON-LD (schema.org TechArticle) rather than scraping prose.
    The page returns HTTP 200 even for unknown CVEs (a client-side loading
    stub with no ld+json block), so absence of that block means "not
    tracked", not a fetch error."""
    html = _http_text(HACKERWIRE_VULN_PAGE % cve_id, timeout=15)
    if not html:
        return None
    m = re.search(r'<script type="application/ld\+json">(.*?)</script>',
                 html, re.S)
    if not m:
        return None
    try:
        data = json.loads(m.group(1))
    except Exception:  # noqa: BLE001
        return None
    graph = data.get("@graph") if isinstance(data, dict) else None
    art = next((g for g in graph or [] if g.get("@type") == "TechArticle"),
              None)
    if not art:
        return None
    return {"headline": art.get("headline"), "description": art.get("description"),
            "date": art.get("datePublished"),
            "url": HACKERWIRE_VULN_PAGE % cve_id}


def fetch_feedly(cve_id):
    """feedly.com/cve/<id>: server-side-rendered Next.js page; extract the
    __NEXT_DATA__ JSON blob (a single well-defined embedded object, not
    prose scraping) for cross-outlet media coverage aggregation."""
    html = _http_text(FEEDLY_CVE_PAGE % cve_id, timeout=20)
    if not html:
        return None
    m = re.search(r'<script id="__NEXT_DATA__"[^>]*>(.*?)</script>',
                 html, re.S)
    if not m:
        return None
    try:
        data = json.loads(m.group(1))
    except Exception:  # noqa: BLE001
        return None
    pp = _dig(data, "props", "pageProps", default={}) or {}
    cve_info = pp.get("cveInfo") or {}
    if not cve_info:
        return None
    chatter = []
    for c in pp.get("chatterEntries") or []:
        link = c.get("sourceLink")
        if not link:
            continue
        host = urllib.parse.urlparse(link).netloc.lower()
        if any(h in host for h in FEEDLY_NOISY_CHATTER_HOSTS):
            continue  # redirect blobs / social mirrors, not a real article
        chatter.append({"title": c.get("title"), "url": link})
        if len(chatter) >= 5:
            break
    return {
        "cvss_estimate": cve_info.get("cvssCategoryEstimate"),
        "trending": cve_info.get("trending"),
        "patched": cve_info.get("patched"),
        "total_chatter": pp.get("totalChatterEntries"),
        "chatter": chatter,
        "link": FEEDLY_CVE_PAGE % cve_id,
    }


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


def _fetch_patch_local(commit, linux_src):
    """Read a commit's patch straight out of a local Linux git checkout via
    `git show`, instead of hitting git.kernel.org. Returns the same shape as
    fetch_patch(), or None if the tree/commit isn't available locally."""
    if not linux_src or not os.path.isdir(os.path.join(linux_src, ".git")):
        return None
    try:
        proc = subprocess.run(
            ["git", "show", "--pretty=fuller", "--date=default", commit],
            cwd=linux_src, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, encoding="utf-8", errors="replace", timeout=30)
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0 or not proc.stdout:
        return None
    raw = proc.stdout

    out = {
        "commit": commit, "raw_url": None,
        "web_url": "https://git.kernel.org/stable/c/%s" % commit,
        "author": None, "date": None, "subject": None, "body": None,
        "files": [], "functions": [], "insertions": 0, "deletions": 0,
    }
    header, _, diff_part = raw.partition("\ndiff --git")
    diff_part = ("diff --git" + diff_part) if diff_part else ""

    m = re.search(r"^Author:\s*(.+)$", header, re.MULTILINE)
    if m:
        out["author"] = m.group(1).strip()
    # commit date (not author date), straight from the local tree
    try:
        cd = subprocess.run(
            ["git", "show", "-s", "--format=%cd", commit],
            cwd=linux_src, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, encoding="utf-8", errors="replace", timeout=30)
        if cd.returncode == 0 and cd.stdout.strip():
            out["date"] = cd.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        pass

    lines = header.split("\n")
    body_lines, in_body = [], False
    for line in lines:
        if not in_body:
            if line.startswith("commit ") or re.match(
                    r"^(Author|AuthorDate|Commit|CommitDate):", line):
                continue
            if line.strip() == "" and not body_lines:
                in_body = True
                continue
            continue
        body_lines.append(line)
    # strip the leading 4-space indent git show applies to commit message
    body_lines = [ln[4:] if ln.startswith("    ") else ln for ln in body_lines]
    body_text = "\n".join(body_lines).strip()
    if body_text:
        subject, _, rest = body_text.partition("\n")
        out["subject"] = subject.strip()
        out["body"] = rest.strip() or None

    out["files"] = re.findall(r"^diff --git a/(\S+) b/\S+", diff_part, re.MULTILINE)
    # plain `git show` prints no diffstat, so count the changed diff lines
    # (skip the ---/+++ file headers)
    out["insertions"] = sum(1 for ln in diff_part.split("\n")
                            if ln.startswith("+") and not ln.startswith("+++"))
    out["deletions"] = sum(1 for ln in diff_part.split("\n")
                           if ln.startswith("-") and not ln.startswith("---"))

    funcs, cur_src = [], False
    for line in diff_part.split("\n"):
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


def fetch_patch(commit, linux_src=None):
    """Fetch a commit patch, preferring a local Linux source tree (`git
    show`, no network) over git.kernel.org when linux_src is given and has
    the commit; parse headers + per-file hunks either way."""
    local = _fetch_patch_local(commit, linux_src)
    if local:
        return local
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
    # the patch mail 'Date:' is the AUTHOR date; leave date unset here
    # (commit date is only taken from the local Linux tree)
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


def _module_names_from_resolution(module_by_branch, modules=None):
    """Collect distinct .ko module basenames (no path, no extension) out of
    resolve_modules_by_branch()'s per-branch/per-config results, plus any
    names already known from fetch_makefile_config()."""
    names = list(modules or [])
    for branch_entries in (module_by_branch or {}).values():
        for cfg_entry in branch_entries:
            for fe in cfg_entry.get("files", []):
                m = re.search(r"([A-Za-z0-9_\-]+)\.ko\b", fe.get("result") or "")
                if m and m.group(1) not in names:
                    names.append(m.group(1))
    return names


_MODULE_STATS_ROW_RE = re.compile(
    r"^\s*(.+?)\s{2,}(\d+)\s+(\d+)\s+([\d.]+)%\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*$")


def fetch_module_stats(module, script_path=MODULE_STATS_SCRIPT_DEFAULT, timeout=60):
    """Run the fleet module_stats.py tool's --brief text report for a single
    module name and parse the per-region summary table (Region, Total IPs,
    Loaded, Loaded %, ZServices, VMs, Phys Srv, KVM Host, Cont Host,
    Containers). Returns None if the script is missing, times out, or the
    module isn't tracked in any region's matrix."""
    if not script_path or not os.path.isfile(script_path):
        return None
    try:
        proc = subprocess.run(
            [script_path, module, "--brief"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0 or not proc.stdout.strip():
        return None
    rows = []
    for line in proc.stdout.splitlines():
        m = _MODULE_STATS_ROW_RE.match(line)
        if not m:
            continue
        region, total, loaded, _pct, zsvc, vms, phys, kvm, cont_host, containers = m.groups()
        rows.append({
            "region": region.strip(), "total_ips": int(total), "loaded": int(loaded),
            "zservices": int(zsvc), "vms": int(vms), "phys_srv": int(phys),
            "kvm_host": int(kvm), "cont_host": int(cont_host),
            "containers": int(containers),
        })
    if not rows:
        return None
    return {"module": module, "rows": rows}


def resolve_modules_by_branch(files, linux_src, configs_dir,
                               branches=MODULE_RESOLVE_BRANCHES):
    """For each affected source file, resolve which module (.ko) or vmlinux
    it builds into, per stable branch (5.10.y/6.1.y/6.12.y) and per matching
    .config file found in configs_dir -- using find_module_new.py's
    Makefile/Kconfig resolution against a throwaway git worktree of that
    branch (the caller's checkout at linux_src is left untouched).
    Returns {branch: [{"config": name, "files": [{"file", "config_symbol",
    "result"}, ...]}, ...]}."""
    files = [f for f in (files or []) if f.endswith((".c", ".S", ".h"))]
    if not files or not linux_src or not os.path.isdir(
            os.path.join(linux_src, ".git")):
        return {}
    try:
        import find_module_new as fm
    except ImportError:
        return {}

    all_configs = []
    if configs_dir and os.path.isdir(configs_dir):
        all_configs = sorted(
            os.path.join(configs_dir, f) for f in os.listdir(configs_dir)
            if f.startswith("config-"))

    def _configs_for_branch(branch):
        m = re.match(r"linux-(\d+\.\d+)\.y", branch)
        if not m:
            return []
        prefix = "config-%s." % m.group(1)
        return [c for c in all_configs if os.path.basename(c).startswith(prefix)]

    result = {}
    for branch in branches:
        cfgs = _configs_for_branch(branch)
        if not cfgs:
            continue
        wt_path = fm._add_worktree(branch, linux_src)
        if wt_path is None:
            continue
        try:
            branch_out = []
            for cfg_path in cfgs:
                kernel_cfg = fm.load_kernel_config(cfg_path)
                per_file = []
                for f in files:
                    try:
                        outcome, raw_config, _, resolved_dir = fm.find_module(
                            f, wt_path, config_path=cfg_path, kernel_cfg=kernel_cfg)
                    except (FileNotFoundError, IsADirectoryError):
                        continue
                    directory = (os.path.relpath(resolved_dir, wt_path)
                                 if resolved_dir else os.path.dirname(f))
                    per_file.append({
                        "file": f,
                        "config_symbol": raw_config,
                        "result": fm.format_outcome(outcome, raw_config, directory),
                    })
                if per_file:
                    branch_out.append({
                        "config": os.path.basename(cfg_path),
                        "files": per_file,
                    })
            if branch_out:
                result[branch] = branch_out
        finally:
            fm._remove_worktree(wt_path, linux_src)
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
    def build(items, source):
        # items: [(cwe_id, name_or_None)], deduplicated, order preserved
        uniq, seen = [], set()
        for cid, name in items:
            if cid not in seen:
                seen.add(cid)
                uniq.append((cid, name))
        if not uniq:
            return None
        return {"id": ", ".join(i for i, _ in uniq),
                "ids": [i for i, _ in uniq],
                "name": uniq[0][1] if len(uniq) == 1 else None,
                "source": source, "derived": False}

    def from_problemtypes(container, source):
        items = []
        for pt in container.get("problemTypes", []) or []:
            for d in pt.get("descriptions", []) or []:
                cid = d.get("cweId") or (d.get("description") if
                      str(d.get("description", "")).startswith("CWE-") else None)
                if cid and str(cid).startswith("CWE-"):
                    name = d.get("description")
                    if name and name.startswith("CWE-"):
                        name = name.split(" ", 1)[1] if " " in name else None
                    items.append((cid, name))
        return build(items, source)

    cna = _dig(cvelist, "containers", "cna", default={}) or {}
    c = from_problemtypes(cna, "CNA")
    if c:
        return c
    if nvd:
        items = [(d["value"], None)
                 for w in nvd.get("weaknesses", []) or []
                 for d in w.get("description", []) or []
                 if d.get("value", "").startswith("CWE-")]
        c = build(items, "NVD")
        if c:
            return c
    for adp in _dig(cvelist, "containers", "adp", default=[]) or []:
        c = from_problemtypes(adp, "CISA-ADP")
        if c:
            return c
    # no keyword guessing: report the absence of an official CWE
    return {"id": "No official record", "ids": [], "name": None,
            "source": "none in CNA, NVD or CISA-ADP data", "derived": False}


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

def build_record(cve_id, fetch_diffs=True, fetch_vendor=True, fetch_media=True,
                  linux_src=None, configs_dir=None, resolve_modules=True,
                  fetch_module_stats_flag=True, module_stats_script=None):
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

    redhat = archlinux = osv = exploitdb = debian = lkc = tuxcare = None
    if fetch_vendor:
        sys.stderr.write("[*] fetching Exploit-DB ...\n")
        exploitdb = summarize_exploitdb(fetch_exploitdb(cve_id))
        if is_kernel:
            sys.stderr.write(
                "[*] fetching Debian tracker / linuxkernelcves.com "
                "(cached, first run may be slow) ...\n")
            debian = summarize_debian(fetch_debian_entry(cve_id), cve_id)
            lkc = fetch_linuxkernelcves(cve_id)
            sys.stderr.write("[*] fetching TuxCare tracker ...\n")
            tuxcare = fetch_tuxcare(cve_id)

    feedly = hackerwire = None
    hackernews_coverage = csn_coverage = dcs_coverage = None
    if fetch_media:
        sys.stderr.write(
            "[*] fetching media/community coverage (Feedly, Hacker Wire, "
            "Hacker News, CyberSecurityNews, SecurityOnline) ...\n")
        colloquial = lkc.get("name") if lkc else None
        feedly = fetch_feedly(cve_id)
        hackerwire = fetch_hackerwire(cve_id)
        hackernews_coverage = fetch_hackernews_coverage(cve_id, colloquial)
        csn_coverage = fetch_wp_coverage(
            CYBERSECURITYNEWS_BASE, cve_id, colloquial)
        dcs_coverage = fetch_wp_coverage(
            SECURITYONLINE_BASE, cve_id, colloquial)

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
            p = fetch_patch(c, linux_src=linux_src)
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

    # per-branch module resolution against a local Linux source tree +
    # per-branch .config files (find_module_new.py's Makefile/Kconfig logic)
    module_by_branch = {}
    if files and is_kernel and resolve_modules and linux_src:
        sys.stderr.write("[*] resolving module per branch/config (local source) ...\n")
        module_by_branch = resolve_modules_by_branch(files, linux_src, configs_dir)

    # fleet exposure: how widely is the affected module actually loaded
    module_stats = {}
    module_not_loaded = []
    module_builtin = []
    for _entries in (module_by_branch or {}).values():
        for _cfg in _entries:
            for _fe in _cfg.get("files", []):
                _res = _fe.get("result") or ""
                if "vmlinux" in _res and ".ko" not in _res:
                    _b = {"file": _fe.get("file"),
                          "config_symbol": _fe.get("config_symbol")}
                    if _b not in module_builtin:
                        module_builtin.append(_b)
    if (fetch_module_stats_flag and module_stats_script
            and os.path.isfile(module_stats_script)):
        candidate_modules = _module_names_from_resolution(
            module_by_branch, None if module_by_branch
            else modinfo.get("modules"))
        if candidate_modules:
            sys.stderr.write("[*] querying fleet module_stats.py for %s ...\n"
                             % ", ".join(candidate_modules))
        for mod in candidate_modules:
            stats = fetch_module_stats(mod, script_path=module_stats_script)
            if stats:
                module_stats[mod] = stats
            else:
                module_not_loaded.append(mod)

    sources = ["CVEProject/cvelistV5"]
    if dyad:
        sources.append("kernel vulns.git (dyad)")
    if nvd:
        sources.append("NVD 2.0 API")
    if epss:
        sources.append("FIRST EPSS")
    sources.append("CISA KEV" if kev else "CISA KEV (not listed)")
    if patches:
        local_patches = any(p.get("raw_url") is None for p in patches.values())
        remote_patches = any(p.get("raw_url") is not None for p in patches.values())
        if local_patches:
            sources.append("local Linux source (%s)" % linux_src)
        if remote_patches:
            sources.append("git.kernel.org (commits)")
    if module_by_branch:
        sources.append("find_module_new.py + local .config (per-branch module resolution)")
    if module_stats:
        sources.append("module_stats.py (fleet module-usage stats)")
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
    if tuxcare:
        sources.append("TuxCare CVE tracker")
    if feedly:
        sources.append("Feedly.com")
    if hackerwire:
        sources.append("The Hacker Wire")
    if hackernews_coverage is not None:
        sources.append("The Hacker News")
    if csn_coverage is not None:
        sources.append("CyberSecurityNews.com")
    if dcs_coverage is not None:
        sources.append("SecurityOnline.info")

    # sources not included, each with the reason
    skipped = []

    def _skip(name, reason):
        skipped.append({"source": name, "reason": reason})

    if not dyad:
        _skip("kernel vulns.git (dyad)",
              "not a Linux kernel CNA record" if not is_kernel
              else "no dyad file published for this CVE")
    if not nvd:
        _skip("NVD 2.0 API", "no NVD record returned (not yet ingested or unreachable)")
    if not epss:
        _skip("FIRST EPSS", "no EPSS score published or API unreachable")
    if not patches:
        _skip("Commit patches",
              "disabled (--no-diff)" if not fetch_diffs
              else "not a Linux kernel CVE" if not is_kernel
              else "no fix commits found, or commits unavailable locally and on git.kernel.org")
    if not module_by_branch:
        _skip("Per-branch module resolution",
              "disabled (--no-module-resolve)" if not resolve_modules
              else "not a Linux kernel CVE" if not is_kernel
              else "no affected source files listed in the CVE record" if not files
              else "local Linux source tree not available" if not (
                  linux_src and os.path.isdir(os.path.join(linux_src, ".git")))
              else "no matching .config files or find_module_new.py unavailable")
    if not module_stats:
        _skip("Fleet module-usage stats",
              "disabled (--no-module-stats)" if not fetch_module_stats_flag
              else "module_stats.py not found" if not (
                  module_stats_script and os.path.isfile(module_stats_script))
              else "affected code is built into vmlinux (no loadable module)"
              if module_builtin and not module_not_loaded
              else "module not loaded in any fleet region" if module_not_loaded
              else "no loadable module identified")
    for _name, _val in (("Red Hat Security Data API", redhat),
                        ("Arch Linux Security Tracker", archlinux),
                        ("OSV.dev", osv)):
        if not _val:
            _skip(_name, "not queried (excluded from reports by design)")
    if exploitdb is None:
        _skip("Exploit-DB", "disabled (--no-vendor)" if not fetch_vendor
              else "lookup failed")
    if not debian:
        _skip("Debian Security Tracker",
              "disabled (--no-vendor)" if not fetch_vendor
              else "not a Linux kernel CVE" if not is_kernel
              else "CVE not tracked by Debian")
    if not lkc:
        _skip("linuxkernelcves.com",
              "disabled (--no-vendor)" if not fetch_vendor
              else "not a Linux kernel CVE" if not is_kernel
              else "CVE not present in community dataset")
    if not tuxcare:
        _skip("TuxCare CVE tracker",
              "disabled (--no-vendor)" if not fetch_vendor
              else "not a Linux kernel CVE" if not is_kernel
              else "no Debian fix entries on TuxCare, or page unreachable")
    for _name, _val in (("Feedly.com", feedly), ("The Hacker Wire", hackerwire)):
        if not _val:
            _skip(_name, "disabled (--no-media)" if not fetch_media
                  else "no entry for this CVE")
    for _name, _val in (("The Hacker News", hackernews_coverage),
                        ("CyberSecurityNews.com", csn_coverage),
                        ("SecurityOnline.info", dcs_coverage)):
        if _val is None:
            _skip(_name, "disabled (--no-media)" if not fetch_media
                  else "site unreachable")
    for _s in skipped:
        sys.stderr.write("  - not included: %s (%s)\n" % (_s["source"], _s["reason"]))

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
        "module_by_branch": module_by_branch, "module_stats": module_stats,
        "module_not_loaded": module_not_loaded,
        "module_builtin": module_builtin,
        "cvss": cvss, "cwe": cwe, "epss": epss, "kev": kev, "ssvc": ssvc,
        "versions": versions, "cpe_ranges": cpe,
        "references": refs, "patches": patches, "sources_used": sources,
        "nvd_status": nvd.get("vulnStatus") if nvd else "Not in NVD",
        "exploitdb": exploitdb, "debian": debian, "lkc": lkc,
        "tuxcare": tuxcare,
        "ubuntu_link": UBUNTU_CVE_PAGE % cve_id if fetch_vendor else None,
        "feedly": feedly, "hackerwire": hackerwire,
        "hackernews_coverage": hackernews_coverage,
        "cybersecuritynews_coverage": csn_coverage,
        "securityonline_coverage": dcs_coverage,
        "qualys_blog_link": QUALYS_BLOG_PAGE if fetch_media else None,
        "bleepingcomputer_search_link":
            BLEEPINGCOMPUTER_SEARCH_PAGE % urllib.parse.quote(cve_id)
            if fetch_media else None,
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


# zLLM's upstream enforces a hard cap on the 'content' field of each chat
# message; stay well under it (leaves room for the prompt template + system
# prompt on top of the JSON data pack itself).
ZLLM_MAX_DATA_PACK_CHARS = 350000


def _slim_patches(patches, body_chars=1200, max_list_items=40):
    """Drop the raw/full commit body down to a short excerpt and cap
    files/functions list length -- some commits (e.g. the kernel's initial
    git-import commit) touch tens of thousands of files and would otherwise
    blow past the LLM's content-length limit by themselves."""
    out = {}
    for commit, p in (patches or {}).items():
        body = p.get("body") or ""
        if len(body) > body_chars:
            body = body[:body_chars] + " …(truncated)"
        files = p.get("files") or []
        functions = p.get("functions") or []
        out[commit] = {
            "commit": p.get("commit"), "web_url": p.get("web_url"),
            "author": p.get("author"), "date": p.get("date"),
            "subject": p.get("subject"), "body": body,
            "files": files[:max_list_items] + (
                ["… (+%d more files)" % (len(files) - max_list_items)]
                if len(files) > max_list_items else []),
            "functions": functions[:max_list_items] + (
                ["… (+%d more)" % (len(functions) - max_list_items)]
                if len(functions) > max_list_items else []),
            "insertions": p.get("insertions"), "deletions": p.get("deletions"),
        }
    return out


def _slim_data_pack(record, max_len=ZLLM_MAX_DATA_PACK_CHARS):
    """Build a JSON-serializable copy of the data pack that fits under
    max_len characters, progressively dropping/truncating the least
    essential and largest fields (patch bodies, media chatter, long refs)
    before ever touching core fields like CVSS/versions/description."""
    r = dict(record)
    r["patches"] = _slim_patches(record.get("patches"))

    def _size():
        return len(json.dumps(r, ensure_ascii=False))

    if _size() <= max_len:
        return r

    # 1. shorten patch commit-message bodies further
    r["patches"] = _slim_patches(record.get("patches"), body_chars=300)
    if _size() <= max_len:
        return r

    # 2. trim bulky, non-essential coverage/reference detail
    if r.get("feedly"):
        r["feedly"] = {k: v for k, v in r["feedly"].items() if k != "chatter"}
    for key in ("hackernews_coverage", "cybersecuritynews_coverage",
                "securityonline_coverage"):
        if r.get(key):
            r[key] = r[key][:1]
    if r.get("references", {}).get("other"):
        r["references"] = dict(r["references"])
        r["references"]["other"] = r["references"]["other"][:5]
    if _size() <= max_len:
        return r

    # 3. drop patch bodies entirely, keep only subject/metadata
    for p in r["patches"].values():
        p["body"] = None
    if _size() <= max_len:
        return r

    # 4. last resort: keep only the mainline + intro commit patches
    v = r.get("versions") or {}
    keep = set(v.get("intro_commits") or [])
    ml = v.get("mainline_commit")
    if ml:
        keep.add(ml)
    r["patches"] = {c: p for c, p in r["patches"].items() if c in keep}
    return r


def render_markdown_llm(r, model=None):
    """Have the zLLM proxy write the report from the raw data pack. This is
    the primary rendering path; render_markdown() (template-based) remains
    available for --template/offline use."""
    data_pack = _slim_data_pack(r)
    user = ZLLM_REPORT_USER_TEMPLATE % (
        r["cve_id"], json.dumps(data_pack, indent=2, ensure_ascii=False))
    body = llm_chat(ZLLM_REPORT_SYSTEM_PROMPT, user, model=model)
    header = ("> Generated %s · sources: %s\n\n" % (
        r["generated_at"], ", ".join(r["sources_used"])))
    if not body.lstrip().startswith("#"):
        body = ("# %s — %s\n\n" % (r["cve_id"], r["title"])) + body
    lines = body.split("\n", 1)
    if len(lines) == 2:
        body = lines[0] + "\n\n" + header + lines[1]
    else:
        body = body + "\n\n" + header
    return body


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

    mbb = r.get("module_by_branch") or {}
    if mbb:
        a("### Module resolution by branch (local source + .config)")
        a("")
        a("| Branch | File | CONFIG_ symbol | Result |")
        a("|---|---|---|---|")
        for branch in sorted(mbb):
            seen_rows = set()
            for cfg_entry in mbb[branch]:
                for fe in cfg_entry["files"]:
                    row = (fe["file"], fe["config_symbol"], fe["result"])
                    if row in seen_rows:
                        continue
                    seen_rows.add(row)
                    a("| `%s` | `%s` | %s | %s |" % (
                        branch, fe["file"],
                        ("`%s`" % fe["config_symbol"]) if fe["config_symbol"] else "—",
                        fe["result"]))
        a("")

    ms = r.get("module_stats") or {}
    if ms:
        a("### Fleet exposure (module_stats.py)")
        a("")
        for mod, stats in ms.items():
            a("**Module `%s`:**" % mod)
            a("")
            a("| Region | Total IPs | Loaded | ZServices | VMs | Phys Srv | "
              "KVM Host | Cont Host | Containers |")
            a("|---|---|---|---|---|---|---|---|---|")
            for row in stats.get("rows") or []:
                a("| %s | %s | %s | %s | %s | %s | %s | %s | %s |" % (
                    row.get("region"), row.get("total_ips"), row.get("loaded"),
                    row.get("zservices"), row.get("vms"), row.get("phys_srv"),
                    row.get("kvm_host"), row.get("cont_host"), row.get("containers")))
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
        a("_Source: %s_" % r["cwe"]["source"])
        a("")
    a("**Upstream description:**")
    a("")
    for line in (r["description"] or "(none)").splitlines():
        a("> %s" % line if line.strip() else ">")
    a("")
    tc = r.get("tuxcare")
    if tc:
        a("### TuxCare status")
        a("")
        a("| Field | Value |")
        a("|---|---|")
        a("| CVE-link | %s |" % tc["link"])
        for i, fx in enumerate(tc["fixes"]):
            a("| %s | %s - %s (%s) |" % (
                "Fixed" if i == 0 else "", fx["os"], fx["kind"], fx["status"]))
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

    # 8. Debian
    a("## 8. Debian")
    a("")
    deb = r.get("debian")
    lkc = r.get("lkc")
    if r.get("ubuntu_link") is None:
        a("_Skipped (--no-vendor)._")
        a("")
    else:
        if deb:
            a("- **Package:** `%s`" % deb["package"])
            a("- **Link:** %s" % deb["link"])
            a("")
            if deb["releases"]:
                a("| Suite | Status | Fixed version |")
                a("|---|---|---|")
                for x in deb["releases"]:
                    a("| %s | %s | %s |" % (
                        x["suite"], x["status"],
                        ("`%s`" % x["fixed_version"]) if x["fixed_version"]
                        else "—"))
                a("")
        elif r["is_kernel"]:
            a("Not tracked by Debian: %s" % (DEBIAN_CVE_PAGE % r["cve_id"]))
            a("")
        else:
            a("Not queried (non-kernel CVE): %s" % (DEBIAN_CVE_PAGE % r["cve_id"]))
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

    # 9. media & community coverage
    a("## 9. Media & community coverage")
    a("")
    feedly, hackerwire = r.get("feedly"), r.get("hackerwire")
    hn_hits = r.get("hackernews_coverage")
    csn_hits = r.get("cybersecuritynews_coverage")
    dcs_hits = r.get("securityonline_coverage")
    if r.get("qualys_blog_link") is None:
        a("_Skipped (--no-media)._")
        a("")
    else:
        if feedly:
            bits = []
            if feedly.get("cvss_estimate"):
                bits.append("CVSS estimate: %s" % feedly["cvss_estimate"])
            if feedly.get("trending"):
                bits.append("trending")
            if feedly.get("total_chatter") is not None:
                bits.append("%s tracked mention(s)" % feedly["total_chatter"])
            a("**[Feedly aggregator](%s)** — %s" % (
                feedly["link"], ", ".join(bits) or "tracked"))
            for c in feedly.get("chatter") or []:
                a("- [%s](%s)" % (c.get("title") or c["url"], c["url"]))
            a("")

        def _fmt_hits(hits):
            return "; ".join("[%s](%s)" % (h["title"], h["url"])
                             for h in hits[:2] if h.get("url"))

        rows = []
        if hackerwire:
            rows.append(("The Hacker Wire (CVE tracker)",
                        "[%s](%s)" % (hackerwire.get("headline")
                                     or "tracked", hackerwire["url"])))
        if hn_hits:
            rows.append(("The Hacker News", _fmt_hits(hn_hits)))
        elif hn_hits is not None:
            rows.append(("The Hacker News", "no coverage found"))
        if csn_hits:
            rows.append(("CyberSecurityNews.com", _fmt_hits(csn_hits)))
        elif csn_hits is not None:
            rows.append(("CyberSecurityNews.com", "no coverage found"))
        if dcs_hits:
            rows.append(("SecurityOnline.info", _fmt_hits(dcs_hits)))
        elif dcs_hits is not None:
            rows.append(("SecurityOnline.info", "no coverage found"))
        if rows:
            a("| Outlet | Coverage |")
            a("|---|---|")
            for name, val in rows:
                a("| %s | %s |" % (name, val))
            a("")
        if r.get("qualys_blog_link") or r.get("bleepingcomputer_search_link"):
            a("_Not queried live (no reliable no-auth API): "
              "[Qualys TRU blog](%s), [BleepingComputer](%s) "
              "(blocks non-browser requests) -- check manually._" % (
                  r.get("qualys_blog_link") or QUALYS_BLOG_PAGE,
                  r.get("bleepingcomputer_search_link")
                  or (BLEEPINGCOMPUTER_SEARCH_PAGE % r["cve_id"])))
            a("")

    # 10. provenance
    a("## 10. Provenance")
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
    ap.add_argument("--no-media", action="store_true",
                    help="skip Feedly/Hacker Wire/Hacker News/community "
                         "media coverage lookups (faster, less detail)")
    ap.add_argument("--template", action="store_true",
                    help="use the built-in template renderer instead of the "
                         "zLLM proxy")
    ap.add_argument("--llm-model", help="zLLM model id to use (default: %s, "
                    "or $ZLLM_MODEL)" % ZLLM_MODEL)
    ap.add_argument("--linux-src", default=LINUX_SRC_DEFAULT,
                    help="local Linux git checkout, used for per-branch "
                         "module resolution and to read commit patches "
                         "without hitting git.kernel.org (default: %s)"
                         % LINUX_SRC_DEFAULT)
    ap.add_argument("--configs-dir", default=CONFIGS_DIR_DEFAULT,
                    help="directory of config-<version> files used for "
                         "per-branch module resolution (default: %s)"
                         % CONFIGS_DIR_DEFAULT)
    ap.add_argument("--no-module-resolve", action="store_true",
                    help="skip per-branch/per-config module resolution "
                         "(faster, less detail)")
    ap.add_argument("--module-stats-script", default=MODULE_STATS_SCRIPT_DEFAULT,
                    help="path to module_stats.py, used to report fleet-wide "
                         "module usage stats (default: %s)"
                         % MODULE_STATS_SCRIPT_DEFAULT)
    ap.add_argument("--no-module-stats", action="store_true",
                    help="skip querying module_stats.py for fleet exposure "
                         "(faster, less detail)")
    args = ap.parse_args(argv)

    cve = args.cve.strip().upper()
    if not CVE_RE.match(cve):
        ap.error("invalid CVE id: %s (expected CVE-YYYY-NNNNN)" % args.cve)

    record = build_record(cve, fetch_diffs=not args.no_diff,
                          fetch_vendor=not args.no_vendor,
                          fetch_media=not args.no_media,
                          linux_src=args.linux_src,
                          configs_dir=args.configs_dir,
                          resolve_modules=not args.no_module_resolve,
                          fetch_module_stats_flag=not args.no_module_stats,
                          module_stats_script=args.module_stats_script)

    if args.json_only:
        sys.stdout.write(json.dumps(record, indent=2, ensure_ascii=False) + "\n")
        return 0

    if args.template:
        md = render_markdown(record)
    else:
        sys.stderr.write("[*] writing report via zLLM (%s) ...\n" %
                         (args.llm_model or ZLLM_MODEL))
        md = render_markdown_llm(record, model=args.llm_model)
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
