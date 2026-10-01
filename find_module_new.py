#!/usr/bin/env python3
"""
find_module_copilot.py

Given a source file's path (relative to the Linux kernel source tree) and the
path to the kernel source tree, determine which kernel module (.ko) the file
is built into, or whether it is built into vmlinux.

The CONFIG_ resolution logic (finding which CONFIG_ option governs a source
file) is reused verbatim from kernel_commit_csv.py's
_resolve_object / _resolve_source_file / _find_dir_mapping chain. This
script only adds a thin layer on top: it takes the resolved CONFIG_ (or
BUILTIN/MODULE sentinel), looks up the value in a .config file, and derives
the resulting module name (or vmlinux) from the Makefile.

Usage:
    python3 find_module_copilot.py <relative_file_path> <linux_src_path> [--config <path-to-.config>]

Examples:
    python3 find_module_copilot.py fs/ext4/acl.c /home/user/linux-6.1.123
    python3 find_module_copilot.py mm/hwpoison-inject.c /home/user/linux-6.1.123
"""

import argparse
import concurrent.futures
import os
import re
import shutil
import subprocess
import sys
import tempfile
import uuid


# ═══════════════════════════════════════════════════════════════════════════════
#  CONFIG_ resolution  (copied verbatim from kernel_commit_csv.py)
# ═══════════════════════════════════════════════════════════════════════════════

def _read_makefile(path):
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return f.readlines()
    return []


def _join_lines(lines):
    full, current = [], ""
    for line in lines:
        line = line.rstrip()
        if line.endswith("\\"):
            current += line[:-1] + " "
        else:
            current += line
            full.append(current)
            current = ""
    return full


def _find_direct_mapping(obj_name, lines):
    config_pat = re.compile(r'[A-Za-z0-9_\-]+-\$\((CONFIG_[A-Za-z0-9_]+)\)\s*[:+]?=\s*(.+)')
    built_pat  = re.compile(r'obj-y\s*[:+]?=\s*(.+)')
    mod_pat    = re.compile(r'obj-m\s*[:+]?=\s*(.+)')
    def _token_match(token):
        # Match exact name or path-prefixed name (e.g. gt/foo.o matches foo.o)
        return token == obj_name or token.endswith("/" + obj_name)
    for line in lines:
        m = config_pat.search(line)
        if m and any(_token_match(t) for t in m.group(2).split()):
            return m.group(1)
        m = built_pat.search(line)
        if m and any(_token_match(t) for t in m.group(1).split()):
            return "BUILTIN"
        m = mod_pat.search(line)
        if m and any(_token_match(t) for t in m.group(1).split()):
            return "MODULE"
    return None


def _find_parent_object(obj_name, lines):
    pattern = re.compile(r'([A-Za-z0-9_\-]+)-(?:objs|y|m)\s*[:+]?=\s*(.+)')
    for line in lines:
        m = pattern.search(line)
        if m and any(t == obj_name or t.endswith("/" + obj_name)
                     for t in m.group(2).split()):
            return m.group(1) + ".o"
    return None


def _find_var_containing_obj(obj_name, lines):
    """
    Find which Makefile variable (e.g. 'gt-y', 'core-y') contains obj_name
    as a token (including path-prefixed forms like gt/foo.o).
    Returns a list of variable names that contain the object.
    """
    assign_pat = re.compile(r'^([A-Za-z0-9_\-]+)\s*[:+]?=\s*(.+)')
    found = []
    def _tok_match(tok):
        return tok == obj_name or tok.endswith("/" + obj_name)
    for line in lines:
        m = assign_pat.match(line)
        if m:
            var_name = m.group(1)
            tokens   = m.group(2).split()
            if any(_tok_match(t) for t in tokens):
                found.append(var_name)
    return found


def _resolve_via_variable(var_name, lines, visited=None, extra_files=None, own_dir=None):
    """
    Given a variable name (e.g. 'gt-y'), find what obj-$(CONFIG_*) or obj-y
    that variable is folded into via patterns like:
        i915-y += $(gt-y)
        obj-$(CONFIG_DRM_I915) += i915.o
    Returns a (result, stem, resolved_dir) tuple, where result is the
    CONFIG_ string, 'BUILTIN', 'MODULE', or None; stem is the base name
    (without ".o") of the top-level object the variable was ultimately
    folded into (e.g. "i915"), or None if result is None; and resolved_dir
    is the directory of the Makefile that contained the winning obj- rule
    (may differ from the file that owns `lines`, e.g. a driver whose object
    list is folded into a sibling directory's module).

    `lines` (the current Makefile, in directory `own_dir`) is searched
    first. If the variable isn't referenced/resolved there, and
    `extra_files` (an iterable of (dir_path, lines) tuples -- e.g. a
    tree-wide index) is provided, the search widens to those files too.
    This is needed for drivers that fold their object list into a variable
    consumed by a *different* Makefile than the one that builds it up
    (e.g. AMD's display driver accumulates $(AMD_DISPLAY_FILES) across many
    subdirectories, but it's only ever turned into
    `amdgpu-y += $(AMD_DISPLAY_FILES)` inside
    drivers/gpu/drm/amd/amdgpu/Makefile).
    """
    if visited is None:
        visited = set()
    if var_name in visited:
        return None, None, None
    visited.add(var_name)

    config_pat  = re.compile(r'obj-\$\((CONFIG_[A-Za-z0-9_]+)\)\s*[:+]?=\s*(.+)')
    builtin_pat = re.compile(r'obj-y\s*[:+]?=\s*(.+)')
    mod_pat     = re.compile(r'obj-m\s*[:+]?=\s*(.+)')
    ref_pat     = re.compile(r'^([A-Za-z0-9_\-]+)\s*[:+]?=\s*(.*\$\(' + re.escape(var_name) + r'\).*)')

    candidate_sources = [(own_dir, lines)]
    if extra_files:
        candidate_sources.extend(extra_files)

    for src_dir, src_lines in candidate_sources:
        # Which variables does var_name get folded into, within this file?
        parent_vars = []
        for line in src_lines:
            m = ref_pat.match(line)
            if m:
                parent_vars.append(m.group(1))

        for pvar in parent_vars:
            # Is this parent var itself obj-$(CONFIG_...)  obj-y  obj-m?
            for line in src_lines:
                m = config_pat.match(line)
                if m and any(t == pvar + ".o" or t == pvar
                             for t in m.group(2).split()):
                    return m.group(1), pvar, src_dir
                m = builtin_pat.match(line)
                if m and any(t == pvar + ".o" or t == pvar
                             for t in m.group(1).split()):
                    return "BUILTIN", pvar, src_dir
                m = mod_pat.match(line)
                if m and any(t == pvar + ".o" or t == pvar
                             for t in m.group(1).split()):
                    return "MODULE", pvar, src_dir
            # Try one level deeper (e.g. gt-y → i915-y → obj-$(CONFIG_DRM_I915) via i915.o)
            # pvar like "i915-y" → strip trailing "-y"/"-m" → "i915" → look for i915.o
            base = re.sub(r'[-_][ym]$', '', pvar)
            for line in src_lines:
                m = config_pat.match(line)
                if m and any(t == base + ".o" or t == base
                             for t in m.group(2).split()):
                    return m.group(1), base, src_dir
                m = builtin_pat.match(line)
                if m and any(t == base + ".o" or t == base
                             for t in m.group(1).split()):
                    return "BUILTIN", base, src_dir
                m = mod_pat.match(line)
                if m and any(t == base + ".o" or t == base
                             for t in m.group(1).split()):
                    return "MODULE", base, src_dir
            # Recurse into the parent variable chain, rooted at the file
            # where pvar was actually found (keeps extra_files available so
            # the chain can keep hopping across files if needed).
            result, stem, resolved_dir = _resolve_via_variable(
                pvar, src_lines, visited, extra_files, own_dir=src_dir
            )
            if result:
                return result, stem, resolved_dir

    return None, None, None


def _resolve_object(obj_name, lines, visited=None, extra_files=None):
    if visited is None:
        visited = set()
    if obj_name in visited:
        return None
    visited.add(obj_name)
    result = _find_direct_mapping(obj_name, lines)
    if result:
        return result
    parent = _find_parent_object(obj_name, lines)
    if parent:
        result = _resolve_object(parent, lines, visited, extra_files)
        if result:
            return result
        # parent chain dead-ended — fall through to variable chain
    # Try variable-chain resolution (e.g. gt-y → i915-y → obj-$(CONFIG_DRM_I915))
    containing_vars = _find_var_containing_obj(obj_name, lines)
    for var in containing_vars:
        result, _stem, _dir = _resolve_via_variable(var, lines, extra_files=extra_files)
        if result:
            return result
    return None


def _find_dir_mapping(dirname, lines):
    config_pat  = re.compile(r'obj-\$\((CONFIG_[A-Za-z0-9_]+)\)\s*[:+]?=\s*(.+)')
    built_pat   = re.compile(r'obj-y\s*[:+]?=\s*(.+)')
    mod_pat     = re.compile(r'obj-m\s*[:+]?=\s*(.+)')
    subdir_pat  = re.compile(r'subdir-\$\((CONFIG_[A-Za-z0-9_]+)\)\s*[:+]?=\s*(.+)')
    targets = [dirname + "/", dirname]
    for line in lines:
        m = config_pat.search(line)
        if m and any(t in m.group(2).split() for t in targets):
            return m.group(1)
        m = built_pat.search(line)
        if m and any(t in m.group(1).split() for t in targets):
            return "BUILTIN"
        m = mod_pat.search(line)
        if m and any(t in m.group(1).split() for t in targets):
            return "MODULE"
        m = subdir_pat.search(line)
        if m and any(t in m.group(2).split() for t in targets):
            return m.group(1)
    return None


def _find_hostprog(obj_base, lines):
    pattern = re.compile(r'hostprogs\s*[:+]?=\s*(.+)')
    for line in lines:
        m = pattern.search(line)
        if m and obj_base in m.group(1).split():
            return True
    return False


def _is_sentinel(result):
    return result in ("BUILTIN", "MODULE")


def _resolve_directory_config_recursive(directory):
    current_dir = os.path.normpath(directory)
    while True:
        parent_dir = os.path.dirname(current_dir)
        if parent_dir == current_dir:
            break
        dirname  = os.path.basename(current_dir)
        kbuild   = os.path.join(parent_dir, "Kbuild")
        makefile = os.path.join(parent_dir, "Makefile")
        lines, source_file = [], None
        if os.path.exists(kbuild):
            lines, source_file = _join_lines(_read_makefile(kbuild)), kbuild
        elif os.path.exists(makefile):
            lines, source_file = _join_lines(_read_makefile(makefile)), makefile
        if lines:
            result = _find_dir_mapping(dirname, lines)
            if result:
                if _is_sentinel(result):
                    current_dir = parent_dir
                    continue
                return result, source_file
        current_dir = parent_dir
    return None, None


_ALWAYS_BUILTIN_DIRS = {"kernel", "lib"}


def _resolve_source_file(file_path):
    file_path  = os.path.normpath(file_path)
    filename   = os.path.basename(file_path)
    directory  = os.path.dirname(file_path)
    obj_name   = re.sub(r'\.(c|rs)$', '.o', filename)
    base_name  = re.sub(r'\.(c|rs)$', '',   filename)
    search_dir = directory
    passed_through_builtin_dir = False

    while True:
        kbuild   = os.path.join(search_dir, "Kbuild")
        makefile = os.path.join(search_dir, "Makefile")
        lines    = []
        if os.path.exists(kbuild):
            lines = _join_lines(_read_makefile(kbuild))
        elif os.path.exists(makefile):
            lines = _join_lines(_read_makefile(makefile))

        if lines:
            if _find_hostprog(base_name, lines):
                return None   # host program — skip

            result = _resolve_object(obj_name, lines)
            if result:
                if _is_sentinel(result):
                    config, _ = _resolve_directory_config_recursive(search_dir)
                    return config if config else ("obj-y" if result == "BUILTIN" else "obj-m")
                return result

            relative_obj = re.sub(r'\.(c|rs)$', '.o',
                                   os.path.relpath(file_path, search_dir))
            result = _resolve_object(relative_obj, lines)
            if result:
                if _is_sentinel(result):
                    config, _ = _resolve_directory_config_recursive(search_dir)
                    return config if config else ("obj-y" if result == "BUILTIN" else "obj-m")
                return result

            dirname = os.path.basename(search_dir)
            result  = _find_dir_mapping(dirname, lines)
            if result:
                if _is_sentinel(result):
                    config, _ = _resolve_directory_config_recursive(search_dir)
                    return config if config else ("obj-y" if result == "BUILTIN" else "obj-m")
                return result

        parent = os.path.dirname(search_dir)
        if parent == search_dir:
            break
        if os.path.basename(search_dir) in _ALWAYS_BUILTIN_DIRS:
            passed_through_builtin_dir = True
        search_dir = parent

    # Last-case fallback: check if the file's own directory is listed under
    # obj-y / obj-m / obj-$(CONFIG_*) in the immediate parent Makefile.
    # e.g. kernel/Makefile has "obj-y += sched/" but no entry for idle.o.
    parent_dir = os.path.dirname(directory)
    if parent_dir and parent_dir != directory:
        kbuild_p   = os.path.join(parent_dir, "Kbuild")
        makefile_p = os.path.join(parent_dir, "Makefile")
        plines = []
        if os.path.exists(kbuild_p):
            plines = _join_lines(_read_makefile(kbuild_p))
        elif os.path.exists(makefile_p):
            plines = _join_lines(_read_makefile(makefile_p))
        if plines:
            dir_result = _find_dir_mapping(os.path.basename(directory), plines)
            if dir_result == "BUILTIN":
                return "obj-y"
            if dir_result == "MODULE":
                return "obj-m"
            if dir_result:
                return dir_result

    # Final fallback: kernel/ and lib/ are always compiled as obj-y in the
    # Linux top-level Makefile.  If the walk-up passed through one of those
    # directories and nothing else resolved, the file is built-in.
    if passed_through_builtin_dir:
        return "obj-y"

    return None


def _resolve_directory_config(directory):
    dirname    = os.path.basename(os.path.normpath(directory))
    search_dir = os.path.dirname(os.path.normpath(directory))
    while True:
        kbuild   = os.path.join(search_dir, "Kbuild")
        makefile = os.path.join(search_dir, "Makefile")
        lines, source_file = [], None
        if os.path.exists(kbuild):
            lines, source_file = _join_lines(_read_makefile(kbuild)), kbuild
        elif os.path.exists(makefile):
            lines, source_file = _join_lines(_read_makefile(makefile)), makefile
        if lines:
            result = _find_dir_mapping(dirname, lines)
            if result:
                if _is_sentinel(result):
                    config, src = _resolve_directory_config_recursive(search_dir)
                    if config:
                        return config, src
                    return ("obj-y" if result == "BUILTIN" else "obj-m"), None
                return result, source_file
        parent = os.path.dirname(search_dir)
        if parent == search_dir:
            break
        dirname    = os.path.basename(search_dir)
        search_dir = parent
    return None, None


def resolve_config(file_path):
    """
    Return the CONFIG_ string for file_path, or None if unresolvable / not applicable.
    Only pure CONFIG_* strings are returned; all other messages become None.
    """
    if not os.path.exists(file_path):
        return None

    file_path = os.path.normpath(file_path)
    filename  = os.path.basename(file_path)
    directory = os.path.dirname(file_path)

    raw = None

    if filename.endswith(".c") or filename.endswith(".rs"):
        raw = _resolve_source_file(file_path)

    elif filename.endswith(".h"):
        c_counterpart = os.path.join(directory, filename[:-2] + ".c")
        if os.path.exists(c_counterpart):
            raw = _resolve_source_file(c_counterpart)

    elif filename in ("Makefile", "Kbuild", "Kconfig"):
        config, _ = _resolve_directory_config(directory)
        raw = config

    # Return only proper CONFIG_* tokens, or obj-y/obj-m builtin markers
    if raw and re.match(r'^CONFIG_[A-Za-z0-9_]+$', raw):
        return raw
    if raw in ("obj-y", "obj-m"):
        return raw
    return None


# ═══════════════════════════════════════════════════════════════════════════════
#  Kconfig symbol types (bool vs tristate) — a bool symbol can never become
#  its own module ('m' is meaningless for it); if a .config mistakenly sets
#  a bool CONFIG_ to 'm' it must be treated as 'y' instead. (Mirrors
#  KconfigTypes in find_module_claude.py, simplified: no arch-awareness.)
# ═══════════════════════════════════════════════════════════════════════════════

_KCONFIG_CFG_RE = re.compile(r'^\s*(?:menuconfig|config)\s+([A-Za-z0-9_]+)\s*$')
_KCONFIG_TYPE_RE = re.compile(r'^\s*(?:def_bool|def_tristate|bool|tristate|int|hex|string)\b')
_KCONFIG_TYPE_RANK = {"tristate": 3, "bool": 2, "int": 1, "hex": 1, "string": 1}

_kconfig_types_cache = {}


class _LazyKconfigTypes:
    """Defers the (multi-second) full-tree Kconfig scan until the first time
    a type is actually looked up via .get(), instead of paying the cost for
    every file even when no 'm' value ever needs sanity-checking.
    """

    def __init__(self, linux_src_path):
        self._linux_src_path = linux_src_path
        self._types = None

    def get(self, symbol):
        if self._types is None:
            self._types = _scan_kconfig_types(self._linux_src_path)
        return self._types.get(symbol)


def _scan_kconfig_types(linux_src_path):
    """Scan every Kconfig file under linux_src_path once, returning
    {CONFIG_NAME: 'bool'|'tristate'|'int'|'hex'|'string'}.
    """
    linux_src_path = os.path.abspath(linux_src_path)
    if linux_src_path in _kconfig_types_cache:
        return _kconfig_types_cache[linux_src_path]

    types = {}

    def _record(sym, t):
        old = types.get(sym)
        if old is None or _KCONFIG_TYPE_RANK.get(t, 0) > _KCONFIG_TYPE_RANK.get(old, 0):
            types[sym] = t

    for root, dirs, files in os.walk(linux_src_path):
        rel = os.path.relpath(root, linux_src_path)
        parts = [] if rel == '.' else rel.split(os.sep)
        if parts and parts[0] in ('.git', 'Documentation', 'tools', 'scripts', 'samples'):
            dirs[:] = []
            continue
        for fn in files:
            if not fn.startswith('Kconfig'):
                continue
            try:
                with open(os.path.join(root, fn), 'r', encoding='utf-8', errors='replace') as fh:
                    cur = None
                    for line in fh:
                        m = _KCONFIG_CFG_RE.match(line)
                        if m:
                            cur = m.group(1)
                            continue
                        if cur and _KCONFIG_TYPE_RE.match(line):
                            word = line.split()[0]
                            t = {'def_bool': 'bool', 'def_tristate': 'tristate'}.get(word, word)
                            _record('CONFIG_' + cur, t)
                            cur = None
            except OSError:
                pass

    _kconfig_types_cache[linux_src_path] = types
    return types


# ═══════════════════════════════════════════════════════════════════════════════
#  Tree-wide Makefile/Kbuild index — used to widen variable-chain resolution
#  (_resolve_via_variable) beyond the current file when a variable is folded
#  into an obj-y/obj-m/obj-$(CONFIG_X) rule in a *different* Makefile (e.g.
#  AMD's display driver funnels $(AMD_DISPLAY_FILES) into
#  drivers/gpu/drm/amd/amdgpu/Makefile). Not specific to any one driver:
#  any file whose object list is consumed by a sibling Makefile benefits.
# ═══════════════════════════════════════════════════════════════════════════════

_makefile_index_cache = {}


class _LazyMakefileIndex:
    """Defers the (multi-second) full-tree Makefile/Kbuild scan until the
    first time a variable-chain resolution actually needs to widen its
    search beyond the current file.
    """

    def __init__(self, linux_src_path):
        self._linux_src_path = linux_src_path
        self._files = None

    def get(self):
        if self._files is None:
            self._files = _scan_makefile_index(self._linux_src_path)
        return self._files


def _scan_makefile_index(linux_src_path):
    """Scan every Makefile/Kbuild file under linux_src_path once, returning
    a list of (dir_path, lines) tuples, where lines is the joined-lines
    list (same format _join_lines produces) and dir_path is the directory
    containing that Makefile/Kbuild (needed to report which directory a
    module actually builds from when its object list crosses files).
    """
    linux_src_path = os.path.abspath(linux_src_path)
    if linux_src_path in _makefile_index_cache:
        return _makefile_index_cache[linux_src_path]

    files = []
    for root, dirs, fnames in os.walk(linux_src_path):
        rel = os.path.relpath(root, linux_src_path)
        parts = [] if rel == '.' else rel.split(os.sep)
        if parts and parts[0] in ('.git', 'Documentation', 'tools', 'scripts', 'samples'):
            dirs[:] = []
            continue
        for fn in fnames:
            if fn in ('Makefile', 'Kbuild'):
                lines = _join_lines(_read_makefile(os.path.join(root, fn)))
                if lines:
                    files.append((root, lines))

    _makefile_index_cache[linux_src_path] = files
    return files


# ═══════════════════════════════════════════════════════════════════════════════
#  .config parsing (kernel .config → {CONFIG_NAME: 'y'/'m'/...})
# ═══════════════════════════════════════════════════════════════════════════════
def load_kernel_config(kconfig_path):
    cfg = {}
    if not kconfig_path or not os.path.isfile(kconfig_path):
        return cfg
    not_set_re = re.compile(r"^#\s+(CONFIG_[A-Za-z0-9_]+)\s+is not set")
    value_re   = re.compile(r"^(CONFIG_[A-Za-z0-9_]+)=(.+)$")
    with open(kconfig_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.rstrip()
            m = not_set_re.match(line)
            if m:
                cfg[m.group(1)] = "n"
                continue
            m = value_re.match(line)
            if m:
                cfg[m.group(1)] = m.group(2).strip('"')
    return cfg


# ═══════════════════════════════════════════════════════════════════════════════
#  Chain resolution: follow composite-object membership all the way up to the
#  top-level obj-$(CONFIG_X)/obj-y/obj-m rule, evaluating each level's CONFIG_
#  against the given .config. Built on the exact same primitives above
#  (_find_direct_mapping's patterns, _find_parent_object, _find_var_containing_obj,
#  _resolve_via_variable) — only the "keep the module/prefix name around and
#  keep walking" part is added, since kernel_commit_csv.py's resolve_config()
#  only needed the *first* CONFIG_ match for applicability purposes.
# ═══════════════════════════════════════════════════════════════════════════════

_CONFIG_PAT_NAMED = re.compile(
    r'([A-Za-z0-9_\-]+)-\$\((CONFIG_[A-Za-z0-9_]+)\)\s*[:+]?=\s*(.+)'
)
_BUILT_PAT = re.compile(r'obj-y\s*[:+]?=\s*(.+)')
_MOD_PAT = re.compile(r'obj-m\s*[:+]?=\s*(.+)')


def _find_direct_mapping_with_prefix(obj_name, lines):
    """Like _find_direct_mapping, but also returns which variable prefix the
    match came from: 'obj' for obj-y/obj-m/obj-$(CONFIG_X) rules, or the
    composite module name for '<modname>-$(CONFIG_X) += obj_name.o' rules.
    Returns (result, prefix) or (None, None).
    """
    def _token_match(token):
        return token == obj_name or token.endswith("/" + obj_name)
    for line in lines:
        m = _CONFIG_PAT_NAMED.search(line)
        if m and any(_token_match(t) for t in m.group(3).split()):
            return m.group(2), m.group(1)
        m = _BUILT_PAT.search(line)
        if m and any(_token_match(t) for t in m.group(1).split()):
            return "BUILTIN", "obj"
        m = _MOD_PAT.search(line)
        if m and any(_token_match(t) for t in m.group(1).split()):
            return "MODULE", "obj"
    return None, None


def resolve_module_chain(obj_name, lines, kernel_cfg, kconfig_types=None, seen=None, makefile_index=None, own_dir=None):
    """Resolve obj_name to ('builtin', None, resolved_dir) /
    ('module', stem, resolved_dir) / ('not_set', config, resolved_dir) /
    ('unknown', obj_name, None) by walking the composite membership chain
    within the same Makefile `lines`, widening to `makefile_index` (a
    _LazyMakefileIndex) if the chain needs to cross into a different
    Makefile. `resolved_dir` is the directory of the Makefile that actually
    contained the winning obj- rule (None means "same directory as the
    source file", i.e. no cross-file hop was needed).
    """
    if kconfig_types is None:
        kconfig_types = {}
    if seen is None:
        seen = set()
    if obj_name in seen:
        return ('unknown', obj_name, None, None)
    seen = seen | {obj_name}

    result, prefix = _find_direct_mapping_with_prefix(obj_name, lines)
    if result is not None:
        if result == "BUILTIN":
            return ('builtin', None, None, None)
        if result == "MODULE":
            return ('module', obj_name[:-2], None, None)
        # result is a CONFIG_* name
        val = kernel_cfg.get(result, 'n')
        if val == 'm' and kconfig_types.get(result) == 'bool':
            # A bool symbol can never really be 'm' -- a .config that sets
            # it that way is malformed; treat it as 'y' instead.
            val = 'y'
        if val == 'n':
            return ('not_set', result, result, None)
        if val == 'm':
            # Independent module named after the object itself, whether this
            # was obj-$(CONFIG_X) += obj_name.o (prefix == 'obj') or a
            # composite member that turns 'm' (prefix == module name).
            return ('module', obj_name[:-2], result, None)
        # val == 'y'
        if prefix == 'obj':
            return ('builtin', None, result, None)
        # Folded into the composite object <prefix>.o — resolve further.
        return resolve_module_chain(prefix + '.o', lines, kernel_cfg, kconfig_types, seen, makefile_index, own_dir)

    # No direct rule for obj_name. Try unconditional composite membership
    # (modname-y / modname-objs += obj_name.o).
    parent = _find_parent_object(obj_name, lines)
    if parent:
        return resolve_module_chain(parent, lines, kernel_cfg, kconfig_types, seen, makefile_index, own_dir)

    # Try variable-chain resolution (e.g. gt-y → i915-y → obj-$(CONFIG_DRM_I915)),
    # widening to the tree-wide index when the current file doesn't resolve it.
    extra_files = makefile_index.get() if makefile_index is not None else None
    for var in _find_var_containing_obj(obj_name, lines):
        result, stem, resolved_dir = _resolve_via_variable(
            var, lines, extra_files=extra_files, own_dir=own_dir
        )
        # `stem` is the actual top-level module name the chain resolved to
        # (e.g. "amdgpu"), which may differ from obj_name's own stem when
        # the object was folded into a composite module via one or more
        # variables/files. Fall back to obj_name's stem if stem is missing.
        module_stem = stem if stem else obj_name[:-2]
        # Only report resolved_dir when it actually differs from own_dir --
        # otherwise leave it None so callers keep using the source file's
        # own directory.
        report_dir = resolved_dir if resolved_dir and resolved_dir != own_dir else None
        if result == "BUILTIN":
            return ('builtin', None, None, report_dir)
        if result == "MODULE":
            return ('module', module_stem, None, report_dir)
        if result:
            val = kernel_cfg.get(result, 'n')
            if val == 'm' and kconfig_types.get(result) == 'bool':
                val = 'y'
            if val == 'n':
                continue
            if val == 'm':
                return ('module', module_stem, result, report_dir)
            return ('builtin', None, result, report_dir)

    return ('unknown', obj_name, None, None)


# ═══════════════════════════════════════════════════════════════════════════════
#  Top-level resolution: file -> vmlinux / module.ko
# ═══════════════════════════════════════════════════════════════════════════════

def find_module(rel_file_path, linux_src_path, config_path=None, kernel_cfg=None, kconfig_types=None, makefile_index=None):
    linux_src_path = os.path.abspath(linux_src_path)
    abs_file_path = os.path.join(linux_src_path, rel_file_path)

    if os.path.isdir(abs_file_path):
        raise IsADirectoryError(f"Skipping directory: {abs_file_path}")

    if not os.path.isfile(abs_file_path):
        raise FileNotFoundError(f"File not found: {abs_file_path}")

    if kernel_cfg is None:
        if config_path is None:
            default_config = os.path.join(linux_src_path, '.config')
            if os.path.isfile(default_config):
                config_path = default_config
        kernel_cfg = load_kernel_config(config_path)

    if kconfig_types is None:
        kconfig_types = _LazyKconfigTypes(linux_src_path)

    if makefile_index is None:
        makefile_index = _LazyMakefileIndex(linux_src_path)

    directory = os.path.dirname(rel_file_path)
    makefile_dir = os.path.join(linux_src_path, directory)
    filename = os.path.basename(rel_file_path)

    if filename.endswith('.h'):
        c_counterpart = os.path.join(makefile_dir, filename[:-2] + '.c')
        if not os.path.isfile(c_counterpart):
            # A header with no same-named .c file in its own directory is not
            # itself a build target -- it may be #included by many .c files
            # across different modules, so there is no single module answer.
            return ('header_only', None), None, config_path, None

    fallback_stem = re.sub(r'\.(c|rs)$', '', filename)
    obj_name = fallback_stem + '.o'

    # Walk up from the file's own directory to the source tree root, trying
    # resolve_module_chain() at each level. Most files are referenced by the
    # Makefile/Kbuild in their own directory, but some (e.g.
    # arch/x86/kvm/mmu/mmu.c, referenced as "mmu/mmu.o" by
    # arch/x86/kvm/Makefile) have no Makefile of their own and are only
    # listed -- by directory-relative token -- in an ancestor directory's
    # Makefile. resolve_module_chain() (unlike the legacy resolve_config()
    # fallback below) tracks the actual composite module stem through the
    # chain, so it must be tried at every level before falling back.
    search_dir = makefile_dir
    while True:
        lines = None
        for name in ('Makefile', 'Kbuild'):
            path = os.path.join(search_dir, name)
            if os.path.isfile(path):
                lines = _join_lines(_read_makefile(path))
                break

        if lines is not None:
            kind, value, chain_config, resolved_dir = resolve_module_chain(
                obj_name, lines, kernel_cfg, kconfig_types, makefile_index=makefile_index, own_dir=search_dir
            )
            if kind != 'unknown':
                if resolved_dir is None and search_dir != makefile_dir:
                    # The winning obj- rule lived in an ancestor directory's
                    # Makefile (the file has no Makefile of its own), so the
                    # module actually builds from that ancestor directory,
                    # not the source file's own directory.
                    resolved_dir = search_dir
                return (kind, value), chain_config, config_path, resolved_dir

        parent_dir = os.path.dirname(search_dir)
        if parent_dir == search_dir or not parent_dir.startswith(linux_src_path):
            break
        search_dir = parent_dir

    # Fallback: use the full directory-walking resolve_config() (handles
    # cases where the object isn't directly listed in its own directory's
    # Makefile, e.g. it's only referenced via the parent directory's obj-list).
    raw = resolve_config(abs_file_path)
    if raw is None:
        return ('unknown', None), raw, config_path, None
    if raw == 'obj-y':
        return ('builtin', None), raw, config_path, None
    if raw == 'obj-m':
        return ('module', fallback_stem), raw, config_path, None

    val = kernel_cfg.get(raw, 'n')
    if val == 'm' and kconfig_types.get(raw) == 'bool':
        val = 'y'
    if val == 'y':
        return ('builtin', None), raw, config_path, None
    if val == 'm':
        return ('module', fallback_stem), raw, config_path, None
    return ('not_set', raw), raw, config_path, None


def format_outcome(outcome, raw_config, directory=''):
    kind, value = outcome
    if kind == 'builtin':
        return "built into vmlinux (built-in)"
    if kind == 'module':
        ko_name = f"{value}.ko"
        return os.path.join(directory, ko_name) if directory else ko_name
    if kind == 'not_set':
        return f"not-compiled ({raw_config} is not set to y or m in the given .config)"
    if kind == 'header_only':
        return ("header-only file, not a build target on its own "
                "(it is #included by other .c files -- resolve those files instead)")
    return "unknown (could not resolve a CONFIG_ or built-in rule for this file)"


# ═══════════════════════════════════════════════════════════════════════════════
#  Multi-branch support: resolve each stable branch concurrently by giving
#  each one its own git worktree (a separate checkout sharing the same .git
#  objects), instead of taking turns force-checking-out one shared tree.
# ═══════════════════════════════════════════════════════════════════════════════

DEFAULT_BRANCHES = ["origin/linux-5.10.y", "origin/linux-6.1.y", "origin/linux-6.12.y"]


def _run_git(args_list, cwd):
    result = subprocess.run(
        ["git"] + args_list, cwd=cwd,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    return result.stdout.strip(), result.returncode, result.stderr.strip()


def _sparse_patterns_for_files(file_args):
    """Build git sparse-checkout patterns (non-cone, .gitignore-style) that
    cover everything find_module() needs: every Makefile/Kbuild/Kconfig* in
    the tree (for CONFIG_ resolution and the tree-wide Makefile/Kconfig-type
    scans), plus the directory of each requested file (so the file itself,
    and any same-directory header/source counterpart, is present).
    This is what makes worktree checkout fast -- a full kernel tree checkout
    copies every .c/.h file (the bulk of the tree's size); we only need the
    build-system files, which are tiny by comparison.
    """
    patterns = ["**/Makefile", "**/Kbuild", "**/Kconfig*"]
    for file_arg in file_args:
        file_dir = os.path.dirname(file_arg)
        patterns.append(f"{file_dir}/*" if file_dir else "/*")
    return patterns


def _add_worktree(branch, repo_dir, sparse_patterns=None):
    """Create a detached git worktree for `branch` in a fresh temp
    directory, so each branch can be resolved concurrently from its own
    checkout without the branches fighting over the same working tree.
    When `sparse_patterns` is given, the worktree is sparse-checked-out to
    just those patterns instead of materializing the entire tree, which is
    the dominant cost of creating a worktree for a huge repo like Linux.
    Returns the worktree path, or None on failure.
    """
    wt_path = os.path.join(tempfile.gettempdir(), f"find_module_wt_{uuid.uuid4().hex}")
    if sparse_patterns:
        _, rc, err = _run_git(
            ["worktree", "add", "--detach", "--no-checkout", wt_path, branch], repo_dir
        )
        if rc != 0:
            print(f"[ERROR] Failed to create worktree for {branch!r}:\n{err}", file=sys.stderr)
            return None
        _run_git(["sparse-checkout", "init", "--no-cone"], wt_path)
        _, rc, err = _run_git(["sparse-checkout", "set"] + sparse_patterns, wt_path)
        if rc != 0:
            print(f"[ERROR] Failed to set sparse-checkout for {branch!r}:\n{err}", file=sys.stderr)
        _, rc, err = _run_git(["checkout", branch], wt_path)
        if rc != 0:
            print(f"[ERROR] Failed to checkout {branch!r} in worktree:\n{err}", file=sys.stderr)
            return None
        return wt_path

    _, rc, err = _run_git(["worktree", "add", "--detach", wt_path, branch], repo_dir)
    if rc != 0:
        print(f"[ERROR] Failed to create worktree for {branch!r}:\n{err}", file=sys.stderr)
        return None
    return wt_path


def _remove_worktree(wt_path, repo_dir):
    """Remove a worktree created by _add_worktree(), best-effort."""
    _run_git(["worktree", "remove", "--force", wt_path], repo_dir)
    if os.path.isdir(wt_path):
        shutil.rmtree(wt_path, ignore_errors=True)


def _process_files(args, linux_src_abs, branch_label=None):
    """Run the file/config resolution loop against whatever tree is
    currently checked out at linux_src_abs. Returns (exit_code, lines),
    where `lines` is the list of output lines to print (buffered rather
    than printed directly, so callers running this in parallel threads
    can print each branch's output as one contiguous block).
    """
    config_paths = args.config if args.config else [None]

    # Resolve each config path once (default to <linux_src>/.config when None)
    # and pre-load its CONFIG_ values so we don't re-read the file per source file.
    resolved_configs = []
    for cfg_arg in config_paths:
        cfg_path = cfg_arg
        if cfg_path is None:
            default_config = os.path.join(linux_src_abs, '.config')
            if os.path.isfile(default_config):
                cfg_path = default_config
        resolved_configs.append((cfg_path, load_kernel_config(cfg_path)))

    # Kconfig type info (bool vs tristate) is only needed to sanity-check a
    # 'm' value; it's computed lazily on first use inside find_module() (and
    # cached), so passing None here avoids a multi-second full-tree Kconfig
    # scan before anything gets printed.
    kconfig_types = None
    # Each branch resolves against its own worktree path, so the tree-wide
    # Makefile/Kconfig caches (keyed by linux_src_abs) never collide across
    # branches -- no manual cache-clearing needed here.
    makefile_index = _LazyMakefileIndex(linux_src_abs)

    multiple_files = len(args.files) > 1
    multiple_configs = len(resolved_configs) > 1
    exit_code = 0
    out = []

    if branch_label:
        out.append(f"=== Branch: {branch_label} ===")

    for f_idx, file_arg in enumerate(args.files):
        if (multiple_files or multiple_configs) and f_idx > 0:
            out.append("")
        out.append(f"File:          {file_arg}")

        abs_check = os.path.join(linux_src_abs, file_arg)
        if os.path.isdir(abs_check):
            out.append(f"Skipped: {file_arg} is a directory, not a file.")
            continue

        for cfg_path, kernel_cfg in resolved_configs:
            try:
                outcome, raw_config, _, resolved_dir = find_module(
                    file_arg, linux_src_abs, config_path=cfg_path, kernel_cfg=kernel_cfg,
                    kconfig_types=kconfig_types, makefile_index=makefile_index
                )
            except FileNotFoundError as e:
                out.append(f"Error: {e}")
                exit_code = 1
                break

            if resolved_dir:
                # The module actually builds from a different directory than
                # the source file (e.g. its object list was folded into a
                # sibling driver's Makefile) -- report that directory
                # instead of the source file's own directory.
                file_dir = os.path.relpath(resolved_dir, linux_src_abs)
            else:
                file_dir = os.path.dirname(file_arg)
            cfg_label = cfg_path or '(none found - all conditional CONFIGs treated as unset)'
            if multiple_configs:
                out.append(f"  Config: {cfg_label}")
                out.append(f"    CONFIG_ found: {raw_config}")
                out.append(f"    Result: {format_outcome(outcome, raw_config, file_dir)}")
            else:
                out.append(f"CONFIG_ found: {raw_config}")
                out.append(f"Config used:   {cfg_label}")
                out.append("")
                out.append(f"Result: {format_outcome(outcome, raw_config, file_dir)}")

    return exit_code, out


def main():
    parser = argparse.ArgumentParser(
        description="Find which kernel module a source file is built into, "
                    "using the CONFIG_ resolution logic from kernel_commit_csv.py."
    )
    parser.add_argument(
        'files', nargs='+',
        help="One or more file paths relative to the Linux source tree, "
             "e.g. fs/ext4/acl.c mm/hwpoison-inject.c"
    )
    parser.add_argument('linux_src', help="Path to the Linux kernel source tree")
    parser.add_argument(
        '--config', nargs='+',
        help="One or more .config file paths (defaults to <linux_src>/.config). "
             "When multiple are given, each file is resolved against every config."
    )
    parser.add_argument(
        '--branches', nargs='+', default=DEFAULT_BRANCHES,
        help="Git refs to check out (one at a time) inside linux_src before "
             f"resolving. Defaults to: {' '.join(DEFAULT_BRANCHES)}. "
             "Pass --no-branches to skip checkout and use the currently "
             "checked-out tree as-is (old single-branch behaviour)."
    )
    parser.add_argument(
        '--no-branches', action='store_true',
        help="Do not check out any branch; resolve against whatever is "
             "currently checked out in linux_src (old single-branch behaviour)."
    )
    args = parser.parse_args()

    linux_src_abs = os.path.abspath(args.linux_src)

    if args.no_branches:
        exit_code, out = _process_files(args, linux_src_abs)
        print("\n".join(out))
        sys.exit(exit_code)

    is_git_repo = os.path.isdir(os.path.join(linux_src_abs, ".git"))
    if not is_git_repo:
        print(f"[WARN] {linux_src_abs} is not a git repo; ignoring --branches "
              "and resolving against the tree as-is.", file=sys.stderr)
        exit_code, out = _process_files(args, linux_src_abs)
        print("\n".join(out))
        sys.exit(exit_code)

    # Give each branch its own git worktree (a separate checkout sharing the
    # same .git objects) so the three branches can be resolved concurrently
    # instead of taking turns force-checking-out the same working tree.
    # Worktree creation (git worktree add + sparse-checkout + resolution) all
    # happens inside the thread pool, so the three branches' checkouts run
    # in parallel too, instead of being created one-by-one before any
    # resolution starts.
    sparse_patterns = _sparse_patterns_for_files(args.files)

    def _resolve_branch(branch):
        wt_path = _add_worktree(branch, linux_src_abs, sparse_patterns=sparse_patterns)
        if wt_path is None:
            return branch, 1, [f"=== Branch: {branch} ===", "[ERROR] Could not prepare worktree; skipped."], None
        rc, out = _process_files(args, wt_path, branch)
        return branch, rc, out, wt_path

    exit_code = 0
    worktree_paths = []
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, len(args.branches))) as pool:
            futures = [pool.submit(_resolve_branch, branch) for branch in args.branches]
            for future in concurrent.futures.as_completed(futures):
                branch, rc, out, wt_path = future.result()
                if wt_path:
                    worktree_paths.append(wt_path)
                exit_code = exit_code or rc
                # Print as soon as each branch finishes instead of waiting
                # for all three, so results show up incrementally.
                print("\n".join(out))
                print()
    finally:
        for wt_path in worktree_paths:
            _remove_worktree(wt_path, linux_src_abs)

    sys.exit(exit_code)


if __name__ == '__main__':
    main()
