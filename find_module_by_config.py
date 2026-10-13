#!/usr/bin/env python3
"""
find_module_by_config.py

Reverse of find_module_new.py: given one or more CONFIG_* options and the
path to a Linux kernel source tree, determine which kernel module(s) (.ko)
the option builds, or whether it is built into vmlinux.

No .config is needed. Whether an option can produce a module is decided from
its Kconfig type alone: a 'tristate' option gating `obj-$(CONFIG_X) += foo.o`
yields foo.ko (when =m, built-in when =y); a 'bool' option can only ever be
built in. Options that merely add objects to a composite module
(`ext4-$(CONFIG_EXT4_FS_POSIX_ACL) += acl.o`) are followed up the composite
chain to the module that owns them (ext4.ko, gated by CONFIG_EXT4_FS).

The Makefile/Kbuild parsing primitives (_find_direct_mapping_with_prefix,
_find_parent_object, _find_var_containing_obj, _resolve_via_variable, the
tree-wide Makefile index, worktree helpers) are imported from
find_module_new.py; this script only adds the CONFIG_ -> object lookup and a
config-less owner resolution on top.

Usage:
    python3 find_module_by_config.py <CONFIG_X> [<CONFIG_Y> ...] <linux_src_path>
            [--arch x86] [--sources] [--branches origin/linux-6.1.y ...]

Examples:
    python3 find_module_by_config.py CONFIG_EXT4_FS /home/user/linux-6.1.123
    python3 find_module_by_config.py EXT4_FS_POSIX_ACL CONFIG_E1000 /home/user/linux-6.1.123
"""

import argparse
import concurrent.futures
import multiprocessing
import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import find_module_new as fm  # noqa: E402


_SKIP_TOP_DIRS = ('.git', 'Documentation', 'tools', 'scripts', 'samples')

# Makefile variable prefixes that use a CONFIG_ but don't add objects to a
# module (compile flags, host tools, generated files, ...).
_HELPER_PREFIXES = {
    'hostprogs', 'hostprogs-always', 'userprogs', 'userprogs-always', 'always',
    'extra', 'targets', 'header-test', 'clean-files', 'mandatory', 'generic',
    'generated', 'dtb', 'dtbo', 'lib-ksyms', 'pi',
}
# arch/*/Makefile style lists that are linked straight into vmlinux.
_BUILTIN_LIST_PREFIXES = {'lib', 'core', 'libs', 'drivers', 'head', 'net', 'init'}

_COND_OPEN_RE = re.compile(r'^\s*(ifeq|ifneq|ifdef|ifndef)\b(.*)$')
_COND_ELSE_RE = re.compile(r'^\s*else\b')
_COND_END_RE = re.compile(r'^\s*endif\b')
_ASSIGN_RE = re.compile(r'^\s*([A-Za-z0-9_\-]+?)-(y|m|objs)\s*[:+]?=\s*(.+)$')


def _normalize_config(name):
    name = name.strip()
    return name if name.startswith('CONFIG_') else 'CONFIG_' + name


def _strip_comment(line):
    return line.split('#', 1)[0]


def _read_config_file(path):
    """One CONFIG_ option per line; blank lines and '#' comments are ignored."""
    names = []
    with open(path, 'r', encoding='utf-8', errors='replace') as fh:
        for line in fh:
            line = line.split('#', 1)[0].strip()
            if line:
                names.append(line.split()[0])
    return names


def _is_flag_prefix(prefix):
    return 'flags' in prefix.lower() or prefix.startswith((
        'CFLAGS', 'AFLAGS', 'LDFLAGS', 'KASAN', 'KCSAN', 'KCOV', 'UBSAN', 'KMSAN',
        'GCOV', 'OBJECT_FILES', 'CONTEXT_TRACKING', 'KBUILD',
    ))


def _stem(obj_token):
    return re.sub(r'\.o$', '', os.path.basename(obj_token))


# ═══════════════════════════════════════════════════════════════════════════════
#  Per-tree context: Kconfig types/locations, Makefile index, per-dir Makefiles
# ═══════════════════════════════════════════════════════════════════════════════

class TreeContext:
    def __init__(self, linux_src_path, git_repo=None, git_ref=None):
        self.src = os.path.abspath(linux_src_path)
        # When resolving a branch from a sparse worktree, .c/.h files are not
        # checked out, so source greps go through `git grep <ref>` instead.
        self.git_repo = git_repo
        self.git_ref = git_ref
        self._index = fm._LazyMakefileIndex(self.src)
        self._kconfig = None
        self._dir_lines = {}

    def index(self):
        return self._index.get()

    def dir_lines(self, directory):
        directory = os.path.normpath(directory)
        if directory not in self._dir_lines:
            lines = []
            for name in ('Kbuild', 'Makefile'):
                path = os.path.join(directory, name)
                if os.path.isfile(path):
                    lines = fm._join_lines(fm._read_makefile(path))
                    break
            self._dir_lines[directory] = lines
        return self._dir_lines[directory]

    def kconfig(self):
        """{CONFIG_NAME: {'type': 'bool'|'tristate'|..., 'files': [rel paths]}}"""
        if self._kconfig is None:
            self._kconfig = _scan_kconfig(self.src)
        return self._kconfig

    def ktype(self, config):
        entry = self.kconfig().get(config)
        return entry['type'] if entry else None

    def rel(self, path):
        return os.path.relpath(path, self.src)


def _scan_kconfig(linux_src_path):
    """Like find_module_new._scan_kconfig_types, but also records which
    Kconfig file(s) define each symbol (for reporting).
    """
    info = {}
    for root, dirs, files in os.walk(linux_src_path):
        rel = os.path.relpath(root, linux_src_path)
        parts = [] if rel == '.' else rel.split(os.sep)
        if parts and parts[0] in _SKIP_TOP_DIRS:
            dirs[:] = []
            continue
        for fn in files:
            if not fn.startswith('Kconfig'):
                continue
            path = os.path.join(root, fn)
            try:
                with open(path, 'r', encoding='utf-8', errors='replace') as fh:
                    cur = None
                    for line in fh:
                        m = fm._KCONFIG_CFG_RE.match(line)
                        if m:
                            cur = 'CONFIG_' + m.group(1)
                            entry = info.setdefault(cur, {'type': None, 'files': []})
                            relp = os.path.relpath(path, linux_src_path)
                            if relp not in entry['files']:
                                entry['files'].append(relp)
                            continue
                        if cur and fm._KCONFIG_TYPE_RE.match(line):
                            word = line.split()[0]
                            t = {'def_bool': 'bool', 'def_tristate': 'tristate'}.get(word, word)
                            old = info[cur]['type']
                            if old is None or fm._KCONFIG_TYPE_RANK.get(t, 0) > fm._KCONFIG_TYPE_RANK.get(old, 0):
                                info[cur]['type'] = t
                            cur = None
            except OSError:
                pass
    return info


# ═══════════════════════════════════════════════════════════════════════════════
#  Config-less owner resolution: which top-level module / vmlinux does an
#  object end up in? Mirrors find_module_new.resolve_module_chain, but instead
#  of evaluating each CONFIG_ against a .config it uses the Kconfig type
#  (tristate -> can be its own module, bool -> built-in).
# ═══════════════════════════════════════════════════════════════════════════════

def _owner(kind, stem, directory, gate):
    return {'kind': kind, 'stem': stem, 'dir': directory, 'gate': gate}


def _owner_for_config(config, prefix, stem, directory, ctx):
    if prefix in _BUILTIN_LIST_PREFIXES:
        return _owner('builtin', None, directory, config)
    if ctx.ktype(config) == 'bool':
        return _owner('builtin', None, directory, config)
    return _owner('module', stem, directory, config)


def resolve_owner(obj_name, lines, own_dir, ctx, seen=None, as_composite=False):
    """Resolve obj_name (e.g. 'ext4.o') within Makefile `lines` (living in
    own_dir) to an owner dict, or None if this Makefile doesn't know it.
    """
    seen = seen or set()
    if obj_name in seen:
        return None
    seen = seen | {obj_name}

    result, prefix = fm._find_direct_mapping_with_prefix(obj_name, lines)
    if result == 'BUILTIN':
        return _owner('builtin', None, own_dir, None)
    if result == 'MODULE':
        return _owner('module', _stem(obj_name), own_dir, None)
    if result:
        if prefix == 'obj' or prefix in _BUILTIN_LIST_PREFIXES:
            return _owner_for_config(result, prefix, _stem(obj_name), own_dir, ctx)
        # <composite>-$(CONFIG_Y) += obj_name -> keep walking up via <composite>.o
        owner = resolve_owner(_composite_name(prefix) + '.o', lines, own_dir, ctx, seen, True)
        if owner:
            return owner

    parent = fm._find_parent_object(obj_name, lines)
    if parent and parent != 'obj.o':
        owner = resolve_owner(parent, lines, own_dir, ctx, seen, True)
        if owner:
            return owner

    variables = fm._find_var_containing_obj(obj_name, lines)
    if as_composite:
        # A composite like 'gt' may only ever be referenced as $(gt-y).
        variables.append(_stem(obj_name) + '-y')
    for var in variables:
        res, stem, rdir = fm._resolve_via_variable(
            var, lines, extra_files=ctx.index(), own_dir=own_dir
        )
        if not res:
            continue
        rdir = rdir or own_dir
        stem = stem or _stem(obj_name)
        if res == 'BUILTIN':
            return _owner('builtin', None, rdir, None)
        if res == 'MODULE':
            return _owner('module', stem, rdir, None)
        return _owner_for_config(res, 'obj', stem, rdir, ctx)
    return None


def resolve_owner_from_dir(obj_name, start_dir, ctx, as_composite=False):
    """Try resolve_owner() in start_dir's Makefile and then every ancestor's
    (some objects are only listed by an ancestor, e.g. "mmu/mmu.o").
    """
    search_dir = os.path.normpath(start_dir)
    while search_dir.startswith(ctx.src):
        lines = ctx.dir_lines(search_dir)
        if lines:
            owner = resolve_owner(obj_name, lines, search_dir, ctx, as_composite=as_composite)
            if owner:
                return owner
        parent = os.path.dirname(search_dir)
        if parent == search_dir:
            break
        search_dir = parent
    return None


def _composite_name(prefix):
    return re.sub(r'-(objs|y|m)$', '', prefix)


# ═══════════════════════════════════════════════════════════════════════════════
#  CONFIG_ -> Makefile rules
# ═══════════════════════════════════════════════════════════════════════════════

def _cond_polarity(keyword, rest, config):
    """For an `ifeq/ifneq/ifdef/ifndef` line mentioning `config`, return
    'pos' if its if-branch is taken when config is enabled, 'neg' if its
    else-branch is, or None if the line doesn't test config.
    """
    if not re.search(r'\b' + re.escape(config) + r'\b', rest):
        return None
    if keyword == 'ifdef':
        return 'pos'
    if keyword == 'ifndef':
        return 'neg'
    args = re.findall(r'"([^"]*)"|\'([^\']*)\'', rest)
    if args:
        args = [a or b for a, b in args]
    else:
        m = re.search(r'\((.*),(.*)\)', rest)
        args = [m.group(1), m.group(2)] if m else []
    if len(args) != 2:
        return 'pos' if keyword == 'ifeq' else 'neg'
    other = (args[1] if config in args[0] else args[0]).strip()
    enabled_match = bool(other) and set(other) <= {'y', 'm'}
    if keyword == 'ifeq':
        return 'pos' if enabled_match else 'neg'
    return 'neg' if enabled_match else 'pos'


def find_config_rules(config, ctx):
    """Every Makefile/Kbuild rule that `config` controls. Returns a list of
    dicts: {dir, prefix, suffix, tokens, text}. `suffix` is None for
    `<prefix>-$(CONFIG_X)` rules, or 'y'/'m'/'objs' for `<prefix>-y` style
    assignments found inside an `ifdef CONFIG_X` / `ifeq ($(CONFIG_X),y)` block.
    """
    direct_re = re.compile(r'([A-Za-z0-9_\-]+)-\$\(' + re.escape(config) + r'\)\s*[:+]?=\s*(.*)')
    rules = []
    for directory, lines in ctx.index():
        stack = []
        for raw in lines:
            line = _strip_comment(raw)
            m = _COND_OPEN_RE.match(line)
            if m:
                stack.append(_cond_polarity(m.group(1), m.group(2), config))
                continue
            if _COND_ELSE_RE.match(line):
                if stack and stack[-1]:
                    stack[-1] = 'neg' if stack[-1] == 'pos' else 'pos'
                # `else ifeq (...)` opens a nested-style chained condition
                chained = _COND_OPEN_RE.match(line.split('else', 1)[1])
                if chained and stack:
                    stack[-1] = _cond_polarity(chained.group(1), chained.group(2), config) or (
                        'neg' if stack[-1] == 'pos' else stack[-1])
                continue
            if _COND_END_RE.match(line):
                if stack:
                    stack.pop()
                continue

            m = direct_re.search(line)
            if m:
                rules.append({'dir': directory, 'prefix': m.group(1), 'suffix': None,
                              'tokens': m.group(2).split(), 'text': raw.strip()})
                continue
            if 'pos' in stack:
                m = _ASSIGN_RE.match(line)
                if m:
                    rules.append({'dir': directory, 'prefix': m.group(1), 'suffix': m.group(2),
                                  'tokens': m.group(3).split(), 'text': raw.strip() + '   [inside if-block]'})
    return rules


# ═══════════════════════════════════════════════════════════════════════════════
#  Rule -> results
# ═══════════════════════════════════════════════════════════════════════════════

def _result(kind, path, note, gate=None):
    return {'kind': kind, 'path': path, 'note': note, 'gate': gate}


def _leaf_result(token, directory, config, ctx, forced_kind=None):
    obj_dir = os.path.normpath(os.path.join(directory, os.path.dirname(token)))
    kind = forced_kind or ('builtin' if ctx.ktype(config) == 'bool' else 'module')
    if kind == 'builtin':
        return _result('builtin', ctx.rel(os.path.join(obj_dir, token.split('/')[-1])),
                       '', config)
    return _result('module', ctx.rel(os.path.join(obj_dir, _stem(token) + '.ko')),
                   'own module', config)


def _owner_result(owner, member, config, ctx):
    if owner is None:
        return None
    via = f"{member} folded into"
    if owner['kind'] == 'builtin':
        gate = f" (gated by {owner['gate']})" if owner['gate'] else ''
        return _result('builtin', ctx.rel(owner['dir']) + '/',
                       f"{via} built-in code{gate}", owner['gate'])
    path = ctx.rel(os.path.join(owner['dir'], owner['stem'] + '.ko'))
    if owner['gate'] and owner['gate'] != config:
        note = f"{via} {owner['stem']}.o, module governed by {owner['gate']}"
    else:
        note = f"{via} {owner['stem']}.o"
    return _result('module', path, note, owner['gate'])


def descend_directory(directory, config, ctx, results, gates, seen_dirs):
    """`obj-$(CONFIG_X) += foo/`: everything built from foo/ needs CONFIG_X.
    Collect the unconditional objects of that directory (and recurse into
    its unconditional subdirectories); objects gated by further CONFIG_s are
    reported as sub-options.
    """
    directory = os.path.normpath(directory)
    if directory in seen_dirs:
        return
    seen_dirs.add(directory)
    lines = ctx.dir_lines(directory)
    if not lines:
        results.append(_result('directory', ctx.rel(directory) + '/',
                               'directory has no Makefile/Kbuild', config))
        return

    found = False
    other_re = re.compile(r'^\s*obj-\$\((CONFIG_[A-Za-z0-9_]+)\)\s*[:+]?=')
    dir_gates = set()
    for raw in lines:
        line = _strip_comment(raw)
        m = re.match(r'^\s*obj-(y|m)\s*[:+]?=\s*(.+)$', line)
        if m:
            for tok in m.group(2).split():
                if tok.startswith('$'):
                    continue
                if tok.endswith('/'):
                    descend_directory(os.path.join(directory, tok), config, ctx, results, gates, seen_dirs)
                    found = True
                elif tok.endswith('.o'):
                    kind = 'module' if m.group(1) == 'm' else (
                        'builtin' if ctx.ktype(config) == 'bool' else 'module')
                    results.append(_leaf_result(tok, directory, config, ctx, kind))
                    found = True
            continue
        m = other_re.match(line)
        if m:
            if m.group(1) == config:
                found = True  # resolved by find_config_rules() on its own
            else:
                dir_gates.add(m.group(1))
    if found:
        return
    if dir_gates:
        # Nothing built here by CONFIG_X alone (e.g. a vendor/menu option):
        # list the options that actually select modules in this directory.
        gates.setdefault(ctx.rel(directory) + '/', set()).update(dir_gates)
    else:
        results.append(_result('directory', ctx.rel(directory) + '/',
                               'enables directory (no objects resolved)', config))


def resolve_rules(config, rules, ctx):
    results, gates, other = [], {}, []
    seen_dirs = set()
    for rule in rules:
        prefix, directory = rule['prefix'], rule['dir']
        tokens = [t for t in rule['tokens'] if not t.startswith('$')]

        if _is_flag_prefix(prefix) or prefix in _HELPER_PREFIXES:
            other.append(rule)
            continue

        if prefix in ('obj', 'subdir') or prefix in _BUILTIN_LIST_PREFIXES:
            forced = None
            if prefix in _BUILTIN_LIST_PREFIXES:
                forced = 'builtin'
            elif rule['suffix'] == 'm':
                forced = 'module'
            elif rule['suffix'] == 'y':
                forced = 'builtin'
            for tok in tokens:
                if tok.endswith('/'):
                    base = ctx.src if prefix in ('core', 'libs', 'drivers', 'head', 'net', 'init') else directory
                    descend_directory(os.path.join(base, tok), config, ctx, results, gates, seen_dirs)
                elif tok.endswith('.o'):
                    results.append(_leaf_result(tok, directory, config, ctx, forced))
            continue

        # <composite>-$(CONFIG_X) += a.o b.o  -> owner of <composite>.o
        if not any(t.endswith('.o') for t in tokens) and not any(
                t.startswith('$') for t in rule['tokens']):
            other.append(rule)  # plain variable, e.g. smp-flag-$(CONFIG_SMP) := SMP
            continue
        composite = _composite_name(prefix)
        owner = resolve_owner_from_dir(composite + '.o', directory, ctx, as_composite=True)
        members = [os.path.basename(t) for t in tokens if t.endswith('.o')]
        member_text = ' '.join(members[:3]) + (f" (+{len(members) - 3} more)" if len(members) > 3 else '')
        res = _owner_result(owner, member_text or f"$(...) objects of {composite}-y", config, ctx)
        if res:
            results.append(res)
        else:
            results.append(_result('unknown', ctx.rel(directory) + '/',
                                   f"objects added to '{composite}' (owner not resolved)", None))
    return _dedupe(results), gates, other


def _dedupe(results):
    seen, out = set(), []
    for r in results:
        key = (r['kind'], r['path'])
        if key not in seen:
            seen.add(key)
            out.append(r)
    return out


# ═══════════════════════════════════════════════════════════════════════════════
#  Source-reference fallback: CONFIG_X used only via #ifdef / IS_ENABLED()
# ═══════════════════════════════════════════════════════════════════════════════

def grep_sources(config, ctx):
    if ctx.git_ref:
        cmd = ['git', 'grep', '-l', '-w', config, ctx.git_ref, '--', '*.c', '*.h']
        cwd = ctx.git_repo
    else:
        cmd = ['grep', '-rlw', '--include=*.c', '--include=*.h', config, '.']
        cwd = ctx.src
    proc = subprocess.run(cmd, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    files = []
    for line in proc.stdout.splitlines():
        if ctx.git_ref and line.startswith(ctx.git_ref + ':'):
            line = line[len(ctx.git_ref) + 1:]
        line = os.path.normpath(line)
        if line.split(os.sep)[0] in _SKIP_TOP_DIRS:
            continue
        files.append(line)
    return sorted(files)


def resolve_source_file(rel_path, ctx):
    obj = re.sub(r'\.c$', '.o', os.path.basename(rel_path))
    owner = resolve_owner_from_dir(obj, os.path.join(ctx.src, os.path.dirname(rel_path)), ctx)
    if owner is None:
        return _result('unknown', None, 'owner not resolved')
    if owner['kind'] == 'builtin':
        return _result('builtin', 'vmlinux', f"gated by {owner['gate']}" if owner['gate'] else 'obj-y')
    note = f"governed by {owner['gate']}" if owner['gate'] else 'obj-m'
    return _result('module', ctx.rel(os.path.join(owner['dir'], owner['stem'] + '.ko')), note)


# ═══════════════════════════════════════════════════════════════════════════════
#  Output
# ═══════════════════════════════════════════════════════════════════════════════

def _arch_ok(path, arch):
    if not arch or not path:
        return True
    parts = path.split('/')
    return not (parts[0] == 'arch' and len(parts) > 1 and parts[1] != arch)


def process_config(config, ctx, arch=None, with_sources=False, max_files=20):
    out = [f"CONFIG:        {config}"]
    kinfo = ctx.kconfig().get(config)
    if kinfo:
        out.append(f"Kconfig:       {kinfo['type'] or 'unknown type'}  ({', '.join(kinfo['files'])})")
    else:
        out.append("Kconfig:       not defined in any Kconfig file of this tree")

    rules = [r for r in find_config_rules(config, ctx) if _arch_ok(ctx.rel(r['dir']), arch)]
    results, gates, other = resolve_rules(config, rules, ctx)
    results = [r for r in results if _arch_ok(r['path'], arch)]

    if rules:
        out.append("Makefile refs:")
        for r in rules:
            text = ' '.join(r['text'].split())
            if len(text) > 140:
                text = text[:137] + '...'
            out.append(f"  {ctx.rel(r['dir'])}: {text}")
    else:
        out.append("Makefile refs: none")

    out.append("")
    modules = [r for r in results if r['kind'] == 'module']
    builtins = [r for r in results if r['kind'] == 'builtin']
    misc = [r for r in results if r['kind'] in ('directory', 'unknown')]

    if modules or builtins or misc or gates:
        out.append("Result:")
        tristate = ctx.ktype(config) == 'tristate'
        for r in modules:
            suffix = ''
            if r['gate'] == config and tristate:
                suffix = f"  ({config}=m; built into vmlinux when =y)"
            elif r['gate'] and r['gate'] != config:
                suffix = f"  (when {r['gate']}=m)"
            out.append(f"  {r['path']}  [{r['note']}]{suffix}")
        for r in builtins:
            out.append(f"  built into vmlinux: {r['path']}" + (f"  [{r['note']}]" if r['note'] else ''))
        for r in misc:
            out.append(f"  {r['kind']}: {r['path']}  [{r['note']}]")
        for d, cfgs in sorted(gates.items()):
            cfgs = sorted(cfgs)
            shown = ', '.join(cfgs[:15]) + (f", ... (+{len(cfgs) - 15})" if len(cfgs) > 15 else '')
            out.append(f"  enables directory {d} -- its objects need further options: {shown}")
    if other and not (modules or builtins or misc or gates):
        out.append("Result: no objects -- only compile flags / build helpers use this option")

    if with_sources or not rules or not (modules or builtins or misc or gates):
        files = [f for f in grep_sources(config, ctx) if _arch_ok(f, arch)]
        c_files = [f for f in files if f.endswith('.c')]
        h_count = len(files) - len(c_files)
        if not files:
            if not (modules or builtins or misc or gates or other):
                out.append("Result: unknown (no Makefile rule and no source references found)")
        else:
            out.append(f"Source refs:   {len(c_files)} .c file(s), {h_count} header(s) "
                       "reference it via #ifdef/IS_ENABLED():")
            grouped = {}
            for f in c_files:
                r = resolve_source_file(f, ctx)
                label = (r['path'] or 'unknown') + (f"  [{r['note']}]" if r['note'] else '')
                grouped.setdefault(label, []).append(f)
            for label, fl in sorted(grouped.items(), key=lambda kv: -len(kv[1])):
                out.append(f"  {label}")
                for f in fl[:max_files]:
                    out.append(f"      {f}")
                if len(fl) > max_files:
                    out.append(f"      ... (+{len(fl) - max_files} more)")
    return out


_WORK = {}


def _work(key, cfg):
    ctx, args = _WORK[key]
    return process_config(cfg, ctx, arch=args.arch, with_sources=args.sources,
                          max_files=args.max_files)


def _process_all(configs, ctx, args, branch_label=None):
    out = [f"=== Branch: {branch_label} ==="] if branch_label else []
    jobs = max(1, min(args.jobs or os.cpu_count() or 1, len(configs)))
    if jobs > 1:
        # Build the expensive shared state once; forked workers inherit it.
        ctx.index()
        ctx.kconfig()
        key = id(ctx)
        _WORK[key] = (ctx, args)
        try:
            mp_ctx = multiprocessing.get_context('fork')
            with concurrent.futures.ProcessPoolExecutor(max_workers=jobs, mp_context=mp_ctx) as pool:
                blocks = list(pool.map(_work, [key] * len(configs), configs))
        finally:
            _WORK.pop(key, None)
    else:
        blocks = [process_config(cfg, ctx, arch=args.arch, with_sources=args.sources,
                                 max_files=args.max_files) for cfg in configs]
    for i, block in enumerate(blocks):
        if i:
            out.append("")
        out.extend(block)
    return out


def main():
    parser = argparse.ArgumentParser(
        description="Find which kernel module(s) a CONFIG_ option builds, using only "
                    "the Linux source tree (no .config needed)."
    )
    parser.add_argument('configs', nargs='*',
                        help="Zero or more CONFIG_ options (the CONFIG_ prefix is optional), "
                             "e.g. CONFIG_EXT4_FS E1000. The LAST positional is the kernel tree path.")
    parser.add_argument('--config-file', nargs='+', metavar='FILE',
                        help="Text file(s) with one CONFIG_ option per line "
                             "(blank lines and # comments ignored)")
    parser.add_argument('--arch', help="Ignore rules under arch/<other>/ (e.g. --arch x86)")
    parser.add_argument('--sources', action='store_true',
                        help="Always list .c files referencing the option via #ifdef/IS_ENABLED() "
                             "(by default only done when no Makefile rule builds objects)")
    parser.add_argument('-j', '--jobs', type=int, default=None,
                        help="Parallel worker processes for CONFIG lookups (default: CPU count)")
    parser.add_argument('--max-files', type=int, default=20,
                        help="Max source files listed per module in the source-refs section")
    parser.add_argument('--branches', nargs='+',
                        help="Git refs to resolve in parallel (each in its own sparse worktree), "
                             "e.g. origin/linux-6.1.y. Default: use the tree as-is.")
    args = parser.parse_args()

    if not args.configs:
        parser.error("the Linux source tree path is required")
    args.linux_src = args.configs.pop()

    linux_src_abs = os.path.abspath(args.linux_src)
    if not os.path.isdir(linux_src_abs):
        print(f"Error: {linux_src_abs} is not a directory", file=sys.stderr)
        sys.exit(1)

    raw_configs = list(args.configs)
    for path in args.config_file or []:
        try:
            raw_configs.extend(_read_config_file(path))
        except OSError as e:
            print(f"Error: cannot read {path}: {e}", file=sys.stderr)
            sys.exit(1)
    if not raw_configs:
        parser.error("give at least one CONFIG_ option or --config-file")
    configs = list(dict.fromkeys(_normalize_config(c) for c in raw_configs))

    if not args.branches:
        print("\n".join(_process_all(configs, TreeContext(linux_src_abs), args)))
        return

    if not os.path.isdir(os.path.join(linux_src_abs, '.git')):
        print(f"[WARN] {linux_src_abs} is not a git repo; ignoring --branches.", file=sys.stderr)
        print("\n".join(_process_all(configs, TreeContext(linux_src_abs), args)))
        return

    # Only build-system files are needed from each branch; source greps use git grep <ref>.
    sparse_patterns = ["**/Makefile", "**/Kbuild", "**/Kconfig*"]

    def _resolve_branch(branch):
        wt_path = fm._add_worktree(branch, linux_src_abs, sparse_patterns=sparse_patterns)
        if wt_path is None:
            return 1, [f"=== Branch: {branch} ===", "[ERROR] Could not prepare worktree; skipped."], None
        ctx = TreeContext(wt_path, git_repo=linux_src_abs, git_ref=branch)
        return 0, _process_all(configs, ctx, args, branch), wt_path

    exit_code, worktrees = 0, []
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(args.branches)) as pool:
            for future in concurrent.futures.as_completed(
                    [pool.submit(_resolve_branch, b) for b in args.branches]):
                rc, out, wt_path = future.result()
                if wt_path:
                    worktrees.append(wt_path)
                exit_code = exit_code or rc
                print("\n".join(out))
                print()
    finally:
        for wt_path in worktrees:
            fm._remove_worktree(wt_path, linux_src_abs)
    sys.exit(exit_code)


if __name__ == '__main__':
    main()
