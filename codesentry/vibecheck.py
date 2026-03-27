"""
codesentry — AI code risk scanner  v1.0.0
Scans AI-generated code for security issues before they reach git.

Default: scan last commit -> print table -> exit. Zero questions. Zero blocking.

USAGE
  codesentry check             scan last commit, print table, exit
  codesentry check --autofix   also generate copy-paste fix prompts
  codesentry check --narrate   plain-English diff explanation  (needs GROQ_API_KEY)
  codesentry check --explain   interactive line explainer      (needs GROQ_API_KEY)
  codesentry check --strict    also fail on MED issues
  codesentry check --compact   one line per issue  (CI-friendly)
  codesentry check --commits 3 scan last 3 commits
  codesentry check path/to/repo scan a specific directory

SUPPRESS FALSE POSITIVES  (add to any line)
  url = "http://localhost:3000"   # codesentry-ignore
  key = os.getenv("KEY")         # codesentry-ignore: P1

CONFIG  (.codesentry in project root or ~/)
  mode    = dev        # eli5 | beginner | dev  (default: dev)
  strict  = false
  compact = false
"""

__version__ = "1.0.0"

import os
import re
import sys
import ast
import json
import math
import hashlib
import datetime
import subprocess
from collections import defaultdict
from dataclasses import dataclass, field

# stdout encoding guard (Windows-safe)
try:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.align import Align
from rich import box

# CI detection: disable rich colour when stdout is not a TTY
IS_TTY = sys.stdout.isatty()


def make_console():
    """Return a Console that strips markup when running in CI / piped output."""
    return Console(no_color=not IS_TTY, highlight=False)


def _print_version(ctx, _param, value):
    """Click eager callback for --version."""
    if not value or ctx.resilient_parsing:
        return
    click.echo(f"codesentry {__version__}")
    ctx.exit()


# ─────────────────────────────────────────────────────────────────────────────
# CONFIG  — read once from .codesentry, never ask interactively
# ─────────────────────────────────────────────────────────────────────────────

def load_config(path):
    cfg = {}
    for candidate in [
        os.path.join(path, ".codesentry"),
        os.path.join(os.path.expanduser("~"), ".codesentry"),
    ]:
        if os.path.isfile(candidate):
            try:
                with open(candidate, "r", encoding="utf-8") as fh:
                    for line in fh:
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        if "=" in line:
                            k, _, v = line.partition("=")
                            cfg[k.strip().lower()] = v.strip().lower()
            except OSError:
                pass
            break
    return cfg


# ─────────────────────────────────────────────────────────────────────────────
# GROQ IMPORT HELPER  — friendly error instead of raw ModuleNotFoundError
# ─────────────────────────────────────────────────────────────────────────────

def _get_groq_client(api_key, console):
    """Return a Groq client or None with a helpful install hint. Never raises."""
    try:
        from groq import Groq
        return Groq(api_key=api_key)
    except ImportError:
        console.print(
            "[yellow]groq package not installed.[/yellow]\n"
            "[dim]Run:  pip install groq[/dim]"
        )
        return None
    except Exception as e:
        console.print(f"[yellow]Could not initialise Groq client: {e}[/yellow]")
        return None


# ─────────────────────────────────────────────────────────────────────────────
# INLINE SUPPRESSION  — # codesentry-ignore  or  # codesentry-ignore: P1,P2
# ─────────────────────────────────────────────────────────────────────────────

def _parse_ignore_ids(line_text):
    m = re.search(r"codesentry-ignore(?::\s*([A-Za-z0-9_,\s]+))?", line_text, re.IGNORECASE)
    if not m:
        return set()
    if m.group(1):
        return {p.strip().upper() for p in m.group(1).split(",")}
    return {"*"}


def _build_ignore_map(raw_lines):
    result = {}
    for i, line in enumerate(raw_lines, 1):
        ids = _parse_ignore_ids(line)
        if ids:
            result[i] = ids
    return result


def _is_suppressed(issue_id, lineno, ignore_map):
    ids = ignore_map.get(lineno, set())
    return "*" in ids or issue_id in ids


# ─────────────────────────────────────────────────────────────────────────────
# OFFLINE TEXT HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def _strip_comments(text, ext):
    """Blank comment-only lines so patterns don't fire on docs. Preserves line count."""
    lines = text.splitlines()
    out, in_ml = [], False
    for line in lines:
        s = line.strip()
        if ext == ".py":
            trips = s.count('"""') + s.count("'''")
            if trips % 2 == 1:
                in_ml = not in_ml
            if in_ml or s.startswith("#") or s.startswith('"""') or s.startswith("'''"):
                out.append("")
                continue
        elif ext in (".js", ".ts", ".jsx", ".tsx") and s.startswith("//"):
            out.append("")
            continue
        out.append(line)
    return "\n".join(out)


def _join_continuations(text):
    """Merge lines ending with backslash or inside unclosed parens/brackets."""
    lines = text.splitlines()
    result, buf, depth = [], "", 0
    for line in lines:
        depth += line.count("(") + line.count("[") - line.count(")") - line.count("]")
        if line.endswith("\\") or depth > 0:
            buf += line.rstrip("\\") + " "
        else:
            result.append(buf + line)
            buf = ""
            depth = max(0, depth)
    if buf:
        result.append(buf)
    return "\n".join(result)


def _shannon_entropy(s):
    if not s:
        return 0.0
    freq = defaultdict(int)
    for c in s:
        freq[c] += 1
    n = len(s)
    return -sum((v / n) * math.log2(v / n) for v in freq.values())


def _has_high_entropy_secret(line):
    tokens = re.findall(r"['\"]([A-Za-z0-9+/=_\-\.]{20,})['\"]", line)
    return any(_shannon_entropy(t) > 4.5 for t in tokens)


# ─────────────────────────────────────────────────────────────────────────────
# PATH CLASSIFIERS
# ─────────────────────────────────────────────────────────────────────────────

_TEST_DIRS = {"test","tests","spec","specs","fixtures","fixture","__mocks__","mocks"}
_TEMPLATE_SUFFIXES = (".example", ".sample", ".template", ".dist")

def _is_test_path(fp):
    return any(p in _TEST_DIRS for p in fp.replace("\\", "/").lower().split("/"))

def _is_template_file(fp):
    return os.path.basename(fp).lower().endswith(_TEMPLATE_SUFFIXES)

def _adjust_severity(severity, fp):
    if not _is_test_path(fp):
        return severity
    order = ["HIGH", "MED", "LOW"]
    return order[min(order.index(severity) + 1, 2)] if severity in order else "LOW"


# ─────────────────────────────────────────────────────────────────────────────
# DUPLICATE FUNCTION DETECTION  — cross-file, fully offline
# ─────────────────────────────────────────────────────────────────────────────

_DUP_ALLOWLIST = {
    "main","init","setup","test","run","get","set","add","load","save",
    "create","update","delete","handle","parse","build","start","stop",
    "close","open","read","write","send","receive","connect","disconnect",
    "login","logout","check","validate","format","render","show","hide",
    "enable","disable","reset","clear","clean","export","process","execute",
    "call","fetch","apply","bind","wrap","merge","split","join","filter",
    "reduce","map","sort","find","index","count","size","length","push",
    "pop","shift","unshift","append","remove","insert","replace","copy",
}
_DUP_MIN_LEN = 5


def scan_duplicate_functions(files_to_scan, path):
    func_locs = defaultdict(list)
    for f in files_to_scan:
        if os.path.splitext(f)[1].lower() not in (".py",".js",".ts",".jsx",".tsx"):
            continue
        full = os.path.join(path, f)
        if not os.path.isfile(full):
            continue
        try:
            with open(full, "r", encoding="utf-8", errors="ignore") as fh:
                for lineno, line in enumerate(fh, 1):
                    m = re.match(
                        r"\s*(?:def|function|const|let|var)\s+"
                        r"([A-Za-z_][A-Za-z0-9_]+)\s*[\(=]", line,
                    )
                    if m:
                        name = m.group(1)
                        if len(name) >= _DUP_MIN_LEN and name.lower() not in _DUP_ALLOWLIST:
                            func_locs[name].append((f, lineno))
        except OSError:
            continue

    issues = []
    for name, locs in func_locs.items():
        if len(locs) > 1:
            for fpath, lineno in locs:
                others = ", ".join(fp for fp, _ in locs if fp != fpath)
                issues.append({
                    "id": "P_DUP", "severity": "MED",
                    "name": "Duplicate function definition",
                    "why": (
                        f"'{name}' defined in {len(locs)} files. "
                        "AI re-implements helpers each session — pick one location."
                    ),
                    "file": fpath, "line": lineno,
                    "context": f"Also in: {others}",
                })
    return issues


# ─────────────────────────────────────────────────────────────────────────────
# AST-BASED PYTHON SCANNER
# Replaces regex for .py files — no false positives on comments/docstrings,
# scope-aware severity (test functions auto-downgraded), safe-call detection.
# ─────────────────────────────────────────────────────────────────────────────

_SECRET_KEYWORDS = {
    "api_key","apikey","password","passwd","secret","token","auth_token",
    "access_token","private_key","stripe_key","sendgrid_key","twilio",
    "jwt_secret","db_password","database_password","client_secret",
}
_SAFE_CALL_NAMES = {
    "getenv","environ","get","getpass","read_secret","fetch_secret",
    "from_env","from_environment",
}
_LOG_METHODS   = {"debug","info","warning","error","critical","exception"}
_LOG_OBJECTS   = {"logging","logger","log"}
_SENSITIVE_VAR = {"token","key","password","secret","auth","credential"}
_SQL_KW        = {"SELECT","INSERT","UPDATE","DELETE","DROP","WHERE"}


def _ast_entropy(s):
    if not s: return 0.0
    freq = defaultdict(int)
    for c in s: freq[c] += 1
    n = len(s)
    return -sum((v/n)*math.log2(v/n) for v in freq.values())


def _looks_like_secret(v):
    if len(v) < 6: return False
    bad = {"your-key","replace","changeme","placeholder","example",
           "test","dummy","fake","xxxx","****","...","your_","<",">"}
    vl = v.lower()
    if any(p in vl for p in bad): return False
    if len(v) < 8 and v.isalpha(): return False
    return True


def _value_is_safe(node):
    if isinstance(node, ast.Call):
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr in _SAFE_CALL_NAMES:
            return True
        if isinstance(func, ast.Name) and func.id in _SAFE_CALL_NAMES:
            return True
    if isinstance(node, ast.Subscript):
        if isinstance(node.value, ast.Attribute) and node.value.attr == "environ":
            return True
    return False


class _ASTScanner(ast.NodeVisitor):
    def __init__(self, rel_path, raw_lines, strict, ignore_map):
        self.rel_path  = rel_path
        self.raw_lines = raw_lines
        self.strict    = strict
        self.ignore_map= ignore_map
        self.findings  = []
        self._scopes   = []          # list of (kind, name, is_test)

    # ── scope tracking ────────────────────────────────────────────────────────
    def _push(self, kind, name):
        is_test = (name.startswith("test_") or name.startswith("Test")
                   or name in {"setUp","tearDown","setUpClass","tearDownClass"}
                   or name.endswith("Test"))
        self._scopes.append((kind, name, is_test))

    def _pop(self):
        self._scopes.pop()

    def _in_test(self):
        return any(t for _, _, t in self._scopes)

    def visit_FunctionDef(self, node):
        self._push("function", node.name)
        self.generic_visit(node)
        self._pop()
    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_ClassDef(self, node):
        self._push("class", node.name)
        self.generic_visit(node)
        self._pop()

    # ── helpers ───────────────────────────────────────────────────────────────
    def _sev(self, base):
        if self._in_test():
            order = ["HIGH","MED","LOW"]
            return order[min(order.index(base)+1, 2)] if base in order else "LOW"
        return base

    def _suppressed(self, pid, lineno):
        ids = self.ignore_map.get(lineno, set())
        return "*" in ids or pid in ids

    def _ctx(self, lineno):
        cs = max(0, lineno-3)
        ce = min(len(self.raw_lines), lineno+2)
        return "\n".join(self.raw_lines[cs:ce])

    def _emit(self, pid, base_sev, name, why, lineno):
        if self._suppressed(pid, lineno):
            return
        self.findings.append({
            "id":      pid,
            "severity":self._sev(base_sev),
            "name":    name,
            "why":     why,
            "file":    self.rel_path,
            "line":    lineno,
            "context": self._ctx(lineno),
            "via":     "ast",
        })

    # ── P1: hardcoded secrets in assignments ──────────────────────────────────
    def visit_Assign(self, node):
        for target in node.targets:
            if isinstance(target, ast.Name):
                self._chk_secret(target.id, node.value, node.lineno)
        self.generic_visit(node)

    def visit_AnnAssign(self, node):
        if isinstance(node.target, ast.Name) and node.value is not None:
            self._chk_secret(node.target.id, node.value, node.lineno)
        self.generic_visit(node)

    def _chk_secret(self, name, val_node, lineno):
        if not any(k in name.lower() for k in _SECRET_KEYWORDS): return
        if _value_is_safe(val_node): return
        if not isinstance(val_node, ast.Constant): return
        v = val_node.value
        if not isinstance(v, str) or not _looks_like_secret(v): return
        self._emit("P1","HIGH","Hardcoded secret",
            "Ships to GitHub and gets scraped by bots within hours.", lineno)

    # ── P1b: high-entropy standalone string ───────────────────────────────────
    # Visited via Assign above; also catch bare string assignments
    def visit_Constant(self, node):
        # Only flag strings that appear as values in assignments (handled above)
        pass

    # ── P_SHELL ───────────────────────────────────────────────────────────────
    def visit_Call(self, node):
        self._chk_shell(node)
        self._chk_eval(node)
        self._chk_deser(node)
        self._chk_log(node)
        self.generic_visit(node)

    def _chk_shell(self, node):
        func = node.func
        ln   = node.lineno
        if isinstance(func, ast.Attribute):
            obj = func.value
            if isinstance(obj, ast.Name) and obj.id == "subprocess":
                if func.attr in ("run","call","check_call","check_output",
                                 "Popen","getoutput","getstatusoutput"):
                    for kw in node.keywords:
                        if kw.arg == "shell" and isinstance(kw.value, ast.Constant):
                            if kw.value.value is True:
                                self._emit("P_SHELL","HIGH","Shell injection risk",
                                    "shell=True allows arbitrary command execution.", ln)
                                return
            if isinstance(obj, ast.Name) and obj.id == "os":
                if func.attr in ("system","popen","execvp","execve",
                                 "execl","execle","execlp","execlpe"):
                    self._emit("P_SHELL","HIGH","Shell injection risk",
                        "Direct shell execution — arbitrary command injection risk.", ln)
                    return
            if isinstance(obj, ast.Name) and obj.id == "commands":
                if func.attr in ("getoutput","getstatusoutput"):
                    self._emit("P_SHELL","HIGH","Shell injection risk",
                        "commands.getoutput() executes shell commands.", ln)

    # ── P_EVAL ────────────────────────────────────────────────────────────────
    def _chk_eval(self, node):
        func = node.func
        if isinstance(func, ast.Name) and func.id in ("eval","exec"):
            if node.args:
                arg = node.args[0]
                if not isinstance(arg, ast.Constant):
                    self._emit("P_EVAL","HIGH","eval/exec on input",
                        "eval/exec on user-controlled input = remote code execution.",
                        node.lineno)

    # ── P_DESER ───────────────────────────────────────────────────────────────
    def _chk_deser(self, node):
        func = node.func
        if not isinstance(func, ast.Attribute): return
        ln = node.lineno
        obj = func.value
        if isinstance(obj, ast.Name) and obj.id == "pickle":
            if func.attr in ("loads","load"):
                self._emit("P_DESER","HIGH","Unsafe deserialization",
                    "pickle.loads can execute arbitrary code on untrusted input.", ln)
                return
        if isinstance(obj, ast.Name) and obj.id == "yaml":
            if func.attr == "load":
                if not any(kw.arg == "Loader" for kw in node.keywords):
                    self._emit("P_DESER","HIGH","Unsafe deserialization",
                        "yaml.load without Loader=SafeLoader can execute arbitrary code.", ln)

    # ── P4: sensitive data in logs ────────────────────────────────────────────
    def _chk_log(self, node):
        func = node.func
        ln   = node.lineno
        is_log = False
        if isinstance(func, ast.Name) and func.id == "print":
            is_log = True
        elif isinstance(func, ast.Attribute):
            if func.attr in _LOG_METHODS:
                if isinstance(func.value, ast.Name):
                    if (func.value.id in _LOG_OBJECTS or
                            "log" in func.value.id.lower()):
                        is_log = True
        if not is_log: return
        for arg in node.args:
            for sub in ast.walk(arg):
                if isinstance(sub, ast.Name):
                    if any(s in sub.id.lower() for s in _SENSITIVE_VAR):
                        self._emit("P4","HIGH","Sensitive data in log",
                            "Credentials written to logs end up in monitoring tools.", ln)
                        return

    # ── P2 / P7: silent except ────────────────────────────────────────────────
    def visit_ExceptHandler(self, node):
        bare   = node.type is None
        broad  = (isinstance(node.type, ast.Name) and
                  node.type.id in ("Exception","BaseException"))
        is_pass= (len(node.body)==1 and isinstance(node.body[0], ast.Pass))
        if bare and is_pass:
            self._emit("P2","HIGH","Silent error catch",
                "Exception swallowed silently — app fails with no trace.", node.lineno)
        elif broad and is_pass:
            self._emit("P7","MED","Broad exception swallowed",
                "Broad exception caught and discarded — bugs vanish silently.", node.lineno)
        self.generic_visit(node)

    # ── P_SQL: f-string with SQL keywords + interpolation ─────────────────────
    def visit_JoinedStr(self, node):
        const_parts, has_interp = [], False
        for val in node.values:
            if isinstance(val, ast.Constant) and isinstance(val.value, str):
                const_parts.append(val.value.upper())
            elif isinstance(val, ast.FormattedValue):
                has_interp = True
        if has_interp and any(kw in " ".join(const_parts) for kw in _SQL_KW):
            self._emit("P_SQL","HIGH","SQL string injection",
                "Dynamic SQL via f-string — SQL injection risk. Use parameterised queries.",
                node.lineno)
        self.generic_visit(node)

    # ── P_NOVALIDATE (strict only) ────────────────────────────────────────────
    def visit_FunctionDef_routes(self, node):
        if not self.strict: return
        for dec in node.decorator_list:
            if isinstance(dec, ast.Call):
                f = dec.func
                if (isinstance(f, ast.Attribute) and
                        f.attr in ("get","post","put","patch","delete") and
                        isinstance(f.value, ast.Name) and
                        f.value.id in ("app","router","blueprint","api")):
                    self._emit("P_NOVALIDATE","MED",
                        "Route without validation hint",
                        "API route — confirm inputs are validated. AI often skips this.",
                        node.lineno)


def _ast_scan_python(filepath, rel_path, raw_lines, strict, ignore_map):
    """
    Run AST scanner on a Python file.
    Returns list of issues, or [] on syntax error (regex scanner is the fallback).
    """
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as fh:
            source = fh.read()
        tree = ast.parse(source, filename=filepath)
    except (OSError, SyntaxError):
        return []          # syntax error → fall through to regex

    scanner = _ASTScanner(rel_path, raw_lines, strict, ignore_map)
    scanner.visit(tree)
    return scanner.findings

# ─────────────────────────────────────────────────────────────────────────────
# AST-BASED JS/TS SCANNER  (TypeScript compiler API via node subprocess)
# Mirrors _ast_scan_python: returns list of issues on success, None on failure.
# Falls back to regex automatically when node/scanner is unavailable.
# ─────────────────────────────────────────────────────────────────────────────

import shutil as _shutil

_JS_SCANNER_DIR  = os.path.join(os.path.dirname(os.path.abspath(__file__)), "js_ast_scanner")
_JS_SCANNER_PATH = os.path.join(_JS_SCANNER_DIR, "scanner.js")


def _node_available():
    """Return True if node is on PATH."""
    return _shutil.which("node") is not None


def _js_scanner_ready():
    """Return True if the scanner script exists."""
    return os.path.isfile(_JS_SCANNER_PATH)


def _ast_scan_js(filepath, rel_path, raw_lines, strict, ignore_map):
    """
    Run the TS-compiler-API AST scanner on a JS/TS/JSX/TSX file.
    Returns list of issues on success, None on any failure (caller falls to regex).
    """
    if not _node_available() or not _js_scanner_ready():
        return None
    cmd = ["node", _JS_SCANNER_PATH, filepath]
    if strict:
        cmd.append("--strict")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
    except (subprocess.TimeoutExpired, OSError):
        return None
    if result.returncode != 0:
        return None
    try:
        raw_findings = json.loads(result.stdout)
    except (json.JSONDecodeError, ValueError):
        return None
    issues = []
    for f in raw_findings:
        lineno = f.get("line", 0)
        pid    = f.get("id", "")
        if _is_suppressed(pid, lineno, ignore_map):
            continue
        cs = max(0, lineno - 3)
        ce = min(len(raw_lines), lineno + 2)
        issues.append({
            "id": pid, "severity": f.get("severity"),
            "name": f.get("name"), "why": f.get("why"),
            "file": rel_path, "line": lineno,
            "context": "\n".join(raw_lines[cs:ce]),
            "via": "ast_js",
        })
    return issues


# IDs covered by the JS AST scanner — skip regex for these in JS/TS files
_JS_AST_COVERED = frozenset({
    "P1", "P1b", "P_EVAL", "P_XSS", "P_SQL", "P_DESER",
    "P2", "P3", "P4", "P7", "P_PROTO", "P_REDOS", "P_SHELL",
})



# ─────────────────────────────────────────────────────────────────────────────
# BASELINE MODE
# Fingerprint every issue. Future scans only report NEW ones.
# Fingerprint = sha256(id + file + stripped_context)[:16]
# Excludes line numbers — survives adding lines above a known issue.
# ─────────────────────────────────────────────────────────────────────────────

_BASELINE_FILE = ".codesentry-baseline.json"


def _fingerprint(issue):
    snippet = issue.get("context", "").strip()
    key = f"{issue['id']}:{issue['file']}:{snippet}"
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]


def _baseline_path(project_path):
    return os.path.join(project_path, _BASELINE_FILE)


def _load_baseline(project_path):
    path = _baseline_path(project_path)
    if not os.path.isfile(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return None


def _save_baseline(project_path, issues, scanned_files, shared=False):
    import json as _json
    entries = {}
    for issue in issues:
        fp = _fingerprint(issue)
        entries[fp] = {
            "id":        issue["id"],
            "severity":  issue["severity"],
            "file":      issue["file"],
            "name":      issue["name"],
            "first_seen":datetime.datetime.utcnow().isoformat() + "Z",
        }
    baseline = {
        "codesentry_baseline_version": "1",
        "created_at":    datetime.datetime.utcnow().isoformat() + "Z",
        "scanned_files": scanned_files,
        "issue_count":   len(entries),
        "shared":        shared,
        "entries":       entries,
    }
    path = _baseline_path(project_path)
    with open(path, "w", encoding="utf-8") as fh:
        _json.dump(baseline, fh, indent=2)
    if not shared:
        _ensure_gitignore_entry(project_path, _BASELINE_FILE)
    return path


def _ensure_gitignore_entry(project_path, entry):
    gi = os.path.join(project_path, ".gitignore")
    try:
        if os.path.isfile(gi):
            existing = open(gi, "r", encoding="utf-8").read()
            if any(l.strip() == entry for l in existing.splitlines()):
                return
            with open(gi, "a", encoding="utf-8") as fh:
                if existing and not existing.endswith("\n"):
                    fh.write("\n")
                fh.write(f"{entry}\n")
        else:
            with open(gi, "w", encoding="utf-8") as fh:
                fh.write(f"{entry}\n")
    except OSError:
        pass


def _filter_new_issues(issues, baseline):
    known = set(baseline.get("entries", {}).keys())
    return [i for i in issues if _fingerprint(i) not in known]


def _baseline_stats(issues, baseline):
    known  = set(baseline.get("entries", {}).keys())
    total  = len(issues)
    known_ct = sum(1 for i in issues if _fingerprint(i) in known)
    return {
        "total":  total,
        "known":  known_ct,
        "new":    total - known_ct,
        "date":   baseline.get("created_at","")[:10],
        "legacy": baseline.get("issue_count", 0),
    }


# ─────────────────────────────────────────────────────────────────────────────
# PATTERNS
# ─────────────────────────────────────────────────────────────────────────────

PATTERNS = [
    {
        "id": "P1", "severity": "HIGH", "name": "Hardcoded secret",
        "regex": (r"(api_key|apikey|password|passwd|secret|token|auth_token"
                  r"|access_token|private_key)\s*[:=]\s*['\"][^'\"]{6,}['\"]"),
        "extensions": [".py",".js",".ts",".jsx",".tsx",".env",".sh",".bash",".yaml",".yml"],
        "why": "Ships to GitHub and gets scraped by bots within hours.",
        "skip_templates": True,
    },
    {
        "id": "P1b", "severity": "HIGH", "name": "High-entropy secret",
        "regex": None, "custom": "entropy",
        "extensions": [".py",".js",".ts",".jsx",".tsx",".env"],
        "why": "High-entropy string — likely a raw key or JWT missed by keyword scan.",
        "skip_templates": True,
    },
    {
        "id": "P1_YAML", "severity": "HIGH", "name": "Hardcoded secret (YAML/unquoted)",
        "regex": (r"^(api_key|apikey|password|passwd|secret|token|auth_token"
                  r"|access_token|private_key|stripe_key|sendgrid_key|twilio)\s*:\s*"
                  r"(?!['\"])[^\s#]{6,}"),
        "extensions": [".yaml", ".yml", ".env"],
        "why": "Unquoted secret in YAML or env file — scraped by bots within hours of a push.",
        "skip_templates": True,
    },
    {
        "id": "P_SQL", "severity": "HIGH", "name": "SQL string injection",
        "regex": r'(f["\']|\.format\s*\(|%\s*[({]).*?\b(SELECT|INSERT|UPDATE|DELETE|DROP|WHERE)\b',
        "extensions": [".py",".js",".ts",".jsx",".tsx"],
        "why": "Dynamic SQL via f-string or .format() — SQL injection risk.",
    },
    {
        "id": "P_SQL_CONCAT", "severity": "HIGH", "name": "SQL string concatenation",
        "regex": r'["\'].*(SELECT|INSERT|UPDATE|DELETE|DROP|WHERE).*["\']\s*\+',
        "extensions": [".py",".js",".ts",".jsx",".tsx"],
        "why": "SQL built by string concatenation — classic injection vector, missed by f-string checks.",
    },
    {
        "id": "P_CONNSTR", "severity": "HIGH", "name": "Hardcoded connection string",
        "regex": r'(Password|pwd|Pwd)\s*=\s*[^;>\s\'"]{4,}',
        "extensions": [".py",".js",".ts",".jsx",".tsx",".json",".yaml",".yml",".env"],
        "why": "Database connection string contains an embedded password.",
        "skip_templates": True,
    },
    {
        "id": "P_SHELL", "severity": "HIGH", "name": "Shell injection risk",
        "regex": (
            r"(subprocess\.[a-z_]+\s*\(.*shell\s*=\s*True"
            r"|os\.system\s*\("
            r"|os\.popen\s*\("
            r"|os\.execvp\s*\("
            r"|os\.execve\s*\("
            r"|commands\.getoutput\s*\()"
        ),
        "extensions": [".py"],
        "why": "Direct shell execution — allows arbitrary command injection if input is untrusted.",
    },
    {
        "id": "P_DESER", "severity": "HIGH", "name": "Unsafe deserialization",
        "regex": r"(pickle\.loads?\s*\(|yaml\.load\s*\([^,)]*\)(?!\s*,\s*Loader))",
        "extensions": [".py"],
        "why": "pickle.loads or yaml.load without Loader= can execute arbitrary code.",
    },
    {
        "id": "P_EVAL", "severity": "HIGH", "name": "eval/exec on input",
        "regex": r"\b(eval|exec)\s*\(\s*(request|input|data|body|params|user|query)",
        "extensions": [".py",".js",".ts",".jsx",".tsx"],
        "why": "eval/exec on user-controlled input = remote code execution.",
    },
    {
        "id": "P_ADMIN", "severity": "HIGH", "name": "Hardcoded admin credentials",
        "regex": r"(username|user|login)\s*=\s*['\"]*(admin|root|administrator)['\"]",
        "extensions": [".py",".js",".ts",".jsx",".tsx",".yaml",".yml"],
        "why": "Default admin credentials hardcoded — trivial to exploit.",
        "skip_templates": True,
    },
    {
        "id": "P2", "severity": "HIGH", "name": "Silent error catch",
        "regex": r"except\s*:\s*pass",
        "extensions": [".py"],
        "why": "Exception swallowed silently — app fails with no trace, no log.",
    },
    {
        "id": "P3", "severity": "HIGH", "name": "Empty catch block",
        "regex": r"catch\s*\([^)]*\)\s*\{\s*\}|\.catch\s*\(\s*\(\s*\)\s*=>\s*\{\s*\}\s*\)",
        "extensions": [".js",".ts",".jsx",".tsx"],
        "why": "JS error swallowed — production failures become completely invisible.",
    },
    {
        "id": "P4", "severity": "HIGH", "name": "Sensitive data in log",
        "regex": r"(console\.log|console\.error|print|logger\.\w+)\s*\(.*?(token|key|password|secret|auth)",
        "extensions": [".py",".js",".ts",".jsx",".tsx"],
        "why": "Credentials written to logs end up in monitoring tools and log aggregators.",
    },
    {
        "id": "P7", "severity": "MED", "name": "Broad exception swallowed",
        "regex": r"except\s+(Exception|BaseException)\s*:\s*\n\s*pass",
        "extensions": [".py"],
        "why": "Broad exception caught and discarded — bugs vanish silently in production.",
    },
    {
        "id": "P5", "severity": "MED", "name": "TODO in production path",
        "regex": r"(#\s*TODO|//\s*TODO|#\s*FIXME|//\s*FIXME|<!--\s*TODO)",
        "extensions": [".py",".js",".ts",".jsx",".tsx",".sh",".bash"],
        "why": "AI placeholder left in code that actually runs in production.",
    },
    {
        "id": "P6", "severity": "MED", "name": "Hardcoded localhost",
        "regex": r"(localhost|127\.0\.0\.1|0\.0\.0\.0)",
        "extensions": [".py",".js",".ts",".jsx",".tsx",".json"],
        "why": "Works on your machine, breaks silently on every real deployment.",
        "skip_docker_services": True,
    },
    {
        "id": "P8", "severity": "LOW", "name": "Debug flag on",
        "regex": r"(DEBUG|APP_DEBUG|NODE_ENV)\s*=\s*(True|true|1|development|dev)[^_]",
        "extensions": [".py",".js",".ts",".jsx",".tsx",".env",".yaml",".yml"],
        "why": "Debug mode exposes stack traces and internal state in production.",
        "skip_templates": True,
    },
    {
        "id": "P_NOVALIDATE", "severity": "MED", "name": "Route without validation hint",
        "regex": r"@(app|router|blueprint)\.(get|post|put|patch|delete)\s*\(",
        "extensions": [".py"],
        "why": "API route defined — confirm request body/params are validated. AI often skips this.",
        "informational": True,
    },
]

# ─────────────────────────────────────────────────────────────────────────────
# SKIP LIST
# ─────────────────────────────────────────────────────────────────────────────

_SKIP_FRAGMENTS = [
    "node_modules","dist","build",".next","__pycache__",
    ".min.js",".min.css","migrations","package-lock.json",
    "yarn.lock","poetry.lock",
    ".pyc",".pyo",".map",".exe",".dll",".so",".dylib",".bin",
    ".png",".jpg",".jpeg",".gif",".svg",".ico",
    ".woff",".woff2",".ttf",".eot",".pdf",
    ".zip",".tar",".gz",".lock",
]

def _should_skip(fp):
    fp = fp.replace("\\", "/")
    return any(s in fp for s in _SKIP_FRAGMENTS)

_MAX_FILE_KB = 500


def _git_available():
    try:
        subprocess.run(["git", "--version"], capture_output=True, check=True)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False


# ─────────────────────────────────────────────────────────────────────────────
# CORE FILE SCAN
# ─────────────────────────────────────────────────────────────────────────────

def _scan_file(filepath, rel_path, strict):
    ext      = os.path.splitext(filepath)[1].lower()
    template = _is_template_file(filepath)
    issues   = []

    try:
        with open(filepath, "rb") as fb:
            if b"\x00" in fb.read(512):
                return []
    except OSError:
        return []

    try:
        if os.path.getsize(filepath) / 1024 > _MAX_FILE_KB:
            return []
    except OSError:
        return []

    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as fh:
            raw_text = fh.read()
    except OSError:
        return []

    raw_lines  = raw_text.splitlines()
    ignore_map = _build_ignore_map(raw_lines)

    # ── Python files: AST scanner first, regex as fallback ───────────────────
    if ext == ".py" and not template:
        ast_issues = _ast_scan_python(filepath, rel_path, raw_lines,
                                      strict, ignore_map)
        if ast_issues is not None:
            # AST succeeded — use its results, skip regex for .py patterns
            # (still run entropy P1b via regex since AST doesn't walk all literals)
            issues.extend(ast_issues)
            # Entropy pass — not covered by AST node walk above
            joined = _join_continuations(raw_text)
            clean  = _strip_comments(joined, ext)
            p1b    = next((p for p in PATTERNS if p["id"] == "P1b"), None)
            if p1b:
                for lineno, line in enumerate(clean.splitlines(), 1):
                    if _is_suppressed("P1b", lineno, ignore_map):
                        continue
                    if _has_high_entropy_secret(line):
                        # Don't double-report if AST already caught it
                        already = any(
                            i["line"] == lineno and i["id"] == "P1b"
                            for i in issues
                        )
                        if not already:
                            cs, ce = max(0, lineno-3), min(len(raw_lines), lineno+2)
                            issues.append({
                                "id": "P1b", "severity": "HIGH",
                                "name": p1b["name"], "why": p1b["why"],
                                "file": rel_path, "line": lineno,
                                "context": "\n".join(raw_lines[cs:ce]),
                            })
            # Run non-Python-specific patterns (YAML secrets in .py is unusual
            # but run P5/P6/P8 etc via regex since AST doesn't cover them all)
            joined = _join_continuations(raw_text)
            clean  = _strip_comments(joined, ext)
            ast_covered = {"P1","P1b","P_SHELL","P_EVAL","P_DESER",
                           "P4","P2","P7","P_SQL","P_NOVALIDATE"}
            for p in PATTERNS:
                if ext not in p.get("extensions", []):
                    continue
                if p["id"] in ast_covered:
                    continue
                if p.get("custom") == "entropy":
                    continue
                if template and p.get("skip_templates"):
                    continue
                if p.get("informational") and not strict:
                    continue
                if not p.get("regex"):
                    continue
                for m in re.finditer(p["regex"], clean,
                                     flags=re.IGNORECASE | re.MULTILINE):
                    lineno = clean.count("\n", 0, m.start()) + 1
                    if _is_suppressed(p["id"], lineno, ignore_map):
                        continue
                    cs, ce = max(0, lineno-3), min(len(raw_lines), lineno+2)
                    issues.append({
                        "id": p["id"],
                        "severity": _adjust_severity(p["severity"], rel_path),
                        "name": p["name"], "why": p["why"],
                        "file": rel_path, "line": lineno,
                        "context": "\n".join(raw_lines[cs:ce]),
                    })
            return issues

    # ── JS/TS files: AST scanner first, regex fallback ────────────────────
    if ext in (".js", ".ts", ".jsx", ".tsx") and not template:
        ast_issues = _ast_scan_js(filepath, rel_path, raw_lines, strict, ignore_map)
        if ast_issues is not None:
            issues.extend(ast_issues)
            # Entropy (P1b) — AST doesn't walk all string literals
            joined = _join_continuations(raw_text)
            clean  = _strip_comments(joined, ext)
            p1b = next((p for p in PATTERNS if p["id"] == "P1b"), None)
            if p1b:
                for lineno, line in enumerate(clean.splitlines(), 1):
                    if _is_suppressed("P1b", lineno, ignore_map):
                        continue
                    if _has_high_entropy_secret(line):
                        already = any(
                            i["line"] == lineno and i["id"] == "P1b" for i in issues
                        )
                        if not already:
                            cs, ce = max(0, lineno-3), min(len(raw_lines), lineno+2)
                            issues.append({
                                "id": "P1b", "severity": "HIGH",
                                "name": p1b["name"], "why": p1b["why"],
                                "file": rel_path, "line": lineno,
                                "context": "\n".join(raw_lines[cs:ce]),
                            })
            # Run remaining regex patterns not covered by AST
            for p in PATTERNS:
                if ext not in p.get("extensions", []):
                    continue
                if p["id"] in _JS_AST_COVERED:
                    continue
                if p.get("custom") == "entropy":
                    continue
                if template and p.get("skip_templates"):
                    continue
                if p.get("informational") and not strict:
                    continue
                if not p.get("regex"):
                    continue
                for m2 in re.finditer(p["regex"], clean, flags=re.IGNORECASE | re.MULTILINE):
                    lineno = clean.count("\n", 0, m2.start()) + 1
                    if _is_suppressed(p["id"], lineno, ignore_map):
                        continue
                    cs, ce = max(0, lineno-3), min(len(raw_lines), lineno+2)
                    issues.append({
                        "id": p["id"],
                        "severity": _adjust_severity(p["severity"], rel_path),
                        "name": p["name"], "why": p["why"],
                        "file": rel_path, "line": lineno,
                        "context": "\n".join(raw_lines[cs:ce]),
                    })
            return issues

    # ── Non-Python files (and .py fallback on syntax error) ──────────────────
    joined = _join_continuations(raw_text)
    clean  = _strip_comments(joined, ext)

    for p in PATTERNS:
        if ext not in p.get("extensions", []):
            continue
        if template and p.get("skip_templates"):
            continue
        if p.get("informational") and not strict:
            continue

        if p.get("custom") == "entropy":
            for lineno, line in enumerate(clean.splitlines(), 1):
                if _is_suppressed(p["id"], lineno, ignore_map):
                    continue
                if _has_high_entropy_secret(line):
                    cs, ce = max(0, lineno-3), min(len(raw_lines), lineno+2)
                    issues.append({
                        "id": p["id"], "severity": p["severity"],
                        "name": p["name"], "why": p["why"],
                        "file": rel_path, "line": lineno,
                        "context": "\n".join(raw_lines[cs:ce]),
                    })
            continue

        if not p.get("regex"):
            continue

        docker_suppress = (
            p["id"] == "P6" and p.get("skip_docker_services")
            and "docker-compose" in os.path.basename(filepath).lower()
        )

        for m in re.finditer(p["regex"], clean, flags=re.IGNORECASE | re.MULTILINE):
            lineno = clean.count("\n", 0, m.start()) + 1
            if _is_suppressed(p["id"], lineno, ignore_map):
                continue
            if docker_suppress:
                rl = raw_lines[lineno - 1] if lineno <= len(raw_lines) else ""
                if rl.startswith("      ") or "services" in rl:
                    continue
            cs, ce = max(0, lineno-3), min(len(raw_lines), lineno+2)
            issues.append({
                "id": p["id"],
                "severity": _adjust_severity(p["severity"], rel_path),
                "name": p["name"], "why": p["why"],
                "file": rel_path, "line": lineno,
                "context": "\n".join(raw_lines[cs:ce]),
            })

    return issues


# ─────────────────────────────────────────────────────────────────────────────
# VIBELOG  — persist every scan to VIBELOG.md, append-only
# ─────────────────────────────────────────────────────────────────────────────

_VIBELOG_HEADER = """\
# codesentry scan log

Append-only record of every codesentry scan on this project.
Generated by codesentry — https://github.com/Jen-chad/codesentry

---
"""

def _ensure_gitignore(project_path):
    """
    Add VIBELOG.md to .gitignore so it never shows up in git status.
    - If .gitignore exists and already contains VIBELOG.md: do nothing.
    - If .gitignore exists but doesn't mention it: append one line.
    - If .gitignore doesn't exist: create it with just VIBELOG.md.
    All operations are non-fatal — silently skipped on any OSError.
    """
    gi_path = os.path.join(project_path, ".gitignore")
    entry   = "VIBELOG.md"
    try:
        if os.path.isfile(gi_path):
            existing = open(gi_path, "r", encoding="utf-8").read()
            # Check whole-line match so we don't partial-match e.g. OLD_VIBELOG.md
            if any(line.strip() == entry for line in existing.splitlines()):
                return   # already there — nothing to do
            # Append with a trailing newline guard
            with open(gi_path, "a", encoding="utf-8") as fh:
                if existing and not existing.endswith("\n"):
                    fh.write("\n")
                fh.write(f"{entry}\n")
        else:
            with open(gi_path, "w", encoding="utf-8") as fh:
                fh.write(f"{entry}\n")
    except OSError:
        pass   # non-fatal


def _write_vibelog(path, issues, scanned_count):
    log_path   = os.path.join(path, "VIBELOG.md")
    is_new     = not os.path.isfile(log_path)

    counts = {"HIGH": 0, "MED": 0, "LOW": 0}
    for i in issues:
        counts[i["severity"]] = counts.get(i["severity"], 0) + 1

    ts    = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    lines = [
        f"\n## {ts} — {scanned_count} file(s) scanned\n",
        f"**Issues:** {counts['HIGH']} HIGH  {counts['MED']} MED  {counts['LOW']} LOW\n",
    ]
    if issues:
        lines.append("\n| Severity | File | Line | Issue |\n")
        lines.append("|----------|------|------|-------|\n")
        sorder = {"HIGH": 0, "MED": 1, "LOW": 2}
        for i in sorted(issues, key=lambda x: sorder.get(x["severity"], 3)):
            lines.append(f"| {i['severity']} | {i['file']} | {i['line']} | {i['name']} |\n")
    else:
        lines.append("\nNo issues found.\n")

    try:
        with open(log_path, "a", encoding="utf-8") as fh:
            if is_new:
                fh.write(_VIBELOG_HEADER)
            fh.writelines(lines)
    except OSError:
        pass   # non-fatal — log is best-effort

    # Keep VIBELOG.md out of git status — do this after writing so the
    # file exists before we touch .gitignore (cleaner ordering).
    if is_new:
        _ensure_gitignore(path)


# ─────────────────────────────────────────────────────────────────────────────
# SCAN CONFIG  — replaces the long positional argument list on run_check
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class ScanConfig:
    """All options for a single codesentry run. Passed as one object, never as 10 args."""
    path:            str  = "."
    autofix:         bool = False
    copy:            bool = False
    one_prompt:      bool = False
    strict:          bool = False
    compact:         bool = False
    narrate:         bool = False
    explain:         bool = False
    mode:            str  = "dev"
    commits:         int  = 1
    output:          str  = "text"
    full:            bool = False
    baseline:        bool = False   # only report new issues vs baseline
    baseline_init:   bool = False   # save current issues as baseline
    baseline_commit: bool = False   # commit baseline to repo (shared with team)


# ─────────────────────────────────────────────────────────────────────────────
# MAIN RUN  — scan -> print -> exit. Nothing blocks. Nothing asks.
# ─────────────────────────────────────────────────────────────────────────────

def run_check(cfg: ScanConfig):
    console = make_console()

    file_cfg    = load_config(cfg.path)
    cfg.mode    = cfg.mode    or file_cfg.get("mode",    "dev")
    cfg.strict  = cfg.strict  or (file_cfg.get("strict",  "false") == "true")
    cfg.compact = cfg.compact or (file_cfg.get("compact", "false") == "true")

    if not os.path.exists(cfg.path):
        console.print(f"[red]Directory not found: {cfg.path}[/red]")
        sys.exit(1)

    all_exts = {ext for p in PATTERNS for ext in p.get("extensions", [])}

    def _full_scan():
        result = []
        for dirpath, _, filenames in os.walk(cfg.path):
            for fn in filenames:
                if os.path.splitext(fn)[1].lower() in all_exts:
                    result.append(os.path.relpath(os.path.join(dirpath, fn), cfg.path))
        return result

    # File collection
    files_to_scan   = []
    fallback_reason = None

    # --full: skip git diff entirely, scan everything in the repo
    if cfg.full:
        console.print("[yellow]Full repo scan — not limited to last commit.[/yellow]")
        files_to_scan = _full_scan()
    elif not _git_available():
        console.print(f"[yellow]git not found — scanning all files in {cfg.path}[/yellow]")
        files_to_scan = _full_scan()
    else:
        def _git(args):
            try:
                r = subprocess.run(args, cwd=cfg.path, capture_output=True, text=True)
                return [f for f in r.stdout.strip().split("\n") if f]
            except Exception:
                return []

        files_to_scan = _git(["git", "diff", "--name-only", f"HEAD~{cfg.commits}"])
        if not files_to_scan:
            files_to_scan = _git(["git", "diff", "--name-only", "HEAD"])
        if not files_to_scan:
            files_to_scan = _git(["git", "diff", "--name-only"])
        if not files_to_scan:
            fallback_reason = "no previous commit found"
            files_to_scan = _full_scan()

        files_to_scan += _git(["git", "diff", "--name-only", "--cached"])
        files_to_scan += _git(["git", "ls-files", "--others", "--exclude-standard"])
        files_to_scan = list(dict.fromkeys(files_to_scan))

    total_candidates = len(files_to_scan)
    issues, scanned_count = [], 0

    for f in files_to_scan:
        if _should_skip(f):
            continue
        full_path = os.path.join(cfg.path, f)
        if os.path.islink(full_path) or not os.path.isfile(full_path):
            continue
        issues.extend(_scan_file(full_path, f, cfg.strict))
        scanned_count += 1

    issues.extend(scan_duplicate_functions(files_to_scan, cfg.path))

    seen, deduped = set(), []
    for i in issues:
        key = (i["file"], i["line"], i["name"])
        if key not in seen:
            seen.add(key)
            deduped.append(i)
    issues = deduped

    # ── Baseline: save fingerprints (--baseline-init) ─────────────────────────
    if cfg.baseline_init:
        path = _save_baseline(cfg.path, issues, scanned_count,
                              shared=cfg.baseline_commit)
        shared_note = (" (committed to repo)" if cfg.baseline_commit
                       else " (local — gitignored)")
        console.print(
            f"\n[bold green]✓ Baseline saved[/bold green]  "
            f"[dim]{len(issues)} issue(s) fingerprinted → {path}{shared_note}[/dim]\n"
            f"[dim]Future scans with --baseline will only report NEW issues.[/dim]\n"
        )

    # ── Baseline: filter to new-only (--baseline) ─────────────────────────────
    baseline_data = None
    if cfg.baseline and not cfg.baseline_init:
        baseline_data = _load_baseline(cfg.path)
        if baseline_data is None:
            console.print(
                "[yellow]No baseline found. Run:[/yellow]  "
                "[bold]codesentry check . --baseline-init[/bold]  first."
            )
        else:
            stats  = _baseline_stats(issues, baseline_data)
            issues = _filter_new_issues(issues, baseline_data)
            console.print(
                f"[dim]Baseline active (set {stats['date']}) — "
                f"[bold]{stats['known']}[/bold] known issue(s) suppressed, "
                f"[bold cyan]{stats['new']}[/bold cyan] new issue(s) to fix.[/dim]"
            )

    # Persist scan results
    _write_vibelog(cfg.path, issues, scanned_count)

    # Header
    skipped = total_candidates - scanned_count
    parts   = [f"Scanned {scanned_count} file(s)"]
    if skipped:
        parts.append(f"{skipped} skipped")
    if fallback_reason:
        parts.append(f"full scan ({fallback_reason})")

    console.print(Panel(
        Align.center(
            f"[bold cyan]codesentry[/bold cyan]  [dim]v{__version__}[/dim]\n"
            + "  •  ".join(parts)
        ),
        border_style="cyan",
    ))

    if fallback_reason:
        console.print(
            f"[yellow]Note: {fallback_reason} — scanned all files instead of last commit.[/yellow]"
        )

    if cfg.narrate:
        _run_narration(console, cfg.path, cfg.mode)

    if cfg.compact:
        _print_compact(console, issues)
    else:
        _print_table(console, issues)
    _render_summary(console, issues)

    if issues:
        hint = (
            "[dim]Suppress a false positive: add  # codesentry-ignore  "
            "or  # codesentry-ignore: P1  to the flagged line.[/dim]"
        )
        if not cfg.explain:
            hint += (
                "  [dim]Run with  --explain  for step-by-step fix guidance on each issue.[/dim]"
            )
        console.print(hint)

    if cfg.autofix and issues:
        _render_autofix(console, issues, cfg.one_prompt, cfg.copy)

    if cfg.explain:
        _run_explain_loop(console, issues, cfg.path, cfg.mode)

    # ── JSON output mode — emit structured JSON then exit cleanly ──
    if cfg.output == "json":
        import json as _json
        import datetime as _dt
        counts = {"HIGH": 0, "MED": 0, "LOW": 0}
        for i in issues:
            counts[i["severity"]] = counts.get(i["severity"], 0) + 1
        payload = {
            "codesentry_version": __version__,
            "scanned_at": _dt.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
            "scanned_files": scanned_count,
            "summary": counts,
            "passed": counts["HIGH"] == 0,
            "issues": [
                {
                    "id":       i["id"],
                    "severity": i["severity"],
                    "file":     i["file"],
                    "line":     i["line"],
                    "name":     i["name"],
                    "why":      i.get("why", ""),
                }
                for i in issues
            ],
        }
        # Write clean JSON to stdout (no Rich markup)
        sys.stdout.write(_json.dumps(payload, indent=2) + "\n")
        sys.exit(0 if counts["HIGH"] == 0 else 1)

    _exit_code(issues, cfg.strict)


# ─────────────────────────────────────────────────────────────────────────────
# AI NARRATION
# ─────────────────────────────────────────────────────────────────────────────

def _run_narration(console, path, mode):
    api_key = os.environ.get("GROQ_API_KEY")
    if not api_key:
        console.print(
            "[yellow]--narrate needs GROQ_API_KEY.[/yellow]\n"
            "[dim]Set with:  export GROQ_API_KEY=your-key[/dim]"
        )
        return

    try:
        diff_text = subprocess.run(
            ["git", "diff", "HEAD"], cwd=path, capture_output=True, text=True
        ).stdout[:800]
    except Exception:
        diff_text = ""

    if not diff_text:
        console.print("[yellow]Nothing to narrate — no diff found.[/yellow]")
        return

    client = _get_groq_client(api_key, console)
    if not client:
        return

    try:
        resp = client.chat.completions.create(
            model=_model(len(diff_text)),
            max_tokens=150,
            messages=[
                {"role": "system", "content": _system_prompt(mode)},
                {"role": "user",   "content": diff_text},
            ],
        )
        console.print(Panel(
            resp.choices[0].message.content,
            title="AI explanation", border_style="cyan",
        ))
    except Exception as e:
        console.print(f"[yellow]Narration failed: {e}[/yellow]")


# ─────────────────────────────────────────────────────────────────────────────
# ISSUE SELECTOR  — replaces the old free-form line explainer
#
# After the scan table prints, --explain shows a numbered menu of every
# found issue. You type the number, get:
#   1. The exact code context (already in memory — offline)
#   2. What the pattern means and why it's risky (offline)
#   3. A concrete fix suggestion for this specific pattern (offline)
#   4. Optionally: Groq elaboration if GROQ_API_KEY is set
#
# No transcription. No format to remember. Works fully offline.
# Groq only adds a sentence or two of extra context when available.
# ─────────────────────────────────────────────────────────────────────────────

# Per-pattern fix guidance — offline, no API needed.
# Each entry is a plain-English "how to fix this" for the pattern.
_FIX_GUIDANCE = {
    "P1":          "Replace the hardcoded value with an environment variable.\n  Before: api_key = \"sk-abc123\"\n  After:  api_key = os.getenv(\"API_KEY\")",
    "P1b":         "This string has unusually high randomness — it looks like a secret.\n  Move it to an environment variable or a secrets manager.",
    "P1_YAML":     "Move the secret out of the YAML file into an environment variable.\n  Before: api_key: sk-live-abc123\n  After:  api_key: {{ env('API_KEY') }}  or load from os.environ in code.",
    "P_SQL":       "Use parameterised queries instead of string formatting.\n  Before: f\"SELECT * FROM users WHERE id={uid}\"\n  After:  cursor.execute(\"SELECT * FROM users WHERE id=%s\", (uid,))",
    "P_SQL_CONCAT":"Use parameterised queries — never build SQL by concatenating strings.\n  Before: \"SELECT * FROM \" + table + \" WHERE id=\" + uid\n  After:  cursor.execute(\"SELECT * FROM users WHERE id=%s\", (uid,))",
    "P_CONNSTR":   "Move the password out of the connection string into an environment variable.\n  Before: \"Server=myserver;Password=abc123\"\n  After:  f\"Server=myserver;Password={os.getenv('DB_PASSWORD')}\"",
    "P_SHELL":     "Replace os.system/os.popen with subprocess and never pass shell=True.\n  Before: os.system(f'rm {path}')  /  subprocess.run(cmd, shell=True)\n  After:  subprocess.run(['rm', path], check=True)",
    "P_DESER":     "For pickle: avoid deserialising untrusted data — no safe fix exists.\n  For yaml: add Loader=yaml.SafeLoader\n  Before: yaml.load(data)\n  After:  yaml.load(data, Loader=yaml.SafeLoader)",
    "P_EVAL":      "Never eval/exec user-controlled input. Find a safer alternative:\n  - Use ast.literal_eval() for simple data structures\n  - Use a lookup dict for dynamic dispatch",
    "P_XSS":       "Never assign user input to innerHTML/outerHTML. Use textContent, or sanitize with DOMPurify:\n  - element.textContent = userInput  (safe)\n  - element.innerHTML = DOMPurify.sanitize(userInput)  (safe with library)",
    "P_PROTO":     "Avoid __proto__ mutation. When merging user-supplied objects, whitelist known keys:\n  - const safe = { name: input.name, email: input.email }  (whitelist)\n  - Use Object.create(null) for dictionaries to avoid prototype chain",
    "P_REDOS":     "Flatten nested quantifiers to prevent catastrophic backtracking:\n  - Replace (a+)+ with a+\n  - Replace ([a-z]*a)* with a safer linear pattern\n  - Consider a linear-time regex engine (re2) for untrusted input",
    "P_SHELL":     "Never interpolate user input into shell commands. Use argument arrays:\n  - subprocess.run(['cmd', user_arg])  (safe — no shell)\n  - execFile('cmd', [userArg])  (safe in Node.js)",
    "P_ADMIN":     "Replace the hardcoded credential with an environment variable or\n  a secrets manager. Never commit real credentials.",
    "P2":          "Replace bare except with a specific exception and log the error.\n  Before: except: pass\n  After:  except ValueError as e: logger.error(e)",
    "P3":          "Add error handling inside the catch block.\n  Before: .catch(() => {})\n  After:  .catch((err) => console.error(\'Caught:\', err))",
    "P4":          "Remove the sensitive field from the log statement.\n  Before: print(f\"Token: {token}\")\n  After:  print(\"Token received\")",
    "P7":          "Catch a specific exception and log it — don\'t discard it.\n  Before: except Exception: pass\n  After:  except Exception as e: logger.warning(\"Unexpected error: %s\", e)",
    "P5":          "Resolve or remove the TODO/FIXME before shipping.\n  If it\'s a known gap, track it in your issue tracker instead.",
    "P6":          "Replace the hardcoded URL with an environment variable.\n  Before: BASE_URL = \"http://localhost:3000\"\n  After:  BASE_URL = os.getenv(\"BASE_URL\", \"http://localhost:3000\")",
    "P8":          "Set DEBUG/NODE_ENV from the environment, not in code.\n  Before: DEBUG = True\n  After:  DEBUG = os.getenv(\"DEBUG\", \"false\").lower() == \"true\"",
    "P_NOVALIDATE":"Add input validation before using request data.\n  Use a schema library (pydantic, marshmallow, cerberus) or\n  at minimum check types and required fields manually.",
    "P_DUP":       "Keep one canonical version and import it everywhere.\n  Delete the duplicate definition and update the imports.",
}

_FIX_SYSTEM_PROMPT = (
    "You are a security-focused code reviewer giving a developer a targeted fix.\n"
    "You are shown a specific security issue, the affected code, and a suggested fix approach.\n"
    "In 2-3 sentences: confirm the fix approach is correct for this specific code, "
    "mention any edge cases, and give the corrected snippet if it is short enough to show inline.\n"
    "Be direct. No preamble. No restating the problem."
)


def _run_explain_loop(console, issues, path, mode):
    """
    Numbered issue selector. Works offline. Groq adds optional elaboration.
    Replaces the old free-form file:line prompt that required transcription.
    """
    if not issues:
        console.print("[dim]No issues to explain.[/dim]")
        return

    api_key = os.environ.get("GROQ_API_KEY")
    client  = _get_groq_client(api_key, console) if api_key else None
    if not api_key:
        console.print(
            "[dim]No GROQ_API_KEY set — showing offline fix guidance only.\n"
            "Set GROQ_API_KEY for AI-powered fix elaboration.[/dim]"
        )

    # Print the numbered index
    console.print("\n[bold cyan]Fix guidance[/bold cyan]  [dim](enter number, or q to quit)[/dim]")
    for idx, i in enumerate(issues, 1):
        sev_color = {"HIGH": "red", "MED": "yellow"}.get(i["severity"], "blue")
        console.print(
            f"  [{sev_color}]{idx:>2}[/{sev_color}]  "
            f"[bold]{i['file']}:{i['line']}[/bold]  "
            f"{i['name']}"
        )

    while True:
        try:
            raw = console.input("\n> ").strip()
        except (EOFError, KeyboardInterrupt):
            break
        if raw.lower() in ("q", "quit", "exit", ""):
            break
        if not raw.isdigit():
            console.print("[red]Enter a number from the list above, or q to quit.[/red]")
            continue
        idx = int(raw)
        if idx < 1 or idx > len(issues):
            console.print(f"[red]Enter a number between 1 and {len(issues)}.[/red]")
            continue

        issue = issues[idx - 1]
        _show_fix_guidance(console, issue, client, mode)


def _show_fix_guidance(console, issue, client, mode):
    """
    Show offline fix guidance for one issue, then optionally ask Groq
    for a targeted elaboration using the actual code context.
    """
    guidance = _FIX_GUIDANCE.get(issue["id"], "No specific fix guidance available for this pattern.")

    # ── offline panel — always shown, no API needed ──
    console.print(Panel(
        f"[bold]Issue:[/bold]  {issue['name']}\n"
        f"[bold]File:[/bold]   {issue['file']}  line {issue['line']}\n"
        f"[bold]Why:[/bold]    {issue['why']}\n\n"
        f"[bold]Code:[/bold]\n[dim]{issue['context']}[/dim]\n\n"
        f"[bold]How to fix:[/bold]\n{guidance}",
        title=f"[{issue['id']}] Fix guidance",
        border_style="green",
    ))

    # ── optional Groq elaboration — only when key is available ──
    if client is None:
        return

    user_msg = (
        f"Issue type: {issue['name']}\n"
        f"Why it matters: {issue['why']}\n"
        f"Suggested fix approach:\n{guidance}\n\n"
        f"Actual code:\n{issue['context']}"
    )

    try:
        resp = client.chat.completions.create(
            model=_model(len(user_msg)),
            max_tokens=180,
            messages=[
                {"role": "system", "content": _FIX_SYSTEM_PROMPT},
                {"role": "user",   "content": user_msg},
            ],
        )
        console.print(Panel(
            resp.choices[0].message.content,
            title="AI elaboration",
            border_style="cyan",
        ))
    except Exception as e:
        console.print(f"[yellow]AI elaboration unavailable: {e}[/yellow]")


# ─────────────────────────────────────────────────────────────────────────────
# AUTOFIX PROMPTS
# ─────────────────────────────────────────────────────────────────────────────

def _render_autofix(console, issues, one_prompt, copy):
    console.print("\n[bold cyan]Autofix prompts[/bold cyan]\n")
    if one_prompt:
        text  = _combined_prompt(issues)
        final = text
        console.print(Panel(text, title="Combined autofix prompt", border_style="green"))
    else:
        parts = []
        for i in issues:
            p = _fix_prompt(i)
            console.print(Panel(p, title=f"{i['file']}:{i['line']}", border_style="green"))
            parts.append(p)
        final = "\n\n---\n\n".join(parts)

    if copy:
        try:
            import pyperclip
            pyperclip.copy(final)
            console.print("[green]Copied to clipboard[/green]")
        except ImportError:
            console.print("[yellow]pip install pyperclip to enable --copy[/yellow]")


def _fix_prompt(issue):
    return (
        "Fix this specific issue. Return ONLY the corrected snippet.\n\n"
        f"Issue : {issue['name']}\n"
        f"Why   : {issue['why']}\n"
        f"File  : {issue['file']}  Line: {issue['line']}\n\n"
        "Rules:\n"
        "- Fix ONLY this issue\n"
        "- Do NOT change unrelated code\n"
        "- Do NOT refactor or rename\n"
        "- If unsure, leave unchanged\n\n"
        f"Code:\n{issue['context']}\n"
    )


def _combined_prompt(issues):
    out = (
        "Fix the issues below. Return updated code grouped by file.\n"
        "No explanations. Fix ONLY listed issues. No refactoring.\n\nIssues:"
    )
    for idx, i in enumerate(issues, 1):
        out += (
            f"\n\n[{idx}] {i['file']}:{i['line']} — {i['name']}\n"
            f"Why: {i['why']}\nCode:\n{i['context']}"
        )
    out += "\n\nOutput: updated code grouped by file only."
    return out


# ─────────────────────────────────────────────────────────────────────────────
# RENDERING
# ─────────────────────────────────────────────────────────────────────────────

_SEV_ORDER = {"HIGH": 0, "MED": 1, "LOW": 2}

def _print_compact(console, issues):
    if not issues:
        console.print("[bold green]Clean[/bold green]")
        return
    issues.sort(key=lambda x: _SEV_ORDER.get(x["severity"], 3))
    max_len = max(len(f"{i['file']}:{i['line']}") for i in issues)
    for i in issues:
        tag = {"HIGH": "[bold red][HIGH][/bold red]",
               "MED":  "[yellow][MED ][/yellow]"}.get(i["severity"], "[blue][LOW ][/blue]")
        loc = f"{i['file']}:{i['line']}".ljust(max_len + 2)
        console.print(f"{tag} {loc}-> {i['name']}")


def _print_table(console, issues):
    if not issues:
        console.print()
        console.print(Panel(
            Align.center("[bold green]Clean — no issues detected[/bold green]"),
            border_style="green",
        ))
        console.print()
        return

    issues.sort(key=lambda x: _SEV_ORDER.get(x["severity"], 3))
    console.print()
    t = Table(
        show_header=True, header_style="bold", box=box.ROUNDED,
        show_lines=True, expand=True, row_styles=["none", "on #1e1e1e"], padding=(0, 1),
    )
    t.add_column("Severity",      min_width=10, justify="center")
    t.add_column("File",          min_width=20, overflow="fold")
    t.add_column("Line",          min_width=6,  justify="center")
    t.add_column("Issue",         min_width=28, overflow="fold")
    t.add_column("Why it matters",min_width=35, overflow="fold")

    for i in issues:
        sev = {"HIGH": "[bold white on red] HIGH [/bold white on red]",
               "MED":  "[bold black on yellow] MED [/bold black on yellow]"}.get(
               i["severity"], "[bold white on blue] LOW [/bold white on blue]")
        t.add_row(sev, i["file"], str(i["line"]), i["name"], i.get("why", ""))

    console.print(Panel(t, title="Scan results", border_style="red"))
    console.print()


def _render_summary(console, issues):
    counts = {"HIGH": 0, "MED": 0, "LOW": 0}
    for i in issues:
        counts[i["severity"]] = counts.get(i["severity"], 0) + 1
    console.print(
        f"[bold]Summary:[/bold]  "
        f"[red]{counts['HIGH']} HIGH[/red]  "
        f"[yellow]{counts['MED']} MED[/yellow]  "
        f"[blue]{counts['LOW']} LOW[/blue]"
    )


def _exit_code(issues, strict):
    if strict and any(i["severity"] in ("HIGH", "MED") for i in issues):
        sys.exit(1)
    elif not strict and any(i["severity"] == "HIGH" for i in issues):
        sys.exit(1)


# ─────────────────────────────────────────────────────────────────────────────
# AI HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def _model(size):
    return "llama-3.1-8b-instant" if size < 300 else "llama-3.3-70b-versatile"


def _system_prompt(mode):
    """
    System prompt for AI NARRATION only — explains what a git diff changed.
    3 bullets: what changed, why it was changed, what could break.
    NOT used for fix guidance (that uses _FIX_SYSTEM_PROMPT).
    """
    if mode == "eli5":
        return (
            "You explain code changes to someone who has never coded.\n"
            "Use simple everyday words. No technical terms. Max 3 short lines.\n"
            "Format (use exactly these labels):\n"
            "* What changed\n"
            "* Why\n"
            "* Risk"
        )
    if mode == "dev":
        return (
            "You are a senior engineer doing a quick diff review.\n"
            "Be technical and concise. One sentence per point. Max 3 bullets.\n"
            "Format (use exactly these labels):\n"
            "* Change\n"
            "* Impact\n"
            "* Risk"
        )
    # default: beginner
    return (
        "You explain code changes to a junior developer.\n"
        "Plain English, no jargon. Max 3 short bullets.\n"
        "Format (use exactly these labels):\n"
        "* What changed\n"
        "* Why\n"
        "* Risk"
    )


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

@click.command(help="""
Scan AI-generated code for security issues before you commit.

\b
Quick start:
  codesentry check            scan last commit, print table, exit
  codesentry check --autofix  generate fix prompts for every issue
  codesentry check --narrate  plain-English diff summary (needs GROQ_API_KEY)
  codesentry check --explain  numbered fix guidance per issue (Groq optional)
  codesentry check --strict   also fail on MED issues
  codesentry check --compact  one line per issue (CI-friendly)
  codesentry check --commits 3 scan last 3 commits
  codesentry check path/to/repo scan a specific directory

\b
Suppress a false positive on one line:
  url = "http://localhost:3000"   # codesentry-ignore
  key = os.getenv("KEY")         # codesentry-ignore: P1

\b
Set defaults in .codesentry (project root or ~/):
  mode    = dev      # eli5 | beginner | dev
  strict  = false
  compact = false
""")
@click.argument("path", default=".", type=click.Path())
@click.option("--version",    is_eager=True, expose_value=False, is_flag=True,
              callback=_print_version, help="Show version and exit.")
@click.option("--autofix",    is_flag=True, help="Generate fix prompts for found issues")
@click.option("--copy",       is_flag=True, help="Copy autofix prompts to clipboard")
@click.option("--one-prompt", is_flag=True, help="Combine all fix prompts into one")
@click.option("--strict",     is_flag=True, help="Fail on MED issues too")
@click.option("--compact",    is_flag=True, help="One line per issue (CI-friendly)")
@click.option("--narrate",    is_flag=True, help="AI diff explanation  (needs GROQ_API_KEY)")
@click.option("--explain",    is_flag=True, help="Numbered fix guidance for each found issue (Groq optional)")
@click.option("--mode",       type=click.Choice(["eli5", "beginner", "dev"]), default=None,
              help="AI explanation style (default: dev, or set in .codesentry)")
@click.option("--commits",    default=1, type=int,
              help="Number of recent commits to scan (default: 1)")
@click.option("--output",          type=click.Choice(["text", "json"]), default="text",
              help="Output format: text (default) or json (CI/dashboard friendly)")
@click.option("--full",            is_flag=True,
              help="Scan entire repo, not just last commit")
@click.option("--baseline",        is_flag=True,
              help="Only report issues not in the saved baseline")
@click.option("--baseline-init",   is_flag=True,
              help="Save current issues as the baseline (run once on existing repos)")
@click.option("--baseline-commit", is_flag=True,
              help="Commit the baseline file to the repo (share with team)")
def main(path, autofix, copy, one_prompt, strict, compact, narrate, explain,
         mode, commits, output, full, baseline, baseline_init, baseline_commit):
    run_check(ScanConfig(
        path=path,
        autofix=autofix,
        copy=copy,
        one_prompt=one_prompt,
        strict=strict,
        compact=compact,
        narrate=narrate,
        explain=explain,
        mode=mode or "dev",
        commits=commits,
        output=output,
        full=full,
        baseline=baseline,
        baseline_init=baseline_init,
        baseline_commit=baseline_commit,
    ))


if __name__ == "__main__":
    main()
