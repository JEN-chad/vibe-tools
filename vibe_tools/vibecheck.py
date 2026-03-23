"""
vibecheck — AI code risk scanner  v1.0.0
Scans AI-generated code for security issues before they reach git.

Default: scan last commit -> print table -> exit. Zero questions. Zero blocking.

USAGE
  vibecheck                   scan last commit, print table, exit
  vibecheck --autofix         also generate copy-paste fix prompts
  vibecheck --narrate         plain-English diff explanation  (needs GROQ_API_KEY)
  vibecheck --explain         interactive line explainer      (needs GROQ_API_KEY)
  vibecheck --strict          also fail on MED issues
  vibecheck --compact         one line per issue  (CI-friendly)
  vibecheck --commits 3       scan last 3 commits
  vibecheck path/to/repo      scan a specific directory

SUPPRESS FALSE POSITIVES  (add to any line)
  url = "http://localhost:3000"   # vibecheck-ignore
  key = os.getenv("KEY")         # vibecheck-ignore: P1

CONFIG  (.vibecheck in project root or ~/)
  mode    = dev        # eli5 | beginner | dev  (default: dev)
  strict  = false
  compact = false
"""

__version__ = "1.0.0"

import os
import re
import sys
import math
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
    click.echo(f"vibecheck {__version__}")
    ctx.exit()


# ─────────────────────────────────────────────────────────────────────────────
# CONFIG  — read once from .vibecheck, never ask interactively
# ─────────────────────────────────────────────────────────────────────────────

def load_config(path):
    cfg = {}
    for candidate in [
        os.path.join(path, ".vibecheck"),
        os.path.join(os.path.expanduser("~"), ".vibecheck"),
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
# INLINE SUPPRESSION  — # vibecheck-ignore  or  # vibecheck-ignore: P1,P2
# ─────────────────────────────────────────────────────────────────────────────

def _parse_ignore_ids(line_text):
    m = re.search(r"vibecheck-ignore(?::\s*([A-Za-z0-9_,\s]+))?", line_text, re.IGNORECASE)
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
        "id": "P_SQL", "severity": "HIGH", "name": "SQL string injection",
        "regex": r'(f["\']|\.format\s*\(|%\s*[({]).*?\b(SELECT|INSERT|UPDATE|DELETE|DROP|WHERE)\b',
        "extensions": [".py",".js",".ts",".jsx",".tsx"],
        "why": "Dynamic SQL via f-string or .format() — SQL injection risk.",
    },
    {
        "id": "P_SHELL", "severity": "HIGH", "name": "Shell injection risk",
        "regex": r"subprocess\.[a-z_]+\s*\(.*shell\s*=\s*True",
        "extensions": [".py"],
        "why": "shell=True with variable input allows arbitrary command execution.",
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

    joined     = _join_continuations(raw_text)
    clean      = _strip_comments(joined, ext)
    raw_lines  = raw_text.splitlines()
    ignore_map = _build_ignore_map(raw_lines)

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
                    cs, ce = max(0, lineno - 3), min(len(raw_lines), lineno + 2)
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
            cs, ce = max(0, lineno - 3), min(len(raw_lines), lineno + 2)
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
# vibecheck scan log

Append-only record of every vibecheck scan on this project.
Generated by vibecheck — https://github.com/Jen-chad/vibe-tools

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
    """All options for a single vibecheck run. Passed as one object, never as 10 args."""
    path:       str  = "."
    autofix:    bool = False
    copy:       bool = False
    one_prompt: bool = False
    strict:     bool = False
    compact:    bool = False
    narrate:    bool = False
    explain:    bool = False
    mode:       str  = "dev"
    commits:    int  = 1


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

    if not _git_available():
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
            f"[bold cyan]vibecheck[/bold cyan]  [dim]v{__version__}[/dim]\n"
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
            "[dim]Suppress a false positive: add  # vibecheck-ignore  "
            "or  # vibecheck-ignore: P1  to the flagged line.[/dim]"
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
    "P_SQL":       "Use parameterised queries instead of string formatting.\n  Before: f\"SELECT * FROM users WHERE id={uid}\"\n  After:  cursor.execute(\"SELECT * FROM users WHERE id=%s\", (uid,))",
    "P_SHELL":     "Remove shell=True and pass arguments as a list.\n  Before: subprocess.run(cmd, shell=True)\n  After:  subprocess.run([\"git\", \"status\"])",
    "P_DESER":     "For pickle: avoid deserialising untrusted data — no safe fix exists.\n  For yaml: add Loader=yaml.SafeLoader\n  Before: yaml.load(data)\n  After:  yaml.load(data, Loader=yaml.SafeLoader)",
    "P_EVAL":      "Never eval/exec user-controlled input. Find a safer alternative:\n  - Use ast.literal_eval() for simple data structures\n  - Use a lookup dict for dynamic dispatch",
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
  vibecheck                  scan last commit, print table, exit
  vibecheck --autofix        generate fix prompts for every issue
  vibecheck --narrate        plain-English diff summary (needs GROQ_API_KEY)
  vibecheck --explain        numbered fix guidance per issue (Groq optional)
  vibecheck --strict         also fail on MED issues
  vibecheck --compact        one line per issue (CI-friendly)
  vibecheck --commits 3      scan last 3 commits
  vibecheck path/to/repo     scan a specific directory

\b
Suppress a false positive on one line:
  url = "http://localhost:3000"   # vibecheck-ignore
  key = os.getenv("KEY")         # vibecheck-ignore: P1

\b
Set defaults in .vibecheck (project root or ~/):
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
              help="AI explanation style (default: dev, or set in .vibecheck)")
@click.option("--commits",    default=1, type=int,
              help="Number of recent commits to scan (default: 1)")
def main(path, autofix, copy, one_prompt, strict, compact, narrate, explain, mode, commits):
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
    ))


if __name__ == "__main__":
    main()
