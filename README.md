
# codesentry

**Real-time security scanner for AI-generated code.**  
Catches hardcoded secrets, SQL injection, shell injection, unsafe deserialization, and 14 more patterns — before they reach git.

```
pip install codesentry
codesentry check
```

---

## Why codesentry

AI coding assistants write fast but cut corners. They hardcode API keys, build SQL by string concatenation, swallow exceptions silently, and leave `DEBUG = True` in production paths. These bugs are boring to explain but expensive to fix after a breach.

codesentry scans your last commit in under a second, prints a table of exactly what's wrong and why, and generates a ready-to-paste fix prompt you can drop straight into Claude or ChatGPT to get corrected code back immediately.

---

## Install

```bash
pip install codesentry
```

Requires Python 3.10+. No API key needed for scanning — only for AI-powered explanation and narration features.

---

## Quick start

```bash
# Scan the last commit in the current repo
codesentry check

# Scan entire repo (not just last commit)
codesentry check --full

# Scan a specific path
codesentry check path/to/project

# Strict mode — also fail on MED issues
codesentry check --strict

```

---

## Commands

### `codesentry check` — scan for security issues

```
codesentry check [PATH] [OPTIONS]
```

| Option | Description |
|--------|-------------|
| `--full` | Scan entire repo, not just last commit |
| `--commits N` | Scan last N commits (default: 1) |
| `--strict` | Fail on MED issues too (default: HIGH only) |
| `--compact` | One line per issue — CI-friendly |
| `--output json` | Machine-readable JSON output |
| `--autofix` | Generate copy-paste fix prompts per issue |
| `--one-prompt` | Combine all fix prompts into one |
| `--copy` | Copy fix prompt to clipboard |
| `--explain` | Numbered fix guidance per issue |
| `--narrate` | AI plain-English diff explanation (needs `GROQ_API_KEY`) |
| `--mode eli5\|beginner\|dev` | AI explanation style (default: dev) |
| `--baseline` | Only report issues not in saved baseline |
| `--baseline-init` | Save current issues as baseline |
| `--baseline-commit` | Commit baseline file to repo |

**Example output:**

```
 codesentry — 3 issues found
─────────────────────────────────────────────────────────
 HIGH  P1          auth.py:12      Hardcoded secret
       Ships to GitHub and gets scraped by bots within hours.

 HIGH  P_SQL       db.py:34        SQL string injection
       Dynamic SQL via string interpolation — SQL injection risk.

 MED   P5          app.py:78       TODO in production path
       AI placeholder left in code that actually runs in production.
─────────────────────────────────────────────────────────
 Result: FAIL  (2 HIGH · 1 MED)
```

**JSON output** (for dashboards and CI):

```bash
codesentry check --output json
```

```json
{
  "codesentry_version": "1.0.0",
  "scanned_files": 12,
  "summary": { "HIGH": 2, "MED": 1, "LOW": 0 },
  "passed": false,
  "issues": [
    {
      "id": "P1",
      "severity": "HIGH",
      "file": "auth.py",
      "line": 12,
      "name": "Hardcoded secret",
      "why": "Ships to GitHub and gets scraped by bots within hours.",
      "context": "api_key = \"sk-abc123\""
    }
  ]
}

```

---


### `codesentry hook` — global git pre-commit hook

Installs a single git hook that runs automatically on every commit across all your repos. No per-project setup.

```bash
# Install
codesentry hook install

# Install with strict mode (blocks MED + HIGH)
codesentry hook install --strict

# Uninstall
codesentry hook uninstall

# Check current status
codesentry hook status
```

**Per-repo opt-out** — if one repo should skip the hook:

```bash
git config codesentry.disable true
```

**Per-repo strict override:**

```bash
git config codesentry.strict false   # loosen for this repo
git config codesentry.strict true    # tighten for this repo
```

---

### `codesentry setup` — configure your Groq API key

Required only for `--narrate` and `--explain` features.

```bash
# Interactive setup (asks where to store the key)
codesentry setup

# Save globally — works across all projects
codesentry setup --global

# Save locally — this project only (.vibe_env)
codesentry setup --local
```

Key lookup order at runtime:
1. `GROQ_API_KEY` environment variable
2. `.vibe_env` in current directory
3. `~/.codesentry/config` global file

---

### `codesentry prompt` — version control for prompt files

Track, diff, and roll back your AI prompt files — same way git tracks code.

```bash
# Initialise prompt tracking in current directory
codesentry prompt init

# Save current version of a prompt file
codesentry prompt save system_prompt.txt

# List all saved versions
codesentry prompt log system_prompt.txt

# Diff two versions
codesentry prompt diff system_prompt.txt v1 v2

# Roll back to a previous version
codesentry prompt checkout system_prompt.txt v3

```

---


## Security rules

18 patterns across Python, JavaScript, TypeScript, JSX, TSX, YAML, JSON, and shell scripts.

| ID | Severity | What it catches |
|----|----------|-----------------|
| `P1` | HIGH | Hardcoded API key / password / secret |
| `P1b` | HIGH | High-entropy string (likely raw JWT or key) |
| `P1_YAML` | HIGH | Secret in YAML or `.env` file |
| `P_SQL` | HIGH | SQL injection via string interpolation |
| `P_SQL_CONCAT` | HIGH | SQL injection via string concatenation |
| `P_CONNSTR` | HIGH | Password embedded in connection string |
| `P_SHELL` | HIGH | `os.system` / `shell=True` — command injection |
| `P_DESER` | HIGH | `pickle.loads` / `yaml.load` without `Loader` |
| `P_EVAL` | HIGH | `eval`/`exec` on user-controlled input |
| `P_ADMIN` | HIGH | Hardcoded admin / root credentials |
| `P2` | HIGH | `except: pass` — silent failure (Python) |
| `P3` | HIGH | `.catch(() => {})` — swallowed error (JS/TS) |
| `P4` | HIGH | Token or password written to log |
| `P7` | MED | `except Exception: pass` — broad swallow |
| `P5` | MED | `TODO` / `FIXME` in a live code path |
| `P6` | MED | Hardcoded `localhost` or `127.0.0.1` |
| `P8` | LOW | `DEBUG = True` or `NODE_ENV=development` |
| `P_NOVALIDATE` | MED | API route with no input validation hint *(strict only)* |

---

## Suppressing false positives

Add an inline comment to skip a specific line:

```python
# Skip all rules on this line
url = "http://localhost:3000"   # codesentry-ignore

# Skip only a specific rule
api_key = os.getenv("API_KEY")  # codesentry-ignore: P1

```

---

## Baseline workflow

Useful when onboarding codesentry onto an existing repo that already has issues you're not ready to fix:

```bash
# 1. Record current issues as accepted baseline
codesentry check --baseline-init

# 2. From now on, only report NEW issues
codesentry check --baseline

# 3. Share baseline with your team
codesentry check --baseline-commit
```

---

## CI integration

### GitHub Actions

```yaml
- name: Security scan
  run: |
    pip install codesentry
    codesentry check --compact --output json
```

Fails the workflow if any HIGH issue is found. Add `--strict` to also fail on MED.

### Pre-commit (alternative to the global hook)

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: codesentry
        name: codesentry security scan
        entry: codesentry check
        language: system
        pass_filenames: false
```

---

## Configuration file

Create `.codesentry` in your project root or `~/` to set defaults:

```ini
mode    = dev        # eli5 | beginner | dev
strict  = false
compact = false
```

---

## VS Code extension

The **VibeGuard** VS Code extension connects directly to the codesentry CLI for enhanced AST scanning. When `codesentry` is detected in your PATH, the extension automatically upgrades from its built-in TypeScript scanner to full Python AST mode.

Features added by the extension on top of the CLI:
- Inline red/amber squiggles as you type (1.5 s debounce)
- Lightbulb quick-fix menu with copy-to-Claude prompt
- Live security dashboard (`Ctrl+Shift+V`) — real-time issue counts, category breakdown, one-click fix-all prompt
- Scan on save, scan on open, workspace-wide scan

Install from the VS Code Marketplace: search **VibeGuard** or **codesentry**.


---

## License


MIT — see [LICENSE](LICENSE)

---

## Links

- [GitHub](https://github.com/Jen-chad/vibe-tools)
- [VS Code Marketplace](https://marketplace.visualstudio.com/items?itemName=jenchad.codesentry)
- [Issue tracker](https://github.com/Jen-chad/vibe-tools/issues)

