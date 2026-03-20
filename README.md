# Vibeguard



> AI-powered code safety scanner with a global git pre-commit hook — built for developers who ship fast with AI assistants.

Vibeguard catches the bugs that vibe-coded AI output almost always leaves behind: hardcoded secrets, silent crash handlers, localhost URLs, and debug flags that make it to production. It runs in your terminal, hooks into git globally, and optionally narrates what changed using Groq's free AI API.

🔗 GitHub: https://github.com/Jen-chad/vibe-tools

> Install via `pip install jenchad-guard`

Requires Python 3.10+. Works on macOS, Linux, and Windows.

---

## Table of Contents

1. [How it works](#how-it-works)
2. [How Vibeguard compares to other PyPI tools](#how-vibeguard-compares-to-other-pypi-tools)
3. [Installation](#installation)
4. [First-time setup](#first-time-setup)
5. [Scanning your code](#scanning-your-code)
6. [Understanding the output](#understanding-the-output)
7. [All scan options](#all-scan-options)
8. [The global git hook](#the-global-git-hook)
9. [Hook controls reference](#hook-controls-reference)
10. [Strict mode](#strict-mode)
11. [Prompt version control](#prompt-version-control)
12. [What Vibeguard detects](#what-vibeguard-detects)
13. [Troubleshooting](#troubleshooting)
14. [Uninstalling](#uninstalling)

---

## How it works

Vibeguard does three things:

**1. Pattern scanning** — reads the files changed in your last git commit (or all files if git isn't available) and checks them against 8 regex patterns that catch the most common AI-generated bugs. No internet connection required for this step.

**2. AI narration** — if you have a Groq API key set, it sends your git diff to a Groq LLM and gets back a plain-English explanation of what changed and what could break. This is optional; the scanner works fine without it.

**3. Pre-commit hook** — optionally installs itself as a global git hook so every `git commit` on your machine runs the scanner automatically, blocking the commit if serious issues are found.

---

## How Vibeguard compares to other PyPI tools

Most code analysis tools on PyPI were built for a world where humans write every line. Vibeguard was built for a world where AI writes most of it — and the mistakes AI makes are different. The table below maps every tool to its actual scope, then shows where Vibeguard is the only tool that covers the gap.

### At a glance

| | **Vibeguard** | **Bandit** | **Semgrep** | **detect-secrets** | **Ruff** | **Flake8 / Pylint** |
|---|:---:|:---:|:---:|:---:|:---:|:---:|
| **PyPI package** | `jenchad-guard` | `bandit` | `semgrep` | `detect-secrets` | `ruff` | `flake8` / `pylint` |
| **Primary purpose** | AI-generated bug safety | Python security (AST) | Multi-language SAST | Secrets only | Style & formatting | Style & lint |
| **Languages covered** | `.py` `.js` `.ts` `.jsx` `.tsx` `.yaml` `.sh` `.env` | Python only | 30+ languages | All file types (secrets only) | Python only | Python only |
| **Hardcoded secrets** | ✅ Built-in | ✅ Python only | ✅ Paid tier for full coverage | ✅ Specialised (25+ detectors) | ❌ | ❌ |
| **Silent `except: pass`** | ✅ Python + JS/TS | ✅ Python only | ⚠️ Needs custom rules | ❌ | ⚠️ Partial (B110 via plugin) | ⚠️ Partial |
| **Sensitive data in logs** | ✅ Built-in | ❌ | ⚠️ Needs custom rules | ❌ | ❌ | ❌ |
| **Hardcoded localhost** | ✅ Built-in | ❌ | ⚠️ Needs custom rules | ❌ | ❌ | ❌ |
| **TODO / FIXME in production** | ✅ Built-in | ❌ | ⚠️ Needs custom rules | ❌ | ⚠️ Via plugin only | ⚠️ Via plugin only |
| **Debug flag detection** | ✅ Built-in | ❌ | ⚠️ Needs custom rules | ❌ | ❌ | ❌ |
| **AI narration of what changed** | ✅ Free (Groq) | ❌ | ❌ | ❌ | ❌ | ❌ |
| **AI fix prompt generation** | ✅ Built-in | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Global git hook (one command)** | ✅ `vibeguard hook install` | ⚠️ Manual per-repo setup | ⚠️ Manual per-repo setup | ⚠️ Manual per-repo setup | ⚠️ Manual per-repo setup | ⚠️ Manual per-repo setup |
| **Per-repo hook disable** | ✅ One git config line | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Strict mode (global + per-repo)** | ✅ Flag or git config | ❌ | ⚠️ Config file only | ❌ | ⚠️ Config file only | ⚠️ Config file only |
| **Scans only changed files** | ✅ Auto via `git diff` | ❌ Full scan always | ⚠️ CI mode only | ❌ Full scan | ❌ Full scan | ❌ Full scan |
| **Prompt version control** | ✅ Built-in (`promptgit`) | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Guided setup wizard** | ✅ `vibeguard setup` | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Zero config to start** | ✅ | ✅ | ⚠️ Rules file required | ✅ | ✅ | ⚠️ Noisy without config |
| **Free & open source** | ✅ MIT | ✅ Apache 2.0 | ✅ Community / 💰 Pro | ✅ Apache 2.0 | ✅ MIT | ✅ MIT |

### What each tool actually does — and where it stops

**Bandit** (`pip install bandit`)

Bandit is the gold standard for Python-specific security analysis. It uses AST (Abstract Syntax Tree) parsing rather than regex, which lets it catch complex patterns like unsafe `yaml.load()`, SQL injection risks, and insecure cryptography that regex-based tools miss entirely. In 2025 benchmarks on 50k LOC Django apps, Bandit averaged 15-second scans detecting 88% of issues — outpacing Pylint's 65% recall, though trailing Semgrep's 92% due to Semgrep's semantic analysis.

Where it stops: Bandit only covers Python. It has no rules for JavaScript, TypeScript, YAML, or shell scripts — the other languages AI coding assistants routinely generate. It has no AI narration, no global hook installer, and requires per-repo setup for any git hook integration. It also produces no guidance on *how to fix* what it finds.

**Semgrep** (`pip install semgrep`)

Semgrep supports static analysis across 30+ languages and includes SAST, supply chain scanning, and secrets detection. Its rule language lets you write checks that look like the code you're scanning, without wrestling with ASTs. For teams with a security engineer who can write rules, it is the most powerful static analysis option in this list.

Where it stops: In security contexts, Semgrep Community Edition misses many true positives because it can only analyze code within the boundaries of a single function or file. Cross-file and cross-function analysis, improved secrets detection, and AI-assisted triage require the paid AppSec Platform. Setup is also substantially heavier than every other tool here — rules must be configured before you get meaningful output, and the binary install is large.

**detect-secrets** (`pip install detect-secrets`)

detect-secrets operates through a system of plugins and filters covering 25+ secret types — AWS keys, GitHub tokens, Stripe keys, OpenAI keys, JWT tokens, Twilio keys, and more — using both regex-based detectors and entropy analysis for non-structured secrets. For the single job of keeping secrets out of commits, it is the most thorough specialised tool available.

Where it stops: detect-secrets *only* finds secrets. It has no awareness of silent error handling, localhost URLs, debug flags, or any other category of AI-generated bug. Analysis of the project's maintenance status based on PyPI release cadence determined that its maintenance is inactive — it hasn't seen any new versions released to PyPI in the past 12 months and could be considered discontinued.

**Ruff** (`pip install ruff`)

Ruff is an extremely fast Python linter and formatter written in Rust, aiming to replace Flake8, Black, isort, pydocstyle, pyupgrade, and autoflake in a single tool that runs tens to hundreds of times faster than any individual tool. On a 250k LOC module, Pylint takes about 2.5 minutes parallelised across 4 cores on an M1 Mac — Ruff covers the same ground in under a second. For style enforcement and formatting in Python projects, it is the right choice.

Where it stops: Ruff only covers Python. It is not a security tool — it has no rules for secrets, silent crash patterns, localhost URLs, or debug flags left on in production. Ruff's primary limitation is that it does not support custom lint rules. Every security or safety check must be re-implemented in Rust and merged into Ruff itself, which means gaps in AI-specific patterns will remain for a long time.

**Flake8 / Pylint** (`pip install flake8` / `pip install pylint`)

The traditional Python code quality workhorses. Pylint gives you a thorough quality score and catches logic issues that faster tools miss; Ruff has increasingly consolidated this category by reimplementing the rules of multiple tools in a single extremely fast binary. Neither Flake8 nor Pylint covers multi-language codebases, secrets, crash-hiding patterns, or any of the deployment risks Vibeguard targets.

### Customisability: how each tool lets you adapt it

| Customisation scenario | **Vibeguard** | Bandit | Semgrep | detect-secrets | Ruff |
|---|---|---|---|---|---|
| **Turn scanning on/off per repo** | `git config vibe-tools.disable true` — one line, no files changed | Manual hook removal | Manual | Manual | Manual |
| **Set severity threshold** | `--strict` flag or `git config vibe-tools.strict true/false` | `-l LOW/MEDIUM/HIGH` flag per run | Rule severity in YAML config | N/A | `--select` / `--ignore` flags |
| **Global default + per-repo override** | ✅ Full git config layering — global sets default, local overrides it | ❌ | ⚠️ Config files per repo only | ❌ | ⚠️ Config files per repo only |
| **Skip specific files or directories** | Auto-skips `node_modules`, `dist`, binaries, lock files | `--exclude` flag or `.bandit` config | `--exclude` patterns in CLI or config | `--exclude-files` regex | `exclude` list in `ruff.toml` |
| **Scan only recent history** | `--commits N` — scan last N commits | ❌ Always full scan | ❌ | ❌ | ❌ |
| **Output format** | Rich table, compact one-liner, or summary | Text, JSON, CSV, SARIF, XML | Text, JSON, SARIF | JSON, human-readable | Text, JSON, SARIF, JUnit, GitHub/GitLab annotations |
| **Explanation style** | `--mode eli5 / beginner / dev` — changes AI narration tone | ❌ | ❌ | ❌ | ❌ |
| **Copy fix prompt to clipboard** | `--copy` flag | ❌ | ❌ | ❌ | ❌ |
| **No config file required** | ✅ Everything works via flags and git config | ✅ | ⚠️ Need rules to get useful output | ✅ | ✅ sensible defaults |

### The right way to use these tools together

Vibeguard does not replace Bandit, Ruff, or detect-secrets — it fills a different gap. The tools complement each other:

| Your project | Recommended stack |
|---|---|
| Python only | Vibeguard (safety + hook) + Ruff (style) + Bandit (deep Python security in CI) |
| Python + JS/TS | Vibeguard (safety + hook) + Ruff (Python style) |
| Security-critical Python | Vibeguard (safety + hook) + Bandit + detect-secrets (in CI) |
| Any AI-assisted project | Vibeguard as the first line — catches what AI gets wrong, regardless of language |

The key distinction: every other tool here requires per-repo configuration to enforce anything at commit time. Vibeguard is the only tool that installs a global pre-commit hook with one command, works across every repo on your machine with no per-repo setup, and lets you relax or tighten that enforcement per repo in a single git config line.

---

## Installation

```bash
pip install jenchad-guard
```

This installs three commands:

| Command | What it does |
|---|---|
| `vibeguard` | Main CLI — the entry point for everything |
| `vibecheck` | Direct alias for the code scanner |
| `promptgit` | Direct alias for prompt version control |

Verify the install worked:

```bash
vibeguard --version
```

---

## First-time setup

Run the guided setup wizard once after installing:

```bash
vibeguard setup
```

The wizard will:

1. Ask you to paste your Groq API key (for AI narration). Get a free key at [console.groq.com](https://console.groq.com) — takes about two minutes.
2. Ask whether to save the key **globally** (works everywhere on your machine, recommended) or **locally** (only in the current project).
3. Confirm everything is working with a test scan.

If you skip setup, Vibeguard still works — the scanner and git hook run fine without a Groq key. Only the AI narration and line explanation features require it.

You can also set the key manually at any time:

```bash
# macOS / Linux
export GROQ_API_KEY="your-key-here"

# Windows (Command Prompt)
set GROQ_API_KEY=your-key-here

# Windows (PowerShell)
$env:GROQ_API_KEY="your-key-here"
```

To make it permanent, add the `export` line to your `~/.bashrc`, `~/.zshrc`, or equivalent shell config file.

---

## Scanning your code

Navigate to your project folder and run:

```bash
cd your-project
vibeguard check .
```

The `.` tells Vibeguard to scan the current directory. You can pass any path:

```bash
vibeguard check /path/to/any/project
```

By default, Vibeguard scans the files changed in your most recent git commit. If you're not in a git repo, it scans all supported files in the directory.

---

## Understanding the output

A typical run looks like this:

```
╭─────────────────────────────────────────────────────╮
│         VibeCheck – AI Code Risk Scanner            │
│              Scanned 4 file(s)                      │
╰─────────────────────────────────────────────────────╯

╭─── Explanation ──────────────────────────────────────╮
│ • auth.py added a login route. The API key is        │
│   hardcoded, which will be exposed if pushed.        │
│ • config.py has a localhost URL that will break      │
│   in any deployed environment.                       │
╰──────────────────────────────────────────────────────╯

╭─── Regression Scan ──────────────────────────────────╮
│ Severity │ File        │ Line │ Issue            │ Why │
│ HIGH     │ auth.py     │ 12   │ Hardcoded secret │ ... │
│ MED      │ config.py   │ 5    │ Hardcoded local  │ ... │
╰──────────────────────────────────────────────────────╯

Summary: 1 HIGH  1 MED  0 LOW
```

The top panel shows how many files were scanned. The Explanation panel (requires Groq key) gives a plain-English summary of what the AI changed and what risks it introduced. The Regression Scan table lists every issue found, sorted HIGH → MED → LOW. The Summary line at the bottom gives you a quick count.

If there are no issues, you'll see:

```
╭──────────────────────────────╮
│  ✓ Clean — no issues detected │
╰──────────────────────────────╯
```

**Exit codes** — Vibeguard exits with code `1` if blocking issues are found, and `0` if the scan is clean. This makes it work in CI/CD pipelines without extra configuration.

---

## All scan options

### `--scan-only` — skip AI narration

Runs the pattern scanner without calling the Groq API. Faster, works offline, and doesn't require an API key.

```bash
vibeguard check . --scan-only
```

Use this in CI/CD where you want deterministic, no-network scanning.

---

### `--compact` — one line per issue

Prints a minimal single-line format instead of the full table. Useful for scripts or very wide terminals.

```bash
vibeguard check . --compact
```

Output looks like:

```
[HIGH] auth.py:12      → Hardcoded secret
[MED ] config.py:5     → Hardcoded localhost
```

---

### `--mode` — choose explanation style

Controls how the AI narration is written. Three options:

```bash
vibeguard check . --mode eli5      # Explain Like I'm 5 — very simple, 3 lines max
vibeguard check . --mode beginner  # Plain English, no jargon (default)
vibeguard check . --mode dev       # Technical, concise, senior-engineer voice
```

If you don't pass `--mode`, Vibeguard will ask you to choose interactively.

---

### `--commits` — scan more history

By default, only the most recent commit is scanned. Use `--commits N` to look back further:

```bash
vibeguard check . --commits 3   # scan files changed in last 3 commits
vibeguard check . --commits 10  # scan last 10 commits
```

Useful after merging a large feature branch or when onboarding to a new codebase.

---

### `--autofix` — generate fix prompts

For every issue found, generates a targeted prompt you can paste into Claude, ChatGPT, or Cursor to fix that specific issue without touching the rest of the file.

```bash
vibeguard check . --autofix
```

Each prompt includes the file name, line number, the problematic code, and strict instructions to fix only that issue — nothing else.

---

### `--one-prompt` — combine all fixes into one prompt

Instead of one prompt per issue, packages all fixes into a single combined prompt:

```bash
vibeguard check . --autofix --one-prompt
```

Best used when you have 3–5 issues and want to hand them all to an AI assistant at once.

---

### `--copy` — copy the prompt to clipboard

Copies the generated fix prompt(s) directly to your clipboard so you can paste immediately:

```bash
vibeguard check . --autofix --copy
vibeguard check . --autofix --one-prompt --copy
```

Requires `pyperclip`, which is installed automatically with Vibeguard.

---

### `--strict` — also fail on MED issues

By default, Vibeguard only exits with code `1` (blocking) on HIGH issues. With `--strict`, MED issues also block:

```bash
vibeguard check . --strict
```

See the [Strict mode](#strict-mode) section for details on when to use this.

---

## The global git hook

The most powerful Vibeguard feature. Install it once and every `git commit` on your machine — in any project — automatically runs the scanner before the commit goes through.

### Installing the hook

```bash
vibeguard hook install
```

This does two things under the hood:

1. Writes a shell script to `~/.config/git/hooks/pre-commit`
2. Runs `git config --global core.hooksPath ~/.config/git/hooks`

Git's `core.hooksPath` setting makes git look for hooks in that directory for every repository on the machine. No per-repo setup needed — it works immediately for all existing and future projects.

### Installing with strict mode

```bash
vibeguard hook install --strict
```

With strict mode, the hook blocks commits that contain MED-severity issues as well as HIGH. Recommended for production services, security-sensitive code, or any project where code quality matters.

### What happens on a blocked commit

When the hook catches an issue and blocks your commit, you'll see:

```
╔═══════════════════════════════════════════════════════╗
║  vibeguard blocked this commit                        ║
║  HIGH severity issues must be fixed before committing ║
║                                                       ║
║  To skip for this repo:                               ║
║    git config vibe-tools.disable true                 ║
║                                                       ║
║  To disable strict mode for this repo:                ║
║    git config vibe-tools.strict false                 ║
╚═══════════════════════════════════════════════════════╝
```

The box also tells you exactly what command to run if you want to disable or relax the check for that specific repo.

### Temporarily bypassing the hook

If you need to commit something urgently and can't fix the issues right now, git's built-in bypass flag still works:

```bash
git commit --no-verify -m "your message"
```

Use this sparingly. The hook exists to protect you.

---

## Hook controls reference

### View current status

```bash
vibeguard hook status
```

Shows whether the hook is installed, where it lives, and what strict mode is currently set to — both globally and for the current repo.

---

### Remove the hook

```bash
vibeguard hook uninstall
```

Removes the pre-commit file and clears `core.hooksPath` from your global git config. Git returns to its default behaviour — no more automatic scanning on commit.

---

### Disable for one repo only

```bash
vibeguard hook disable
```

Adds `vibe-tools.disable = true` to the current repo's local git config. The global hook stays installed and works everywhere else — this repo alone is skipped.

```bash
vibeguard hook enable
```

Re-enables the hook for the current repo (removes the local disable flag).

---

### Toggle strict mode globally

```bash
vibeguard hook enable-strict    # block MED + HIGH globally
vibeguard hook disable-strict   # block HIGH only globally
```

---

### Override strict mode for one repo

You can override the global strict setting per-repo using git config directly:

```bash
# Turn strict ON for this repo (even if global strict is off)
git config vibe-tools.strict true

# Turn strict OFF for this repo (even if global strict is on)
git config vibe-tools.strict false

# Remove the local override — follow global setting again
git config --unset vibe-tools.strict
```

---

## Strict mode

Strict mode controls which severity levels block your workflow.

| Mode | Blocks commits on | Recommended for |
|---|---|---|
| Normal (default) | HIGH only | Most projects |
| Strict | HIGH + MED | Production services, security code, shared codebases |

**HIGH issues** are always serious: hardcoded secrets, silent error swallowing, credentials in logs. These have a direct path to production outages or security breaches.

**MED issues** are risky but not always wrong: TODO comments left in, localhost URLs, broad exception handlers. Sometimes intentional, often not. Strict mode says "we don't tolerate technical debt either."

You can mix and match: enable strict globally, then relax it for a specific repo where MED patterns are expected (like a config repo with intentional localhost entries):

```bash
# Global: strict on
vibeguard hook enable-strict

# This repo: relax strict
git config vibe-tools.strict false
```

---

## Prompt version control

Vibeguard includes `promptgit` — a lightweight version control system for the system prompts, instruction files, and AI context files that drive your AI-assisted workflow. Think of it like git, but purpose-built for `.md`, `.txt`, and prompt files.

### Why this exists

When you're iterating on a system prompt for Cursor, Claude, or any AI tool, you end up with `prompt_v1.md`, `prompt_v2_final.md`, `prompt_v2_final_ACTUALLY_FINAL.md`. Promptgit replaces that chaos with a clean commit history and one-command rollback.

### Setting up a prompt repo

```bash
cd your-project

# Initialise a .promptgit directory in this folder
vibeguard prompt init
```

### Tracking a file

```bash
# Tell promptgit which file(s) to version
vibeguard prompt add AGENTS.md
vibeguard prompt add system-prompt.txt
```

You can track multiple files. All tracked files are snapshotted together in every commit.

### Saving a version

```bash
vibeguard prompt commit -m "initial prompt"
```

After editing your prompt file:

```bash
vibeguard prompt commit -m "added JSON output rule"
vibeguard prompt commit -m "tightened response length to 150 words"
```

### Viewing history

```bash
vibeguard prompt log
```

Output:

```
 Ref  │ Hash     │ Timestamp            │ Message                     │ Words
 v3   │ c4d5e6f7 │ 2026-03-20 11:30 UTC │ tightened response length   │ 162
 v2   │ a1b2c3d4 │ 2026-03-20 10:00 UTC │ added JSON output rule      │ 148
 v1   │ 9f8e7d6c │ 2026-03-19 09:00 UTC │ initial prompt              │ 98
```

### Rolling back

```bash
# Restore a specific version by ref number
vibeguard prompt rollback v1

# Restore by hash prefix
vibeguard prompt rollback 9f8e7d6c

# Restore the most recent commit
vibeguard prompt rollback HEAD
```

Rollback shows you exactly which files it will overwrite and asks for confirmation before doing anything. After restoring, commit the rollback state to keep a clean history:

```bash
vibeguard prompt commit -m "rolled back to v1 — JSON format caused issues"
```

---

## What Vibeguard detects

| ID | Severity | Pattern | File types | Why it matters |
|---|---|---|---|---|
| P1 | HIGH | Hardcoded secret | `.py` `.js` `.ts` `.jsx` `.tsx` `.env` `.sh` `.yaml` | Secrets committed to git get scraped by bots within hours of pushing |
| P2 | HIGH | Silent error catch (`except: pass`) | `.py` | Exceptions swallowed silently — the app fails with no trace and no way to debug |
| P3 | HIGH | Empty JS catch block (`catch(e) {}`) | `.js` `.ts` `.jsx` `.tsx` | Same as P2 but for JavaScript — errors vanish without any record |
| P4 | HIGH | Sensitive data in logs | `.py` `.js` `.ts` `.jsx` `.tsx` | Tokens and passwords written to logs end up in monitoring tools and log aggregators |
| P5 | MED | TODO in production path | `.py` `.js` `.ts` `.jsx` `.tsx` `.sh` | AI assistants frequently leave TODO placeholders in code paths that actually run |
| P6 | MED | Hardcoded localhost | `.py` `.js` `.ts` `.json` `.yaml` | Works on your machine, breaks silently the moment it's deployed anywhere |
| P7 | MED | `except Exception: pass` | `.py` | Broad exception caught and discarded — bugs disappear completely in production |
| P8 | LOW | Hardcoded debug flag | `.py` `.js` `.ts` `.env` `.yaml` | `DEBUG=True` or `NODE_ENV=development` left on exposes internals in production |

Vibeguard scans these file extensions: `.py` `.js` `.ts` `.jsx` `.tsx` `.json` `.yaml` `.yml` `.sh` `.bash` `.env`

It automatically skips `node_modules`, `dist`, `build`, `.next`, `__pycache__`, minified files, binaries, images, lock files, and any file over 500 KB.

---

## Troubleshooting

### "No GROQ_API_KEY set"

The AI narration feature requires a Groq key. Run the setup wizard:

```bash
vibeguard setup
```

Or set the key manually in your shell profile (`~/.bashrc`, `~/.zshrc`, etc.):

```bash
export GROQ_API_KEY="your-key-here"
```

The scanner and git hook work fine without a key — only the narration and line explanation features require it.

---

### "vibeguard: command not found"

The pip scripts directory isn't in your PATH. Try:

```bash
pip install --force-reinstall jenchad-guard
```

If that doesn't fix it, find where pip installs scripts and add it to your PATH:

```bash
python -m site --user-base
# → /home/yourname/.local
# Add /home/yourname/.local/bin to your PATH
```

---

### "hook not working" / commits aren't being scanned

Check the hook status:

```bash
vibeguard hook status
```

If it shows the hook isn't installed, run `vibeguard hook install` again. If it shows installed but commits aren't being scanned, check whether the current repo has disabled the hook:

```bash
git config --local vibe-tools.disable
# If this prints "true", re-enable with:
vibeguard hook enable
```

---

### "Directory not found"

You passed a path that doesn't exist:

```bash
vibeguard check /wrong/path
# → Directory not found: /wrong/path
```

Make sure the path is correct, or run from inside the project:

```bash
cd your-project
vibeguard check .
```

---

### The hook blocked a commit but I need to commit anyway

Use git's bypass flag:

```bash
git commit --no-verify -m "your message"
```

Or disable the hook for this repo:

```bash
vibeguard hook disable
git commit -m "your message"
vibeguard hook enable   # re-enable when done
```

---

## Uninstalling

Remove the git hook first, then uninstall the package:

```bash
vibeguard hook uninstall
pip uninstall jenchad-guard
```

`hook uninstall` clears `core.hooksPath` from your global git config, so git returns to its default hook behaviour immediately.

---

## License

MIT
