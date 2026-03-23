# Vibeguard

> **The safety layer for AI-generated code.**
>
> *Stop committing bugs you didn't write.*

You paste AI code. You commit. Three weeks later an API key is scraped, or your app breaks silently in production with no logs, no trace, nothing to debug. Vibeguard sits at the one moment between "AI wrote it" and "it's in git forever" — your commit — and stops the ones that matter.

```
$ git commit -m "add auth"

╔═══════════════════════════════════════════════════════╗
║  vibeguard blocked this commit                        ║
║  HIGH severity issues must be fixed before committing ║
║                                                       ║
║  [HIGH] auth.py:14  → Hardcoded secret               ║
║  [HIGH] api.py:31   → SQL string injection            ║
║  [MED]  config.py:5 → Hardcoded localhost             ║
╚═══════════════════════════════════════════════════════╝
```

Install once. Guards every repo on your machine automatically. Zero config. Works offline.

🔗 [github.com/Jen-chad/vibe-tools](https://github.com/Jen-chad/vibe-tools) · Python 3.10+ · macOS · Linux · Windows · MIT

---

## 30-second install

```bash
pip install jenchad-guard
vibeguard hook install
```

Done. Every future `git commit` on your machine is now guarded. No per-repo setup. No config files to write. Just works.

Want to scan right now?

```bash
cd your-project
vibeguard check .
```

---

## Built for how you actually code today

If any of these sound familiar, this tool is for you:

- You paste code from ChatGPT, Claude, or Cursor and commit it without reading every line
- You've rotated an API key because it ended up in a public repo
- Your app broke in production with no error log because the AI wrapped everything in `except: pass`
- You've shipped `DEBUG=True` or `http://localhost:3000` into a live environment
- You're building with AI agents across multiple sessions and the codebase is drifting

Every other scanner was built for a world where humans write every line. Vibeguard was built for the world you're in now.

---

## What it catches

15 patterns tuned specifically for what AI assistants write carelessly:

| ID | Severity | What it catches | Why it matters |
|---|---|---|---|
| P1 | **HIGH** | Hardcoded secrets (API keys, tokens, passwords) | Scraped by bots within hours of a push |
| P1b | **HIGH** | High-entropy strings (raw JWTs, webhook keys) | Catches secrets with no keyword prefix |
| P_SQL | **HIGH** | SQL injection via f-strings or `.format()` | Classic AI habit — `f"SELECT * WHERE id={uid}"` |
| P_SHELL | **HIGH** | `subprocess` with `shell=True` | Allows arbitrary command execution |
| P_DESER | **HIGH** | `pickle.loads()` / `yaml.load()` without SafeLoader | Remote code execution if input is untrusted |
| P_EVAL | **HIGH** | `eval()`/`exec()` on user input | Remote code execution |
| P_ADMIN | **HIGH** | Hardcoded `admin` / `root` credentials | Trivial to exploit |
| P2 | **HIGH** | `except: pass` — silent error catch | App fails with no trace, no log |
| P3 | **HIGH** | Empty JS/TS catch blocks `.catch(() => {})` | Same as P2 but JavaScript |
| P4 | **HIGH** | Credentials printed to logs | Visible in every monitoring tool |
| P7 | **MED** | `except Exception: pass` — broad swallow | Bugs vanish completely in production |
| P5 | **MED** | TODO/FIXME left in production paths | AI placeholder running in live code |
| P6 | **MED** | Hardcoded `localhost` / `127.0.0.1` | Works locally, breaks every real deploy |
| P8 | **LOW** | `DEBUG=True` / `NODE_ENV=development` | Exposes stack traces in production |
| P_DUP | **MED** | Same function defined in multiple files | AI re-implements helpers across sessions |

Scans: `.py` `.js` `.ts` `.jsx` `.tsx` `.json` `.yaml` `.yml` `.sh` `.bash` `.env`

Auto-skips: `node_modules`, `dist`, `build`, `.next`, `__pycache__`, minified files, binaries, lock files, files over 500 KB.

---

## How it works

**Offline-first.** The scanner runs entirely on your machine. No internet required. No API key needed for the core scan.

**Git-aware.** Runs `git diff` and scans only the files that changed in your last commit — fast, targeted, no noise from the rest of the codebase. Falls back to a full scan on brand-new repos.

**Entropy scanning.** Beyond keyword matching, high-entropy strings (raw JWTs, webhook secrets, base64 keys) are caught by Shannon entropy analysis — no keyword prefix needed.

**Pre-commit hook.** Optionally installs itself as a global git hook so every `git commit` on your machine runs the scanner automatically and blocks if serious issues are found.

**Paper trail.** Every scan is appended to `VIBELOG.md` in your project root — an append-only history of what was found and when. Auto-added to `.gitignore` so it never pollutes `git status`.

**AI features** (optional, needs a free Groq key):
- `--narrate` — 3-bullet plain-English explanation of what the diff changed and why it's risky
- `--explain` — numbered fix guidance for each issue, with AI elaboration on your specific code

---

## Complete setup guide

### Step 1 — Install

```bash
pip install jenchad-guard
```

Verify:

```bash
vibeguard --version
# vibeguard 1.0.0
```

This installs three commands:

| Command | What it does |
|---|---|
| `vibeguard` | Main CLI — entry point for everything |
| `vibecheck` | Direct alias for the code scanner |
| `promptgit` | Direct alias for prompt version control |

---

### Step 2 — Install the global pre-commit hook

```bash
vibeguard hook install
```

This writes a hook to `~/.config/git/hooks/pre-commit` and sets `git config --global core.hooksPath` so every repo on your machine uses it automatically — existing and future projects alike.

Verify:

```bash
vibeguard hook status
```

From this point forward, any `git commit` that introduces a HIGH-severity issue is blocked until you fix it.

---

### Step 3 — (Optional) Add AI features with a free Groq key

The scanner works fully offline without this. But if you want plain-English diff explanations and AI-powered fix guidance, get a free Groq key at [console.groq.com](https://console.groq.com) — takes about two minutes.

Run the guided setup wizard:

```bash
vibeguard setup
```

Or set the key manually:

```bash
# macOS / Linux — add to ~/.bashrc or ~/.zshrc
export GROQ_API_KEY="your-key-here"

# Windows (Command Prompt)
set GROQ_API_KEY=your-key-here

# Windows (PowerShell)
$env:GROQ_API_KEY="your-key-here"
```

---

### Step 4 — (Optional) Create a `.vibecheck` config file

Drop a `.vibecheck` file in your project root (or `~/`) to set defaults without passing flags every time:

```
# .vibecheck
mode    = dev        # eli5 | beginner | dev  (AI explanation style)
strict  = false      # true = also fail on MED issues
compact = false      # true = one line per issue output
```

CLI flags always override the config file.

---

## Scanning your code

### Basic scan

```bash
cd your-project
vibeguard check .
```

Scans the files changed in your last git commit. Output:

```
╭──────────────────────────────────────────────╮
│         vibecheck  v1.0.0                    │
│         Scanned 4 file(s)                    │
╰──────────────────────────────────────────────╯

╭─── Scan results ─────────────────────────────────────────────────────╮
│ Severity │ File      │ Line │ Issue              │ Why it matters     │
│ HIGH     │ auth.py   │ 14   │ Hardcoded secret   │ Scraped within...  │
│ HIGH     │ api.py    │ 31   │ SQL string inject  │ Dynamic SQL via... │
│ MED      │ config.py │ 5    │ Hardcoded localhost│ Works locally...   │
╰──────────────────────────────────────────────────────────────────────╯

Summary:  2 HIGH  1 MED  0 LOW

Suppress a false positive: add  # vibecheck-ignore  or  # vibecheck-ignore: P1  to the flagged line.
Run with  --explain  for step-by-step fix guidance on each issue.
```

**Exit codes:** `1` if HIGH issues are found (blocks the hook). `0` if clean.

---

### All scan flags

#### `--explain` — numbered fix guidance (offline + optional AI)

After the scan, shows a numbered list of every issue. Type a number for instant fix guidance — before/after code examples for that specific pattern, no format to memorise, no transcription:

```bash
vibeguard check . --explain
```

```
Fix guidance  (enter number, or q to quit)

   1  auth.py:14   Hardcoded secret
   2  api.py:31    SQL string injection
   3  config.py:5  Hardcoded localhost

> 1

╭─── [P1] Fix guidance ──────────────────────────────────────────────╮
│ Issue:  Hardcoded secret                                            │
│ File:   auth.py  line 14                                            │
│ Why:    Ships to GitHub and gets scraped by bots within hours.      │
│                                                                     │
│ Code:                                                               │
│   api_key = "sk-abc123verylongsecret"                               │
│                                                                     │
│ How to fix:                                                         │
│   Replace the hardcoded value with an environment variable.         │
│   Before: api_key = "sk-abc123"                                     │
│   After:  api_key = os.getenv("API_KEY")                            │
╰─────────────────────────────────────────────────────────────────────╯
```

Works 100% offline. If `GROQ_API_KEY` is set, an AI elaboration panel appears below with 2-3 sentences targeted to your specific code.

---

#### `--narrate` — 3-bullet AI diff summary (needs Groq key)

Sends your git diff to Groq and returns a plain-English explanation of what changed and what could break:

```bash
vibeguard check . --narrate
vibeguard check . --narrate --mode eli5    # plain words, no jargon
vibeguard check . --narrate --mode dev     # technical, senior-engineer voice
```

Three explanation modes:

| Mode | Who it's for | Labels |
|---|---|---|
| `dev` (default) | Engineers who want the technical summary | Change · Impact · Risk |
| `beginner` | Junior devs or non-technical reviewers | What changed · Why · Risk |
| `eli5` | Anyone, plainest possible English | What changed · Why · Risk |

---

#### `--autofix` — generate fix prompts

For every issue found, generates a targeted prompt you can paste into Claude, ChatGPT, or Cursor to fix only that specific issue:

```bash
vibeguard check . --autofix           # one prompt per issue
vibeguard check . --autofix --one-prompt   # combine all into one prompt
vibeguard check . --autofix --copy         # copy prompt(s) to clipboard
```

Each prompt contains the file name, line number, the problematic code, and strict rules to fix only that issue — nothing else.

---

#### `--strict` — also block on MED issues

By default only HIGH issues block commits. Strict mode also blocks on MED:

```bash
vibeguard check . --strict
```

Recommended for production services or security-sensitive code.

---

#### `--compact` — one line per issue (CI-friendly)

```bash
vibeguard check . --compact
```

```
[HIGH] auth.py:14      → Hardcoded secret
[HIGH] api.py:31       → SQL string injection
[MED ] config.py:5     → Hardcoded localhost
```

No ANSI colour codes when piped — automatically clean for CI logs.

---

#### `--commits N` — scan more history

```bash
vibeguard check . --commits 3    # scan files changed in last 3 commits
vibeguard check . --commits 10   # useful after merging a large branch
```

---

#### `--mode` — set AI explanation style

```bash
vibeguard check . --mode eli5
vibeguard check . --mode beginner
vibeguard check . --mode dev
```

Can also be set permanently in `.vibecheck`.

---

### Suppressing false positives

Add a comment to any line to suppress that issue:

```python
# Suppress everything on this line
BASE_URL = "http://localhost:3000"   # vibecheck-ignore

# Suppress a specific pattern only (P6 = hardcoded localhost)
BASE_URL = "http://localhost:3000"   # vibecheck-ignore: P6

# Suppress multiple patterns
key = get_test_key()                 # vibecheck-ignore: P1, P1b
```

The suppress hint appears at the bottom of every scan that finds issues — you never need to memorise the syntax.

---

## The global git hook

The most useful Vibeguard feature. Install once, guard everything.

```bash
vibeguard hook install          # normal mode — blocks HIGH
vibeguard hook install --strict  # strict mode — blocks HIGH + MED
```

### Hook controls

```bash
vibeguard hook status           # show current status
vibeguard hook uninstall        # remove the hook entirely

vibeguard hook disable          # skip this repo only (hook stays on everywhere else)
vibeguard hook enable           # re-enable for this repo

vibeguard hook enable-strict    # block MED + HIGH globally
vibeguard hook disable-strict   # block HIGH only globally
```

### Per-repo overrides

```bash
# Turn strict ON for this repo (even if global strict is off)
git config vibe-tools.strict true

# Turn strict OFF for this repo (even if global strict is on)
git config vibe-tools.strict false

# Disable scanning entirely for this repo
git config vibe-tools.disable true
```

### Bypass in an emergency

```bash
git commit --no-verify -m "your message"
```

Use sparingly. The hook exists to protect you.

---

## VIBELOG — your scan history

Every scan automatically appends a timestamped entry to `VIBELOG.md` in your project root:

```markdown
# vibecheck scan log

Append-only record of every vibecheck scan on this project.

---

## 2026-03-21 14:32 UTC — 4 file(s) scanned
**Issues:** 2 HIGH  1 MED  0 LOW

| Severity | File | Line | Issue |
|----------|------|------|-------|
| HIGH | auth.py | 14 | Hardcoded secret |
| HIGH | api.py | 31 | SQL string injection |
| MED | config.py | 5 | Hardcoded localhost |
```

`VIBELOG.md` is automatically added to your `.gitignore` on first scan — it never pollutes `git status`.

---

## Prompt version control

Vibeguard includes `promptgit` — lightweight version control for the system prompts, AGENTS.md files, and instruction files that drive your AI workflow. Think of it as git specifically for `.md` and `.txt` prompt files.

### Why this exists

When you're iterating on a system prompt, you end up with `prompt_v1.md`, `prompt_v2_final.md`, `prompt_ACTUALLY_FINAL.md`. Promptgit replaces that chaos with a clean commit history and one-command rollback.

### Setup

```bash
cd your-project

# Initialise promptgit in this directory
vibeguard prompt init

# Tell it which files to track
vibeguard prompt add AGENTS.md
vibeguard prompt add system-prompt.txt
```

### Saving versions

```bash
vibeguard prompt commit -m "initial prompt"

# After editing your prompt:
vibeguard prompt commit -m "added JSON output rule"
vibeguard prompt commit -m "tightened response to 150 words"
```

### Viewing history

```bash
vibeguard prompt log
```

```
 Ref  │ Hash     │ Timestamp            │ Message                   │ Words
 v3   │ c4d5e6f7 │ 2026-03-21 11:30 UTC │ tightened response length │ 162
 v2   │ a1b2c3d4 │ 2026-03-21 10:00 UTC │ added JSON output rule    │ 148
 v1   │ 9f8e7d6c │ 2026-03-20 09:00 UTC │ initial prompt            │ 98
```

### Rolling back

```bash
vibeguard prompt rollback v1          # restore version 1
vibeguard prompt rollback 9f8e7d6c    # restore by hash
vibeguard prompt rollback HEAD        # restore most recent
```

Rollback shows you exactly what it will overwrite and asks for confirmation before doing anything.

---

## How Vibeguard compares

Most security tools were built for CI — they run after code is already pushed. Vibeguard runs at commit time, on your machine, before anything leaves.

| | **Vibeguard** | **Bandit** | **Semgrep** | **detect-secrets** | **Ruff** |
|---|:---:|:---:|:---:|:---:|:---:|
| AI-generated bug patterns | ✅ 15 built-in | ⚠️ Python only | ⚠️ Needs custom rules | ❌ | ❌ |
| SQL / shell injection | ✅ | ✅ Python only | ⚠️ Paid | ❌ | ❌ |
| Entropy-based secret detection | ✅ Built-in | ❌ | ⚠️ Paid | ✅ | ❌ |
| Duplicate function detection | ✅ Cross-file | ❌ | ❌ | ❌ | ❌ |
| Global git hook (one command) | ✅ | ⚠️ Per-repo | ⚠️ Per-repo | ⚠️ Per-repo | ⚠️ Per-repo |
| Scans only changed files | ✅ Auto via git diff | ❌ Full scan | ⚠️ CI mode only | ❌ Full scan | ❌ Full scan |
| Offline (no internet needed) | ✅ Core scan | ✅ | ✅ | ✅ | ✅ |
| AI narration of diff | ✅ Free (Groq) | ❌ | ❌ | ❌ | ❌ |
| Fix guidance per issue | ✅ Offline | ❌ | ❌ | ❌ | ❌ |
| Scan history (VIBELOG) | ✅ Auto | ❌ | ❌ | ❌ | ❌ |
| Prompt version control | ✅ Built-in | ❌ | ❌ | ❌ | ❌ |
| Zero config to start | ✅ | ✅ | ⚠️ | ✅ | ✅ |
| JS / TS / YAML / shell | ✅ | ❌ | ✅ | ✅ | ❌ |
| Free & open source | ✅ MIT | ✅ | ✅ Community | ✅ | ✅ |

**The right stack:** Vibeguard is not a replacement for Bandit or Ruff — it fills a different gap.

| Project type | Recommended |
|---|---|
| Python only | Vibeguard (safety + hook) + Ruff (style) + Bandit (deep Python security in CI) |
| Python + JS/TS | Vibeguard (safety + hook) + Ruff (Python style) |
| Security-critical | Vibeguard + Bandit + detect-secrets (all in CI) |
| Any AI-assisted project | Vibeguard as the first line — catches what AI gets wrong, regardless of language |

---

## Naming

Three names, one tool:

| Name | What it is |
|---|---|
| **Vibeguard** | The brand. What you call it, search for it, star on GitHub. |
| **jenchad-guard** | The PyPI package name (`pip install jenchad-guard`). PyPI requires globally unique names. |
| `vibeguard` / `vibecheck` / `promptgit` | The CLI commands installed on your machine. |

Same pattern as `Beautiful Soup` (installed as `beautifulsoup4`) and `Pillow` (the `PIL` fork).

---

## Troubleshooting

### `vibeguard: command not found`

The pip scripts directory isn't in your PATH:

```bash
pip install --force-reinstall jenchad-guard

# If still not found, add scripts to PATH:
python -m site --user-base
# → /home/yourname/.local
# Add /home/yourname/.local/bin to your PATH
```

### `--narrate` or `--explain` AI features not working

```bash
# Check the key is set
echo $GROQ_API_KEY        # macOS/Linux
echo %GROQ_API_KEY%       # Windows

# Run guided setup
vibeguard setup

# Or set manually
export GROQ_API_KEY="your-key-here"
```

The scanner and git hook work without a key — only AI features need it.

### `groq package not installed`

```bash
pip install groq
```

### Hook not blocking commits

```bash
vibeguard hook status

# If disabled for this repo:
git config --local vibe-tools.disable
# If prints "true":
vibeguard hook enable
```

### Need to commit urgently despite issues

```bash
git commit --no-verify -m "your message"
```

### Blocked commit but issue is a false positive

Add a suppression comment to the flagged line:

```python
url = "http://localhost:3000"   # vibecheck-ignore: P6
```

---

## Uninstalling

```bash
vibeguard hook uninstall
pip uninstall jenchad-guard
```

`hook uninstall` clears `core.hooksPath` from your global git config — git returns to default behaviour immediately.

---

## License

MIT — [github.com/Jen-chad/vibe-tools](https://github.com/Jen-chad/vibe-tools)
