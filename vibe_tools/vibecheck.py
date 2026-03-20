import os
import re
import sys
import subprocess
from collections import defaultdict

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.align import Align
from rich import box

sys.stdout.reconfigure(encoding='utf-8')


def run_check(
    path,
    scan_only,
    autofix,
    copy,
    one_prompt,
    strict,
    compact,
    mode,
    commits
):
    console = Console()

    # ── Load API key (env → local .vibe_env → global config) ──────────────
    # This must happen before any Groq client is created.
    # If the key is absent, the user is offered an interactive setup flow.
    from vibe_tools.setup import load_api_key, prompt_setup_if_missing
    if not load_api_key():
        # prompt_setup_if_missing prints the warning and either runs setup
        # (loading the key into os.environ) or exits gracefully.
        api_available = prompt_setup_if_missing(console)
    else:
        api_available = True
    # ──────────────────────────────────────────────────────────────────────

    if not scan_only and not autofix and not mode:
        mode = choose_mode(console)

    if not os.path.exists(path):
        console.print(f"[red]Directory not found: {path}[/red]")
        sys.exit(1)

    # ---------------- FILE DETECTION (FIX 3, 6, 7) ---------------- #
    files_to_scan = []

    if not git_available():
        # FIX 6: git not found — full scan
        console.print(f"[yellow]git not found — scanning all files in {path}[/yellow]")
        all_exts = set()
        for p in PATTERNS:
            all_exts.update(p['extensions'])
        for dirpath, dirnames, filenames in os.walk(path):
            for fn in filenames:
                ext = os.path.splitext(fn)[1].lower()
                if ext in all_exts:
                    rel = os.path.relpath(os.path.join(dirpath, fn), path)
                    files_to_scan.append(rel)
    else:
        # FIX 3: --commits flag with fallback chain
        # 1. git diff HEAD~{commits}
        try:
            result = subprocess.run(
                ['git', 'diff', '--name-only', f'HEAD~{commits}'],
                cwd=path, capture_output=True, text=True, check=True
            )
            files_to_scan = [f for f in result.stdout.strip().split('\n') if f]
        except Exception:
            files_to_scan = []

        # 2. Fallback: git diff HEAD
        if not files_to_scan:
            try:
                result = subprocess.run(
                    ['git', 'diff', '--name-only', 'HEAD'],
                    cwd=path, capture_output=True, text=True
                )
                files_to_scan = [f for f in result.stdout.strip().split('\n') if f]
            except Exception:
                files_to_scan = []

        # 3. Fallback: staged only
        if not files_to_scan:
            try:
                result = subprocess.run(
                    ['git', 'diff', '--name-only'],
                    cwd=path, capture_output=True, text=True
                )
                files_to_scan = [f for f in result.stdout.strip().split('\n') if f]
            except Exception:
                files_to_scan = []

        # 4. Fallback: full scan
        if not files_to_scan:
            all_exts = set()
            for p in PATTERNS:
                all_exts.update(p['extensions'])
            for dirpath, dirnames, filenames in os.walk(path):
                for fn in filenames:
                    ext = os.path.splitext(fn)[1].lower()
                    if ext in all_exts:
                        rel = os.path.relpath(os.path.join(dirpath, fn), path)
                        files_to_scan.append(rel)

        # FIX 7: staged + untracked new files
        try:
            staged = subprocess.run(
                ['git', 'diff', '--name-only', '--cached'],
                cwd=path, capture_output=True, text=True
            ).stdout.strip().split('\n')
            files_to_scan += [f for f in staged if f]
        except Exception:
            pass

        try:
            untracked = subprocess.run(
                ['git', 'ls-files', '--others', '--exclude-standard'],
                cwd=path, capture_output=True, text=True
            ).stdout.strip().split('\n')
            files_to_scan += [f for f in untracked if f]
        except Exception:
            pass

        # Deduplicate files_to_scan
        files_to_scan = list(dict.fromkeys(files_to_scan))

    total_candidates = len(files_to_scan)

    # ---------------- SCAN (FIX 2, 4, 5, 8) ---------------- #
    issues = []
    scanned_count = 0

    for f in files_to_scan:
        full_path = os.path.join(path, f)

        # FIX 2: skip junk paths
        if should_skip(f):
            continue

        # FIX 8: skip symlinks
        if os.path.islink(full_path):
            continue

        # FIX 4: file size guard
        try:
            size_kb = os.path.getsize(full_path) / 1024
            if size_kb > MAX_FILE_KB:
                continue
        except OSError:
            continue

        # FIX 5: binary guard
        try:
            with open(full_path, 'rb') as fb:
                chunk = fb.read(512)
                if b'\x00' in chunk:
                    continue
        except OSError:
            continue

        # Only scan files that exist
        if not os.path.isfile(full_path):
            continue

        ext = os.path.splitext(f)[1].lower()

        try:
            with open(full_path, 'r', encoding='utf-8', errors="ignore") as file_obj:
                text = file_obj.read()
                lines = text.splitlines()
        except OSError:
            continue

        scanned_count += 1

        for p in PATTERNS:
            if ext in p['extensions']:
                for match in re.finditer(p['regex'], text, flags=re.IGNORECASE):
                    line_no = text.count('\n', 0, match.start()) + 1

                    # context (3 lines around)
                    start = max(0, line_no - 3)
                    end = min(len(lines), line_no + 2)
                    context = "\n".join(lines[start:end])

                    issues.append({
                        "severity": p["severity"],
                        "name": p["name"],
                        "why": p["why"],
                        "file": f,
                        "line": line_no,
                        "context": context
                    })

    # FIX 1: Deduplicate issues on (file, line, name)
    seen = set()
    deduped = []
    for i in issues:
        key = (i['file'], i['line'], i['name'])
        if key not in seen:
            seen.add(key)
            deduped.append(i)
    issues = deduped

    # FIX 9: Scanned file count display
    skipped_count = total_candidates - scanned_count
    if skipped_count > 0:
        scan_info = f"Scanned {scanned_count} file(s)  •  {skipped_count} skipped"
    else:
        scan_info = f"Scanned {scanned_count} file(s)"

    # ---------------- UI HEADER (FIX 9) ---------------- #
    console.print(Panel(
        Align.center(f"[bold cyan]VibeCheck – AI Code Risk Scanner[/bold cyan]\n{scan_info}"),
        border_style="cyan"
    ))

    # ---------------- SCAN-ONLY / AUTOFIX MODE ---------------- #
    if scan_only or autofix:
        if compact:
            print_compact(console, issues)
        else:
            print_issues_table(console, issues)
        render_summary(console, issues)

        if autofix and issues:
            console.print("\n[bold cyan]🔧 Autofix Prompts[/bold cyan]\n")
            if one_prompt:
                prompt_text = generate_combined_prompt(issues)
                console.print(Panel(prompt_text, title="Combined Autofix Prompt", border_style="green"))
                final_output = prompt_text
            else:
                prompts = []
                for i in issues:
                    prompt = generate_fix_prompt(i, i["file"], i["line"], i["context"])
                    console.print(Panel(prompt, title=f"{i['file']}:{i['line']}", border_style="green"))
                    prompts.append(prompt)
                final_output = "\n\n---\n\n".join(prompts)

            if copy:
                try:
                    import pyperclip
                    pyperclip.copy(final_output)
                    console.print("[green]Copied to clipboard[/green]")
                except ImportError:
                    console.print("[yellow]pyperclip not installed, skipping copy[/yellow]")

        if strict:
            if any(i["severity"] in ["HIGH", "MED"] for i in issues):
                sys.exit(1)
        else:
            if any(i["severity"] == "HIGH" for i in issues):
                sys.exit(1)

        return

    # ---------------- AI NARRATION ---------------- #
    narration = ""
    try:
        diff_text = subprocess.run(
            ["git", "diff", "HEAD"],
            cwd=path, capture_output=True, text=True
        ).stdout[:800]
    except Exception:
        diff_text = ""

    if diff_text and api_available and os.environ.get("GROQ_API_KEY"):
        from groq import Groq
        client = Groq(api_key=os.environ.get("GROQ_API_KEY"))

        response = client.chat.completions.create(
            model=select_model(len(diff_text)),
            max_tokens=150,
            messages=[
                {"role": "system", "content": get_prompt(mode)},
                {"role": "user", "content": diff_text}
            ]
        )

        narration = response.choices[0].message.content

    if narration:
        console.print(Panel(narration, title="Explanation", border_style="cyan"))

    # ---------------- RESULTS TABLE ---------------- #
    if compact:
        print_compact(console, issues)
    else:
        print_issues_table(console, issues)
    render_summary(console, issues)

    # ---------------- AUTOFIX ---------------- #
    if autofix and issues:
        console.print("\n[bold cyan]🔧 Autofix Prompts[/bold cyan]\n")
        if one_prompt:
            prompt_text = generate_combined_prompt(issues)
            console.print(Panel(prompt_text, title="Combined Autofix Prompt", border_style="green"))
            final_output = prompt_text
        else:
            prompts = []
            for i in issues:
                prompt = generate_fix_prompt(i, i["file"], i["line"], i["context"])
                console.print(Panel(prompt, title=f"{i['file']}:{i['line']}", border_style="green"))
                prompts.append(prompt)
            final_output = "\n\n---\n\n".join(prompts)

        if copy:
            try:
                import pyperclip
                pyperclip.copy(final_output)
                console.print("[green]Copied to clipboard[/green]")
            except ImportError:
                console.print("[yellow]pyperclip not installed, skipping copy[/yellow]")

    # ---------------- INTERACTIVE ---------------- #
    while True:
        user_input = console.input("\nExplain a line (file:line or q): ")

        if user_input.lower() == "q":
            break

        try:
            file, lines = user_input.split(":")
            line_numbers = [int(x.strip()) for x in lines.split(",")]
            explain_batch(os.path.join(path, file), line_numbers, mode, console)
        except Exception:
            console.print("[red]Invalid format[/red]")

    if strict:
        if any(i["severity"] in ["HIGH", "MED"] for i in issues):
            sys.exit(1)
    else:
        if any(i["severity"] == "HIGH" for i in issues):
            sys.exit(1)


# ---------------- MODEL SELECTOR ---------------- #
def select_model(size):
    if size < 300:
        return "llama-3.1-8b-instant"
    return "llama-3.3-70b-versatile"

# ---------------- PROMPT MODES ---------------- #
def get_prompt(mode):
    if mode == "eli5":
        return (
            "Explain like a 5-year-old.\n"
            "- Very simple words\n"
            "- Max 3 short lines\n"
            "- No technical words\n"
            "Format:\n• What changed\n• Why\n• Risk"
        )
    elif mode == "dev":
        return (
            "You are a senior engineer.\n"
            "- Be technical\n"
            "- Be concise\n"
            "Format:\n• Change\n• Impact\n• Risk"
        )
    return (
        "Explain for beginners.\n"
        "- Simple English\n"
        "- No jargon\n"
        "- Max 3 bullet points\n"
        "Format:\n• What changed\n• Why\n• Risk"
    )

# ---------------- MODE PICKER ---------------- #
def choose_mode(console):
    console.print("\n[bold cyan]Select explanation mode:[/bold cyan]")
    console.print("1. ELI5\n2. Beginner\n3. Dev")
    choice = console.input("Enter choice (1/2/3): ")
    return {"1": "eli5", "2": "beginner", "3": "dev"}.get(choice, "beginner")

# ---------------- AUTOFIX PROMPT ---------------- #
def generate_fix_prompt(issue, file_path, line_no, context):
    return f"""You are fixing a specific issue in code.

Issue: {issue['name']}
Why: {issue['why']}
File: {file_path}
Line: {line_no}

Rules:
* Fix ONLY the listed issues
* DO NOT modify unrelated code
* DO NOT refactor entire file
* DO NOT rename variables unless required
* DO NOT change formatting unnecessarily
* DO NOT introduce new features
* DO NOT re-run or re-analyze the code
* DO NOT create additional TODOs
* DO NOT loop or retry fixes
* Apply minimal, targeted changes only
* If unsure, leave the code unchanged

Task:
Fix ONLY this issue.

Output:
Return ONLY the updated code snippet.
Do NOT include explanations.

Code:
{context}
"""

def generate_combined_prompt(issues):
    prompt = """You are fixing multiple specific issues in a codebase.

STRICT RULES:
* Fix ONLY the listed issues
* Do NOT modify unrelated code
* Do NOT refactor entire files
* Do NOT change architecture
* Do NOT rename variables unless required
* Do NOT introduce new features
* Do NOT re-run fixes
* Do NOT loop or iterate
* Apply minimal targeted fixes only
* If a fix is unclear, skip it

Execution Constraints:
* Process each issue EXACTLY ONCE
* Do NOT revisit already fixed code
* Do NOT cascade changes
* Do NOT expand scope beyond given lines

Issues:"""
    for idx, i in enumerate(issues, 1):
        prompt += f"\n\n[Issue {idx}]\n"
        prompt += f"File: {i['file']}\n"
        prompt += f"Line: {i['line']}\n"
        prompt += f"Problem: {i['name']}\n"
        prompt += f"Why: {i['why']}\n"
        prompt += f"Code:\n{i['context']}"

    prompt += """

Output Format:
* Return updated code grouped by file
* Only include files that were changed
* No explanations
* No comments outside code"""
    return prompt

# ---------------- BATCH EXPLAINER ---------------- #
def explain_batch(file_path, line_numbers, mode, console):
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            lines = f.readlines()

        snippets = []
        for ln in line_numbers:
            if ln <= len(lines):
                snippets.append((ln, lines[ln - 1].strip()))

        if not snippets:
            console.print("[red]Invalid line number(s)[/red]")
            return

        api_key = os.environ.get("GROQ_API_KEY")
        if not api_key:
            console.print("[yellow]No GROQ_API_KEY set[/yellow]")
            return

        from groq import Groq
        client = Groq(api_key=api_key)

        # Build a single prompt that asks for one labelled explanation per line.
        # This keeps it to ONE API call regardless of how many lines are given,
        # while guaranteeing every line gets its own answer.
        numbered_block = "\n".join(f"[{ln}] {code}" for ln, code in snippets)
        labels = ", ".join(f"[{ln}]" for ln, _ in snippets)

        system_prompt = get_prompt(mode)
        user_msg = (
            f"Explain EACH of the following lines separately.\n"
            f"For every line, start your answer with its label exactly as shown "
            f"(e.g. {labels}), then give a short explanation (2-3 sentences max).\n"
            f"Cover every label — do not skip any.\n\n"
            f"{numbered_block}"
        )

        # max_tokens: 80 per line is generous but tight enough to stay cheap
        max_tok = min(80 * len(snippets), 500)

        response = client.chat.completions.create(
            model=select_model(len(user_msg)),
            max_tokens=max_tok,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_msg}
            ]
        )

        explanation = response.choices[0].message.content

        console.print(Panel(
            f"[bold]Lines:[/bold]\n{numbered_block}\n\n[bold]Explanations:[/bold]\n{explanation}",
            title="Batch Explanation",
            border_style="green"
        ))

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")

# ---------------- LINE EXPLAINER ---------------- #
def explain_line(file_path, line_no, mode, console):
    explain_batch(file_path, [line_no], mode, console)

# ---------------- PATTERNS (UNCHANGED) ---------------- #
PATTERNS = [
    {
        "id": "P1",
        "severity": "HIGH",
        "name": "Hardcoded secret",
        "regex": r"(api_key|password|secret|token)\s*[:=]\s*['\"][^'\"]{6,}['\"]",
        "extensions": [".py", ".js", ".ts", ".jsx", ".tsx", ".env", ".sh", ".bash", ".yaml", ".yml"],
        "why": "Ships to GitHub and gets scraped within hours."
    },
    {
        "id": "P2",
        "severity": "HIGH",
        "name": "Silent error catch",
        "regex": r"except\s*:\s*pass",
        "extensions": [".py"],
        "why": "Errors swallowed silently — app fails with no trace."
    },
    {
        "id": "P3",
        "severity": "HIGH",
        "name": "Empty catch block",
        "regex": r"catch\s*\([^)]*\)\s*\{\s*\}",
        "extensions": [".js", ".ts", ".jsx", ".tsx"],
        "why": "JavaScript errors ignored — silent failure in production."
    },
    {
        "id": "P4",
        "severity": "HIGH",
        "name": "Sensitive data in log",
        "regex": r"(console\.log|console\.error|print|logger\.\w+|log\.print)\s*\(.*?(token|key|password|secret)",
        "extensions": [".py", ".js", ".ts", ".jsx", ".tsx"],
        "why": "Credentials exposed in server logs and monitoring tools."
    },
    {
        "id": "P5",
        "severity": "MED",
        "name": "TODO in production path",
        "regex": r"#\s*TODO|//\s*TODO|#\s*FIXME|//\s*FIXME|<!--\s*TODO",
        "extensions": [".py", ".js", ".ts", ".jsx", ".tsx", ".sh", ".bash"],
        "why": "AI placeholder left in code that runs in production."
    },
    {
        "id": "P6",
        "severity": "MED",
        "name": "Hardcoded localhost",
        "regex": r"(localhost|127\.0\.0\.1|0\.0\.0\.0)",
        "extensions": [".py", ".js", ".ts", ".jsx", ".tsx", ".json", ".yaml", ".yml"],
        "why": "Works locally, breaks on every real deployment."
    },
    {
        "id": "P7",
        "severity": "MED",
        "name": "Missing error handling",
        "regex": r"except\s+Exception\s*:\s*\n\s*pass",
        "extensions": [".py"],
        "why": "Broad exception caught and ignored — bugs disappear silently."
    },
    {
        "id": "P8",
        "severity": "LOW",
        "name": "Hardcoded debug flag",
        "regex": r"(DEBUG|debug|APP_DEBUG|NODE_ENV)\s*=\s*(True|true|1|development|dev)",
        "extensions": [".py", ".js", ".ts", ".jsx", ".tsx", ".env", ".yaml", ".yml"],
        "why": "Debug mode left on — exposes internals in production."
    }
]

# ---------------- FIX 2: SKIP PATHS ---------------- #
SKIP_PATHS = [
    'node_modules', 'dist', 'build', '.next', '__pycache__',
    '.min.js', '.min.css', 'migrations', 'package-lock.json',
    'yarn.lock', 'poetry.lock', '.pyc', '.pyo', '.map',
    '.exe', '.dll', '.so', '.dylib', '.bin', '.png', '.jpg',
    '.jpeg', '.gif', '.svg', '.ico', '.woff', '.woff2',
    '.ttf', '.eot', '.pdf', '.zip', '.tar', '.gz'
]

def should_skip(filepath):
    fp = filepath.replace('\\', '/')
    return any(skip in fp for skip in SKIP_PATHS)

# ---------------- FIX 4: MAX FILE SIZE ---------------- #
MAX_FILE_KB = 500

# ---------------- FIX 6: GIT DETECTION ---------------- #
def git_available():
    try:
        subprocess.run(
            ['git', '--version'],
            capture_output=True, check=True
        )
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False


# ---------------- TABLE RENDERING ---------------- #
def print_compact(console, issues):
    if not issues:
        console.print("[bold green]✓ Clean[/bold green]")
        return

    order = {"HIGH": 0, "MED": 1, "LOW": 2}
    issues.sort(key=lambda x: order.get(x["severity"], 3))

    max_len = max(len(f"{i['file']}:{i['line']}") for i in issues)

    for i in issues:
        sev = i["severity"]

        if sev == "HIGH":
            sev_fmt = "[bold red][HIGH][/bold red]"
        elif sev == "MED":
            sev_fmt = "[yellow][MED ][/yellow]"
        else:
            sev_fmt = "[blue][LOW ][/blue]"

        file_line = f"{i['file']}:{i['line']}"
        padded = file_line.ljust(max_len + 2)

        console.print(
            f"{sev_fmt} {padded}→ {i['name']}"
        )

def print_issues_table(console, issues):
    if not issues:
        console.print()
        console.print(Panel(Align.center("[bold green]✓ Clean — no issues detected[/bold green]"), border_style="green"))
        console.print()
        return

    order = {"HIGH": 0, "MED": 1, "LOW": 2}
    issues.sort(key=lambda x: order.get(x["severity"], 3))

    console.print()
    table = Table(
        show_header=True,
        header_style="bold",
        box=box.ROUNDED,
        show_lines=True,
        expand=True,
        row_styles=["none", "on #1e1e1e"],
        padding=(0, 1)
    )
    table.add_column("Severity", min_width=10, justify="center")
    table.add_column("File", min_width=20, overflow="fold")
    table.add_column("Line", min_width=6, justify="center")
    table.add_column("Issue", min_width=30, overflow="fold")
    table.add_column("Why it matters", min_width=35, overflow="fold")

    for i in issues:
        sev = i['severity']
        if sev == "HIGH":
            sev_fmt = "[bold white on red] HIGH [/bold white on red]"
        elif sev == "MED":
            sev_fmt = "[bold black on yellow] MED [/bold black on yellow]"
        else:
            sev_fmt = "[bold white on blue] LOW [/bold white on blue]"

        table.add_row(
            sev_fmt,
            i['file'],
            str(i['line']),
            i['name'],
            i.get('why', '')
        )

    console.print(Panel(table, title="Regression Scan", border_style="red"))
    console.print()

# ---------------- SUMMARY ---------------- #
def render_summary(console, issues):
    counts = {"HIGH": 0, "MED": 0, "LOW": 0}
    for i in issues:
        counts[i["severity"]] = counts.get(i["severity"], 0) + 1

    console.print(
        f"\n[bold]Summary:[/bold] "
        f"[red]{counts['HIGH']} HIGH[/red]  "
        f"[yellow]{counts['MED']} MED[/yellow]  "
        f"[blue]{counts['LOW']} LOW[/blue]"
    )

# ---------------- CLI ---------------- #
@click.command()
@click.argument('path', default='.', type=click.Path())
@click.option('--scan-only', is_flag=True, help='Only run regression scan (no AI)')
@click.option('--autofix', is_flag=True, help='Generate AI prompts to fix issues')
@click.option('--copy', is_flag=True, help='Copy the generated prompt to clipboard')
@click.option('--one-prompt', is_flag=True, help='Combine all autofix prompts into one')
@click.option('--strict', is_flag=True, help='Fail on MED issues also')
@click.option('--compact', is_flag=True, help='Minimal output')
@click.option('--mode', type=click.Choice(['eli5', 'beginner', 'dev']), default=None)
@click.option('--commits', default=1, help='Number of recent commits to scan (default: 1)')
def main(path, scan_only, autofix, copy, one_prompt, strict, compact, mode, commits):
    run_check(path, scan_only, autofix, copy, one_prompt, strict, compact, mode, commits)


if __name__ == '__main__':
    main()