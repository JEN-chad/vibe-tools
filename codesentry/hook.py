"""
codesentry hook manager
Installs / uninstalls a global git pre-commit hook that runs codesentry check.
Supports --strict mode (blocks MED + HIGH) with per-repo opt-out.
"""

import os
import sys
import stat
import subprocess
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich.align import Align

console = Console()

# ─── helpers ────────────────────────────────────────────────────────────────

def get_global_hooks_dir() -> Path | None:
    """Return the configured core.hooksPath, or None."""
    try:
        result = subprocess.run(
            ["git", "config", "--global", "core.hooksPath"],
            capture_output=True, text=True
        )
        p = result.stdout.strip()
        return Path(p).expanduser() if p else None
    except Exception:
        return None


def set_global_hooks_dir(path: Path):
    subprocess.run(
        ["git", "config", "--global", "core.hooksPath", str(path)],
        check=True
    )


def unset_global_hooks_dir():
    subprocess.run(
        ["git", "config", "--global", "--unset", "core.hooksPath"],
        check=True
    )


def default_hooks_dir() -> Path:
    return Path.home() / ".config" / "git" / "hooks"


HOOK_MARKER = "# codesentry managed hook"

HOOK_TEMPLATE = """\
#!/usr/bin/env sh
{marker}
# Installed by: codesentry hook install
# Uninstall:    codesentry hook uninstall
# Disable for this repo only:
#   git config codesentry.disable true
# ──────────────────────────────────────────────────

# 1. Per-repo opt-out
DISABLED=$(git config --local --get codesentry.disable 2>/dev/null || echo "false")
if [ "$DISABLED" = "true" ]; then
  exit 0
fi

# 2. Resolve strict flag: global setting, overridden by local repo config
STRICT_GLOBAL=$(git config --global --get codesentry.strict 2>/dev/null || echo "{strict_default}")
STRICT_LOCAL=$(git config --local --get codesentry.strict 2>/dev/null || echo "")

if [ -n "$STRICT_LOCAL" ]; then
  STRICT="$STRICT_LOCAL"
else
  STRICT="$STRICT_GLOBAL"
fi

# 3. Build codesentry command
CODESENTRY="codesentry"
if ! command -v codesentry >/dev/null 2>&1; then
  echo "[codesentry] codesentry not found in PATH — skipping hook"
  exit 0
fi

REPO_ROOT=$(git rev-parse --show-toplevel 2>/dev/null || echo ".")

if [ "$STRICT" = "true" ]; then
  $VIBECHECK "$REPO_ROOT" --scan-only --strict
else
  $VIBECHECK "$REPO_ROOT" --scan-only
fi

EXIT_CODE=$?
if [ $EXIT_CODE -ne 0 ]; then
  echo ""
  echo "  ╔═══════════════════════════════════════════════════════╗"
  echo "  ║  codesentry blocked this commit                       ║"
  if [ "$STRICT" = "true" ]; then
  echo "  ║  Strict mode: HIGH + MED issues must be fixed         ║"
  else
  echo "  ║  HIGH severity issues must be fixed before committing ║"
  fi
  echo "  ║                                                       ║"
  echo "  ║  To skip for this repo:                               ║"
  echo "  ║    git config codesentry.disable true                 ║"
  echo "  ║                                                       ║"
  echo "  ║  To disable strict mode for this repo:               ║"
  echo "  ║    git config codesentry.strict false                 ║"
  echo "  ╚═══════════════════════════════════════════════════════╝"
  echo ""
  exit 1
fi
exit 0
"""

# ─── commands ───────────────────────────────────────────────────────────────

@click.group()
def hook():
    """Manage the global codesentry git pre-commit hook."""
    pass


@hook.command("install")
@click.option("--strict", is_flag=True, default=False,
              help="Block commits with MED issues too (not just HIGH)")
@click.option("--hooks-dir", default=None, type=click.Path(),
              help="Custom directory for the global hooks (default: ~/.config/git/hooks)")
def install(strict: bool, hooks_dir: str | None):
    """Install codesentry as a global git pre-commit hook."""

    target_dir = Path(hooks_dir).expanduser() if hooks_dir else default_hooks_dir()
    target_dir.mkdir(parents=True, exist_ok=True)

    hook_file = target_dir / "pre-commit"

    # Don't clobber a non-vibe hook
    if hook_file.exists():
        content = hook_file.read_text(errors="ignore")
        if HOOK_MARKER not in content:
            console.print(
                f"[yellow]⚠  A pre-commit hook already exists at {hook_file}\n"
                f"   It was NOT written by codesentry. Remove it manually first,[/yellow]\n"
                f"   then re-run [bold]codesentry hook install[/bold]."
            )
            sys.exit(1)

    strict_default = "true" if strict else "false"
    hook_content = HOOK_TEMPLATE.format(
        marker=HOOK_MARKER,
        strict_default=strict_default
    )

    hook_file.write_text(hook_content, encoding="utf-8", errors="ignore")
    hook_file.chmod(hook_file.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)

    # Point git at this directory globally
    set_global_hooks_dir(target_dir)

    # Persist the strict default in global git config
    subprocess.run(
        ["git", "config", "--global", "codesentry.strict", strict_default],
        check=True
    )

    strict_label = "[bold red]ON[/bold red]" if strict else "[green]OFF[/green]"

    console.print(Panel(
        Align.center(
            f"[bold green]✓ codesentry global hook installed[/bold green]\n\n"
            f"Hook location : [cyan]{hook_file}[/cyan]\n"
            f"Strict mode   : {strict_label}\n\n"
            f"[dim]Every git commit on this machine will now be scanned.[/dim]\n\n"
            f"[bold]Per-repo controls:[/bold]\n"
            f"  Disable for one repo  → [yellow]git config codesentry.disable true[/yellow]\n"
            f"  Override strict here  → [yellow]git config codesentry.strict false[/yellow]\n"
            f"  Re-enable strict here → [yellow]git config codesentry.strict true[/yellow]"
        ),
        title="codesentry hook",
        border_style="green"
    ))


@hook.command("uninstall")
@click.option("--keep-dir", is_flag=True, default=False,
              help="Keep the hooks directory, just remove the pre-commit file")
def uninstall(keep_dir: bool):
    """Remove the global codesentry pre-commit hook."""

    hooks_dir = get_global_hooks_dir()
    if not hooks_dir:
        hooks_dir = default_hooks_dir()

    hook_file = hooks_dir / "pre-commit"

    if hook_file.exists():
        content = hook_file.read_text(errors="ignore")
        if HOOK_MARKER not in content:
            console.print(
                "[yellow]⚠  The pre-commit hook at that path was not installed by codesentry.[/yellow]\n"
                "   Remove it manually if you want."
            )
            sys.exit(1)
        hook_file.unlink()
        console.print(f"[green]✓ Removed hook:[/green] {hook_file}")
    else:
        console.print("[yellow]No codesentry hook file found.[/yellow]")

    # Unset the global hooksPath only if it points at our dir
    current = get_global_hooks_dir()
    if current and Path(current).resolve() == hooks_dir.resolve():
        try:
            unset_global_hooks_dir()
            console.print("[green]✓ Cleared core.hooksPath from global git config[/green]")
        except Exception:
            pass

    # Remove the global strict setting
    try:
        subprocess.run(
            ["git", "config", "--global", "--unset", "codesentry.strict"],
            capture_output=True
        )
    except Exception:
        pass

    console.print("[dim]codesentry will no longer scan commits globally.[/dim]")


@hook.command("status")
def status():
    """Show current hook installation status."""

    hooks_dir = get_global_hooks_dir()
    hook_file = (hooks_dir / "pre-commit") if hooks_dir else None
    installed = hook_file and hook_file.exists() and HOOK_MARKER in hook_file.read_text(errors="ignore")

    try:
        strict_global = subprocess.run(
            ["git", "config", "--global", "--get", "codesentry.strict"],
            capture_output=True, text=True
        ).stdout.strip() or "false"
    except Exception:
        strict_global = "false"

    status_icon = "[bold green]✓ Installed[/bold green]" if installed else "[red]✗ Not installed[/red]"
    strict_label = "[bold red]ON[/bold red]" if strict_global == "true" else "[green]OFF[/green]"

    console.print(Panel(
        f"Hook status   : {status_icon}\n"
        f"Hook location : [cyan]{hook_file or 'N/A'}[/cyan]\n"
        f"Strict mode   : {strict_label} [dim](global)[/dim]\n\n"
        f"[bold]Commands:[/bold]\n"
        f"  [yellow]codesentry hook install --strict[/yellow]   → enable strict mode\n"
        f"  [yellow]codesentry hook install[/yellow]            → disable strict mode\n"
        f"  [yellow]codesentry hook uninstall[/yellow]          → remove the hook\n\n"
        f"[bold]Per-repo override:[/bold]\n"
        f"  [yellow]git config codesentry.disable true[/yellow]  → skip this repo entirely\n"
        f"  [yellow]git config codesentry.strict false[/yellow]  → relax strict for this repo",
        title="codesentry hook status",
        border_style="cyan"
    ))


@hook.command("enable-strict")
@click.option("--local", "scope", flag_value="local", help="Enable only for current repo")
@click.option("--global", "scope", flag_value="global", default=True, help="Enable globally (default)")
def enable_strict(scope: str):
    """Enable strict mode (blocks MED + HIGH issues)."""
    subprocess.run(["git", "config", f"--{scope}", "codesentry.strict", "true"], check=True)
    console.print(f"[bold red]Strict mode ON[/bold red] ([dim]{scope}[/dim])")


@hook.command("disable-strict")
@click.option("--local", "scope", flag_value="local", help="Disable only for current repo")
@click.option("--global", "scope", flag_value="global", default=True, help="Disable globally (default)")
def disable_strict(scope: str):
    """Disable strict mode (only HIGH issues block commits)."""
    subprocess.run(["git", "config", f"--{scope}", "codesentry.strict", "false"], check=True)
    console.print(f"[green]Strict mode OFF[/green] ([dim]{scope}[/dim])")


@hook.command("disable")
def disable_repo():
    """Disable codesentry hook for the current repository only."""
    try:
        subprocess.run(
            ["git", "config", "--local", "codesentry.disable", "true"],
            check=True
        )
        console.print("[yellow]codesentry hook disabled for this repo.[/yellow]")
        console.print("[dim]Re-enable: git config codesentry.disable false[/dim]")
    except subprocess.CalledProcessError:
        console.print("[red]Not inside a git repo.[/red]")
        sys.exit(1)


@hook.command("enable")
def enable_repo():
    """Re-enable codesentry hook for the current repository."""
    try:
        subprocess.run(
            ["git", "config", "--local", "--unset", "codesentry.disable"],
            capture_output=True
        )
        console.print("[green]codesentry hook enabled for this repo.[/green]")
    except Exception:
        console.print("[red]Not inside a git repo.[/red]")
        sys.exit(1)
