"""
vibe_tools/setup.py — API key management & onboarding
Handles load_api_key(), save_global_key(), save_local_key(), interactive_setup()
and the `vibe-tools setup` CLI command.
"""

import os
import sys
import platform
from pathlib import Path

from rich.console import Console
from rich.panel import Panel

# ─── paths ──────────────────────────────────────────────────────────────────

def _global_config_path() -> Path:
    """Return the path to the global config file (cross-platform)."""
    if platform.system() == "Windows":
        base = Path(os.environ.get("USERPROFILE", Path.home()))
    else:
        base = Path.home()
    return base / ".vibe-tools" / "config"


def _local_env_path() -> Path:
    """Return the path to the local .vibe_env file."""
    return Path(".") / ".vibe_env"


# ─── loaders ────────────────────────────────────────────────────────────────

def load_api_key() -> str | None:
    """
    Load GROQ_API_KEY with priority:
      1. os.environ["GROQ_API_KEY"]
      2. ./.vibe_env  (local project)
      3. ~/.vibe-tools/config  (global)
    Returns the key string or None if not found.
    Sets os.environ["GROQ_API_KEY"] as a side-effect when found in a file.
    """
    # 1. Already in environment
    if key := os.environ.get("GROQ_API_KEY"):
        return key

    # 2. Local .vibe_env
    local = _local_env_path()
    if local.exists():
        key = _read_key_from_file(local)
        if key:
            os.environ["GROQ_API_KEY"] = key
            return key

    # 3. Global config
    global_cfg = _global_config_path()
    if global_cfg.exists():
        key = _read_key_from_file(global_cfg)
        if key:
            os.environ["GROQ_API_KEY"] = key
            return key

    return None


def _read_key_from_file(path: Path) -> str | None:
    """Parse GROQ_API_KEY=xxxx from a config file. Returns value or None."""
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line.startswith("GROQ_API_KEY="):
                value = line.split("=", 1)[1].strip()
                if value:
                    return value
    except OSError:
        pass
    return None


# ─── savers ─────────────────────────────────────────────────────────────────

def save_global_key(key: str) -> Path:
    """Save GROQ_API_KEY to the global config file. Returns the file path."""
    config_path = _global_config_path()
    config_path.parent.mkdir(parents=True, exist_ok=True)
    _write_key_to_file(config_path, key)
    return config_path


def save_local_key(key: str) -> Path:
    """Save GROQ_API_KEY to ./.vibe_env. Returns the file path."""
    local_path = _local_env_path()
    _write_key_to_file(local_path, key)
    return local_path


def _write_key_to_file(path: Path, key: str) -> None:
    """
    Write (or update) GROQ_API_KEY in a config file.
    Preserves any other lines that may exist.
    """
    existing_lines: list[str] = []
    if path.exists():
        try:
            existing_lines = path.read_text(encoding="utf-8").splitlines()
        except OSError:
            pass

    # Replace existing GROQ_API_KEY line or append
    new_line = f"GROQ_API_KEY={key}"
    updated = False
    result_lines = []
    for line in existing_lines:
        if line.strip().startswith("GROQ_API_KEY="):
            result_lines.append(new_line)
            updated = True
        else:
            result_lines.append(line)

    if not updated:
        result_lines.append(new_line)

    path.write_text("\n".join(result_lines) + "\n", encoding="utf-8")


# ─── interactive setup ──────────────────────────────────────────────────────

def _prompt_for_key(console: Console) -> str:
    """Prompt user for an API key, retrying on empty input."""
    while True:
        key = console.input("\n[bold]Enter your GROQ API key:[/bold] ").strip()
        if key:
            return key
        console.print("[red]  ✖  Key cannot be empty. Please try again.[/red]")


def _prompt_for_scope(console: Console) -> str:
    """
    Ask where to store the key: global or local.
    Returns 'global' or 'local'.
    """
    console.print("\n[bold cyan]Where should the key be saved?[/bold cyan]")
    console.print("  [bold]1.[/bold] Global (recommended) — [dim]~/.vibe-tools/config[/dim]")
    console.print("  [bold]2.[/bold] Local  — [dim]./.vibe_env  (this project only)[/dim]")

    while True:
        choice = console.input("\nEnter choice [1/2]: ").strip()
        if choice == "1":
            return "global"
        if choice == "2":
            return "local"
        console.print("[red]  ✖  Invalid choice. Enter 1 or 2.[/red]")


def _check_existing_key(console: Console, scope: str) -> bool:
    """
    If a key already exists at the chosen scope, ask the user if they want to overwrite.
    Returns True if we should proceed, False to abort.
    """
    path = _global_config_path() if scope == "global" else _local_env_path()
    existing = _read_key_from_file(path) if path.exists() else None

    if not existing:
        return True  # nothing there, proceed freely

    console.print(
        f"\n[yellow]⚠  A key already exists in "
        f"{'~/.vibe-tools/config' if scope == 'global' else '.vibe_env'}.[/yellow]"
    )
    answer = console.input("Overwrite it? [y/N]: ").strip().lower()
    return answer == "y"


def interactive_setup(console: Console, scope: str | None = None) -> bool:
    """
    Full interactive onboarding flow.
    scope: 'global' | 'local' | None (ask the user).
    Returns True if a key was saved, False if aborted.
    """
    console.print(Panel(
        "[bold cyan]vibe-tools Setup[/bold cyan]\n"
        "[dim]Stores your GROQ API key so you never have to set it manually.[/dim]",
        border_style="cyan"
    ))

    # Resolve scope
    if scope is None:
        scope = _prompt_for_scope(console)

    # Check for an existing key
    if not _check_existing_key(console, scope):
        console.print("[dim]Setup cancelled.[/dim]")
        return False

    # Get the key
    key = _prompt_for_key(console)

    # Save
    if scope == "global":
        saved_path = save_global_key(key)
        location_label = f"[bold]global[/bold] ([dim]{saved_path}[/dim])"
    else:
        saved_path = save_local_key(key)
        location_label = f"[bold]local[/bold] ([dim]{saved_path}[/dim])"

    # Load into current process
    os.environ["GROQ_API_KEY"] = key

    console.print(f"\n[bold green]✅ API key saved successfully[/bold green]")
    console.print(f"   Stored in: {location_label}\n")
    return True


# ─── auto-detection prompt (called from run_check) ──────────────────────────

def prompt_setup_if_missing(console: Console) -> bool:
    """
    If GROQ_API_KEY is not available, ask the user whether to run setup.
    Returns True if a key is now available (either was already set, or user set it),
    False if the user declined.
    """
    key = load_api_key()
    if key:
        return True

    console.print("\n[yellow]⚠  No GROQ_API_KEY found.[/yellow]")
    answer = console.input("Run setup now? [y/n]: ").strip().lower()

    if answer != "y":
        console.print("[dim]Skipping AI features — no key provided.[/dim]\n")
        return False

    return interactive_setup(console)


# ─── CLI command ─────────────────────────────────────────────────────────────

import click  # noqa: E402  (placed here to keep imports grouped by stdlib/third-party)


@click.command("setup")
@click.option("--global", "scope", flag_value="global", help="Store API key globally (~/.vibe-tools/config)")
@click.option("--local",  "scope", flag_value="local",  help="Store API key in current project (.vibe_env)")
def setup_cmd(scope):
    """
    Configure your GROQ API key for vibe-tools.

    \b
    Storage locations:
      --global   ~/.vibe-tools/config   (used across all projects)
      --local    ./.vibe_env            (current project only)

    If neither flag is given, you will be asked interactively.
    """
    console = Console()
    success = interactive_setup(console, scope=scope)
    if not success:
        sys.exit(1)