"""
jenchad-guard — unified CLI entry point

  vibeguard check       → scan code for issues
  vibeguard prompt      → version prompt files
  vibeguard hook        → manage the global git pre-commit hook
  vibeguard setup       → configure GROQ API key (global or local)
"""

import click
from rich.console import Console
from rich.panel import Panel
from rich.align import Align
from importlib.metadata import version

from vibe_tools.hook import hook
from vibe_tools.config import setup_cmd


# ─── constants ──────────────────────────────────────────────────────────────

APP_NAME = "jenchad-guard"
CLI_NAME = "vibeguard"
APP_VERSION = version(APP_NAME)


# ─── root group ─────────────────────────────────────────────────────────────

@click.group(invoke_without_command=True)
@click.version_option(APP_VERSION, prog_name=CLI_NAME)
@click.pass_context
def cli(ctx):
    """
    jenchad-guard — AI code safety & prompt versioning toolkit

    \b
    Commands:
      check    Scan code for AI-generated bugs
      prompt   Version and roll back prompt files
      hook     Manage the global git pre-commit hook
      setup    Configure your GROQ API key
    """
    if ctx.invoked_subcommand is None:
        console = Console()
        console.print(Panel(
            Align.center(
                f"[bold cyan]{CLI_NAME} v{APP_VERSION}[/bold cyan]\n\n"
                f"[dim]Run [bold]{CLI_NAME} --help[/bold] to see all commands[/dim]"
            ),
            border_style="cyan"
        ))


# ─── attach commands ─────────────────────────────────────────────────────────

cli.add_command(hook, name="hook")
cli.add_command(setup_cmd, name="setup")


# ─── CHECK COMMAND ──────────────────────────────────────────────────────────

@cli.command("check")
@click.argument("path", default=".", type=click.Path())
@click.option("--scan-only", is_flag=True, help="Only run regression scan (no AI)")
@click.option("--autofix", is_flag=True, help="Generate AI prompts to fix issues")
@click.option("--copy", is_flag=True, help="Copy autofix prompt to clipboard")
@click.option("--one-prompt", is_flag=True, help="Combine all autofix prompts into one")
@click.option("--strict", is_flag=True, help="Fail on MED issues also")
@click.option("--compact", is_flag=True, help="Minimal output")
@click.option("--mode", type=click.Choice(["eli5", "beginner", "dev"]), default=None)
@click.option("--commits", default=1, help="Number of recent commits to scan")
def check(path, scan_only, autofix, copy, one_prompt, strict, compact, mode, commits):
    """
    Scan code for AI-generated bugs.
    """
    from vibe_tools.vibecheck import run_check

    run_check(
        path,
        scan_only,
        autofix,
        copy,
        one_prompt,
        strict,
        compact,
        mode,
        commits
    )


# ─── PROMPT COMMAND ─────────────────────────────────────────────────────────

@cli.command("prompt", context_settings=dict(ignore_unknown_options=True, allow_extra_args=True))
@click.argument("args", nargs=-1, type=click.UNPROCESSED)
def prompt_cmd(args):
    """
    Version and roll back prompt files (wraps promptgit).
    """
    import sys
    from vibe_tools.promptgit import cli as promptgit_cli

    sys.argv = ["promptgit"] + list(args)
    promptgit_cli(standalone_mode=True)


# ─── backward compatibility entry points ─────────────────────────────────────

def vibecheck_entry():
    from vibe_tools.vibecheck import main
    main()


def promptgit_entry():
    from vibe_tools.promptgit import cli
    cli()