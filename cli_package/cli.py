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
from vibe_tools.setup import setup_cmd


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
@click.option("--autofix",    is_flag=True, help="Generate fix prompts for found issues")
@click.option("--copy",       is_flag=True, help="Copy autofix prompts to clipboard")
@click.option("--one-prompt", is_flag=True, help="Combine all fix prompts into one")
@click.option("--strict",     is_flag=True, help="Fail on MED issues too")
@click.option("--compact",    is_flag=True, help="One line per issue (CI-friendly)")
@click.option("--narrate",    is_flag=True, help="AI diff explanation  (needs GROQ_API_KEY)")
@click.option("--explain",    is_flag=True, help="Numbered fix guidance per issue (Groq optional)")
@click.option("--mode",       type=click.Choice(["eli5", "beginner", "dev"]), default=None,
              help="AI explanation style (default: dev, or set in .vibecheck)")
@click.option("--commits",    default=1, type=int,
              help="Number of recent commits to scan (default: 1)")
@click.option("--output",          type=click.Choice(["text", "json"]), default="text",
              help="Output format: text (default) or json (CI/dashboard friendly)")
@click.option("--full",            is_flag=True,
              help="Scan entire repo, not just last commit")
@click.option("--baseline",        is_flag=True,
              help="Only report issues not in the saved baseline")
@click.option("--baseline-init",   is_flag=True,
              help="Save current issues as baseline (run once on existing repos)")
@click.option("--baseline-commit", is_flag=True,
              help="Commit the baseline file to repo (share with team)")
def check(path, autofix, copy, one_prompt, strict, compact, narrate, explain,
          mode, commits, output, full, baseline, baseline_init, baseline_commit):
    """Scan code for AI-generated bugs."""
    from vibe_tools.vibecheck import run_check, ScanConfig

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