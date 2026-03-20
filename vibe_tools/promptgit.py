import os
import json
import hashlib
from pathlib import Path
from datetime import datetime, timezone
import sys
import shutil

import click
from rich.console import Console
from rich.table import Table

def short_hash(text):
    return hashlib.sha256(text.encode('utf-8')).hexdigest()[:8]

def now_ts():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

def check_repo(path):
    repo_dir = Path(path) / ".promptgit"
    if not repo_dir.exists():
        print("Not a promptgit repo. Run: python promptgit.py init")
        sys.exit(1)
    return repo_dir

def safe_load_json(file_path, default):
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        print(f"Warning: Failed to load {file_path} - {e}")
        return default

def save_json(file_path, data):
    with open(file_path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2)

def resolve_ref(ref, history, commits_dir):
    commits = history.get("commits", [])
    if not commits:
        print(f"Version not found: {ref}")
        sys.exit(1)
        
    target_id = None
    if ref == "HEAD":
        target_id = commits[-1]["id"]
    elif ref.startswith("v") and ref[1:].isdigit():
        idx = int(ref[1:]) - 1
        if 0 <= idx < len(commits):
            target_id = commits[idx]["id"]
    else:
        # prefix match
        for c in commits:
            if c["id"].startswith(ref):
                target_id = c["id"]
                break
                
    if not target_id:
        print(f"Version not found: {ref}")
        sys.exit(1)
        
    commit_file = commits_dir / f"{target_id}.json"
    if not commit_file.exists():
        print(f"Version not found: {ref}")
        sys.exit(1)
        
    return safe_load_json(commit_file, None), target_id

@click.group()
def cli():
    pass

@cli.command()
@click.argument('filename')
@click.argument('path', default='.', type=click.Path())
def add(filename, path):
    repo_dir = check_repo(path)
    file_path = Path(path) / filename
    if not file_path.exists():
        print(f"File not found: {filename}")
        sys.exit(1)
        
    config_file = repo_dir / "config.json"
    config = safe_load_json(config_file, {"tracked_files": []})
    
    if filename not in config["tracked_files"]:
        config["tracked_files"].append(filename)
        save_json(config_file, config)
        
    print(f"✓ Tracking {filename}")

@cli.command()
@click.argument('path', default='.', type=click.Path())
def init(path):
    repo_dir = Path(path) / ".promptgit"
    if repo_dir.exists():
        print("Already initialised.")
        return
        
    repo_dir.mkdir(parents=True, exist_ok=True)
    (repo_dir / "commits").mkdir(exist_ok=True)
    
    save_json(repo_dir / "config.json", {"tracked_files": []})
    save_json(repo_dir / "history.json", {"commits": []})
    
    print(f"✓ Initialised promptgit in {path}")

@cli.command()
@click.option('-m', '--message', required=True, help="Commit message")
@click.argument('path', default='.', type=click.Path())
def commit(message, path):
    repo_dir = check_repo(path)
    config = safe_load_json(repo_dir / "config.json", {"tracked_files": []})
    
    if not config.get("tracked_files"):
        print("No files tracked. Run: python promptgit.py add <file> <path>")
        sys.exit(1)
        
    files_content = {}
    combined_content = []
    total_words = 0
    
    for filename in config["tracked_files"]:
        file_path = Path(path) / filename
        if file_path.exists():
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            files_content[filename] = content
            combined_content.append(content)
            total_words += len(content.split())
        else:
            files_content[filename] = ""
            combined_content.append("")
            
    full_text = "\n".join(combined_content)
    commit_id = short_hash(full_text)
    
    history_file = repo_dir / "history.json"
    history = safe_load_json(history_file, {"commits": []})
    commits = history.get("commits", [])
    
    if commits and commits[-1]["id"] == commit_id:
        print("Nothing changed.")
        return
        
    timestamp = now_ts()
    
    commit_data = {
        "id": commit_id,
        "message": message,
        "timestamp": timestamp,
        "word_count": total_words,
        "files": files_content
    }
    
    save_json(repo_dir / "commits" / f"{commit_id}.json", commit_data)
    
    summary = {
        "id": commit_id,
        "message": message,
        "timestamp": timestamp,
        "word_count": total_words
    }
    commits.append(summary)
    history["commits"] = commits
    save_json(history_file, history)
    
    print(f"[{commit_id}] {message}")

@cli.command()
@click.argument('path', default='.', type=click.Path())
def log(path):
    repo_dir = check_repo(path)
    history = safe_load_json(repo_dir / "history.json", {"commits": []})
    commits = history.get("commits", [])
    
    if not commits:
        print("No commits yet.")
        return
        
    console = Console()
    table = Table(show_header=True, header_style="bold")
    table.add_column("Ref")
    table.add_column("Hash")
    table.add_column("Timestamp")
    table.add_column("Message")
    table.add_column("Words")
    
    for i in range(len(commits) - 1, -1, -1):
        c = commits[i]
        ref = f"v{i + 1}"
        table.add_row(
            ref,
            c.get("id", ""),
            str(c.get("timestamp", "")),
            str(c.get("message", "")),
            str(c.get("word_count", 0))
        )
        
    console.print(table)

@cli.command()
@click.argument('ref')
@click.argument('path', default='.', type=click.Path())
def rollback(ref, path):
    repo_dir = check_repo(path)
    history = safe_load_json(repo_dir / "history.json", {"commits": []})
    
    commit_data, commit_id = resolve_ref(ref, history, repo_dir / "commits")
    if not commit_data:
        print(f"Version not found: {ref}")
        sys.exit(1)
        
    files = commit_data.get("files", {})
    num_files = len(files)
    
    print(f"About to restore {ref} ({commit_id}) — this will overwrite {num_files} file(s):")
    for filename in files.keys():
        print(f"  {filename}")
        
    ans = input("Continue? [y/N] ")
    if ans.strip().lower() != 'y':
        print("Cancelled.")
        sys.exit(0)
        
    for filename, content in files.items():
        file_path = Path(path) / filename
        file_path.parent.mkdir(parents=True, exist_ok=True)
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(content)
            
    print(f"✓ Restored {ref} ({commit_id}) — {num_files} file(s) written")
    for filename in files.keys():
        print(f"  {filename}")
    print()
    print("Tip: run commit -m 'after rollback' to save this state")

if __name__ == '__main__':
    cli()
