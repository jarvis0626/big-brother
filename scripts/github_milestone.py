"""User-authorized private GitHub major-change checkpoints.

Authentication stays in Git Credential Manager. This script never writes or logs
a token and refuses to push unless the exact destination is verified private.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
OWNER = "jarvis0626"
NAME = "big-brother"
REMOTE = f"https://github.com/{OWNER}/{NAME}.git"
REPOSITORY_PATH = f"/repos/{OWNER}/{NAME}"
API = "https://api.github.com"
SECRET_PATTERNS = [re.compile(rb"gh[pousr]_[A-Za-z0-9]{36,}"),
                   re.compile(rb"github_pat_[A-Za-z0-9_]{70,}"),
                   re.compile(rb"sk-(?:proj-)?[A-Za-z0-9_-]{40,}"),
                   re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")]
EXCLUDED_PREFIXES = ("node_modules/", ".venv/", ".cache/", "build/", "dist/", "release/",
                     "training/data/", "training/cache/", "training/sources/")


class CheckpointError(RuntimeError):
    pass


def git(*args, capture=True, check=True, input=None, binary=False):
    result = subprocess.run(["git", "-c", "credential.interactive=never", *args], cwd=ROOT,
                            input=input, capture_output=capture, text=not binary,
                            encoding=None if binary else "utf-8", errors=None if binary else "replace",
                            env={**os.environ, "GIT_TERMINAL_PROMPT": "0"},
                            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
    if check and result.returncode:
        # Do not print command output, which could include a malformed remote containing credentials.
        raise CheckpointError(f"Git operation {args[0]} failed with exit code {result.returncode}.")
    return result


def credential():
    request = f"protocol=https\nhost=github.com\nusername={OWNER}\n\n"
    result = git("credential", "fill", input=request, check=False)
    if result.returncode:
        raise CheckpointError("Git Credential Manager has no usable GitHub credential. Sign in to GitHub through your credential manager and retry.")
    values = dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)
    token = values.get("password")
    if not token:
        raise CheckpointError("GitHub credential is missing. Sign in through Git Credential Manager and retry.")
    return token


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise CheckpointError("Unexpected GitHub API redirect was refused.")


class GitHub:
    def __init__(self):
        self.token = credential()
        self.opener = urllib.request.build_opener(NoRedirect)
        identity = self.request("GET", "/user")
        if identity.get("login", "").lower() != OWNER.lower():
            raise CheckpointError("Authenticated GitHub account does not match the configured repository owner.")

    def request(self, method, path, body=None, allow_missing=False):
        if not path.startswith("/") or path.startswith("//"):
            raise CheckpointError("Invalid API path")
        headers = {"Accept": "application/vnd.github+json", "Authorization": f"Bearer {self.token}",
                   "X-GitHub-Api-Version": "2026-03-10", "User-Agent": "Big-Brother-Milestone"}
        payload = json.dumps(body).encode("utf-8") if body is not None else None
        if payload:
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(API + path, data=payload, headers=headers, method=method)
        try:
            with self.opener.open(request, timeout=30) as response:
                return json.loads(response.read(1024 * 1024))
        except urllib.error.HTTPError as error:
            if allow_missing and error.code == 404:
                return None
            raise CheckpointError(f"GitHub API request failed with HTTP {error.code}; no credentials or headers were logged.") from None

    def ensure_private(self, create=False):
        repository = self.request("GET", REPOSITORY_PATH, allow_missing=True)
        created = False
        if repository is None:
            if not create:
                raise CheckpointError("Repository does not exist. Run --prepare to create the authorized private repository.")
            self.request("POST", "/user/repos", {"name": NAME, "description": "Windows process behavior observation with local evidence and trained anomaly scoring",
                         "private": True, "auto_init": False, "has_wiki": False})
            created = True
            repository = self.request("GET", REPOSITORY_PATH)
        if repository.get("private") is not True or repository.get("visibility") != "private":
            raise CheckpointError("Destination is not verified private. No code will be pushed.")
        if repository.get("full_name", "").lower() != f"{OWNER}/{NAME}".lower():
            raise CheckpointError("Unexpected repository identity. No code will be pushed.")
        if not repository.get("permissions", {}).get("push"):
            raise CheckpointError("GitHub account lacks repository push permission.")
        return repository, created


def ensure_remote():
    existing = git("remote", "get-url", "origin", check=False)
    if existing.returncode:
        git("remote", "add", "origin", REMOTE)
    elif existing.stdout.strip() != REMOTE:
        raise CheckpointError("Existing origin points elsewhere; it was preserved. Configure the intended private destination explicitly before retrying.")
    pushes = git("remote", "get-url", "--push", "--all", "origin").stdout.splitlines()
    if pushes != [REMOTE]:
        raise CheckpointError("Origin has an unexpected push destination; no push attempted.")


def audit_paths(*, staged_only=False):
    if staged_only:
        # Audit the exact index blobs that a commit would contain. Working-tree
        # edits and unrelated untracked files must not change the review scope.
        candidates = []
        listing = git("ls-files", "--cached", "--stage", "-z").stdout
        for entry in filter(None, listing.split("\0")):
            metadata, relative = entry.split("\t", 1)
            mode, object_id, stage = metadata.split()
            if stage != "0":
                raise CheckpointError("Resolve unmerged index entries before a milestone checkpoint.")
            if mode not in ("100644", "100755"):
                raise CheckpointError(f"Non-regular index candidate requires a separate review: {relative}")
            if not re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", object_id):
                raise CheckpointError("Invalid index object identity.")
            candidates.append((relative, object_id))
    else:
        listing = git("ls-files", "--cached", "--others", "--exclude-standard", "-z").stdout
        candidates = [(relative, None) for relative in filter(None, listing.split("\0"))]
    count, size = 0, 0
    for relative, object_id in candidates:
        normalized = relative.replace("\\", "/")
        target = (ROOT / relative).resolve()
        if not target.is_relative_to(ROOT):
            raise CheckpointError("A candidate path escapes the repository workspace.")
        if not staged_only and not target.is_file():
            continue
        filename = normalized.rsplit("/", 1)[-1].lower() if staged_only else target.name.lower()
        if normalized.startswith(EXCLUDED_PREFIXES) or filename in ("drive-index.html", "optc-access-sample.bin"):
            raise CheckpointError(f"Raw data/cache artifact would be committed: {relative}")
        if filename.startswith(".env") or filename.endswith((".sqlite", ".sqlite3", ".db", ".pem", ".key", ".pfx")):
            raise CheckpointError(f"Sensitive local data candidate refused: {relative}")
        candidate_size = int(git("cat-file", "-s", object_id).stdout) if staged_only else target.stat().st_size
        if candidate_size > 10 * 1024 * 1024:
            raise CheckpointError(f"Large source candidate requires a deliberate separate review: {relative}")
        contents = git("cat-file", "blob", object_id, binary=True).stdout if staged_only else target.read_bytes()
        if any(pattern.search(contents) for pattern in SECRET_PATTERNS):
            raise CheckpointError(f"Potential credential material detected in {relative}; no contents were logged.")
        count += 1
        size += candidate_size
    return {"candidate_files": count, "candidate_bytes": size}


def checkpoint(client, message, *, staged_only=False):
    if not message or len(message) > 240 or "\n" in message:
        raise CheckpointError("Use a concise single-line milestone commit message.")
    client.ensure_private()
    ensure_remote()
    audit = audit_paths(staged_only=True) if staged_only else audit_paths()
    if not staged_only:
        git("add", "--all")
    staged = git("diff", "--cached", "--quiet", check=False)
    if staged.returncode == 1:
        git("commit", "-m", message)
    elif staged.returncode != 0:
        raise CheckpointError("Unable to determine staged changes.")
    head = git("rev-parse", "HEAD").stdout.strip()
    branch = git("branch", "--show-current").stdout.strip()
    if not branch or not re.fullmatch(r"[A-Za-z0-9_./-]+", branch):
        raise CheckpointError("A named branch is required for milestone push.")
    # Repeat privacy check immediately before uploading. Never force or rewrite history.
    client.ensure_private()
    git("push", "--set-upstream", "origin", f"{branch}:{branch}")
    remote_head = git("ls-remote", "origin", f"refs/heads/{branch}").stdout.split()
    if not remote_head or remote_head[0] != head:
        raise CheckpointError("Push completed but remote commit verification did not match.")
    return {"repository": f"https://github.com/{OWNER}/{NAME}", "private": True, "branch": branch,
            "commit": head, "verified_remote_commit": remote_head[0], **audit}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--prepare", action="store_true", help="Create/verify private repository and configure origin; no commit or push")
    action.add_argument("--audit", action="store_true", help="Audit candidate source paths locally; no network or mutation")
    action.add_argument("--message", help="Commit the reviewed major milestone and push to the verified private origin")
    parser.add_argument("--staged-only", action="store_true",
                        help="Audit exact index contents and commit only already-staged files; excludes untracked files (with --audit or --message)")
    args = parser.parse_args()
    if args.staged_only and args.prepare:
        parser.error("--staged-only applies only to --audit or --message")
    try:
        if args.audit:
            result = audit_paths(staged_only=args.staged_only)
        else:
            client = GitHub()
            if args.prepare:
                repository, created = client.ensure_private(create=True)
                ensure_remote()
                result = {"repository": repository["html_url"], "private": True, "created": created, "pushed": False}
            else:
                result = checkpoint(client, args.message, staged_only=args.staged_only)
        print(json.dumps(result, indent=2))
        return 0
    except CheckpointError as error:
        print(f"Milestone blocked: {error}", file=sys.stderr)
        return 1
    except Exception as error:
        # Unexpected exception details are withheld because credential/helper libraries can include request internals.
        print(f"Milestone blocked by {type(error).__name__}; no credential data was logged.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
