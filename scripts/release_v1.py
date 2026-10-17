"""Build and publish the user-authorized v1 release to the verified private repo.

Credentials remain in memory via Git Credential Manager. Only the four reviewed
release assets are uploaded; raw observations, training data and caches stay local.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import http.client
import json
import mimetypes
from pathlib import Path
import re
import sys
import urllib.parse
import zipfile

try:
    from .github_milestone import GitHub, CheckpointError, REPOSITORY_PATH, git, ensure_remote
except ImportError:
    from github_milestone import GitHub, CheckpointError, REPOSITORY_PATH, git, ensure_remote

ROOT = Path(__file__).resolve().parents[1]
RELEASE = ROOT / "release"


@dataclass(frozen=True)
class ReleaseConfig:
    version: str

    @property
    def tag(self):
        return "v" + self.version

    @property
    def installer(self):
        return f"Big-Brother-{self.version}-x64-nsis.exe"

    @property
    def portable(self):
        return f"Big-Brother-{self.version}-x64-portable.exe"

    @property
    def bundle(self):
        return f"Big-Brother-{self.version}-Windows-x64.zip"

    @property
    def assets(self):
        return (self.bundle, self.installer, self.portable, "SHA256SUMS.txt")


def release_config():
    """Derive one release from the current package, never a stale imported tag."""
    try:
        version = json.loads((ROOT / "package.json").read_text(encoding="utf8"))["version"]
    except (OSError, ValueError, KeyError, TypeError):
        raise CheckpointError("Package metadata could not be read safely") from None
    if not isinstance(version, str) or not re.fullmatch(r"1\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)", version):
        raise CheckpointError("This helper requires a stable 1.x package version")
    return ReleaseConfig(version)


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def asset_path(name, config=None):
    config = config or release_config()
    if name not in config.assets:
        raise CheckpointError("Unexpected release asset")
    path = RELEASE / name
    if not path.is_file() or path.is_symlink() or not path.resolve().is_relative_to(RELEASE.resolve()):
        raise CheckpointError("Release asset is missing or escapes the release directory")
    return path


def validate_bundle(path, exe_hashes, config=None):
    config = config or release_config()
    expected = {"Installer/" + config.installer, "Portable/" + config.portable,
                "START-HERE.txt", "SHA256SUMS.txt", "LICENSE.txt", "THIRD-PARTY-NOTICES.txt"}
    with zipfile.ZipFile(path) as archive:
        if set(archive.namelist()) != expected or len(archive.namelist()) != len(expected):
            raise CheckpointError("Bundle has missing or unexpected files")
        if archive.testzip() is not None:
            raise CheckpointError("Bundle CRC verification failed")
        for folder, name in [("Installer", config.installer), ("Portable", config.portable)]:
            digest = hashlib.sha256()
            with archive.open(folder + "/" + name) as stream:
                for block in iter(lambda: stream.read(1024 * 1024), b""):
                    digest.update(block)
            if digest.hexdigest() != exe_hashes[name]:
                raise CheckpointError("Bundled executable does not match the reviewed package")


def build_bundle():
    config = release_config()
    hashes = {}
    for name in (config.installer, config.portable):
        path = asset_path(name, config)
        with path.open("rb") as stream:
            if stream.read(2) != b"MZ":
                raise CheckpointError("Expected a Windows executable")
        hashes[name] = sha256(path)
    start = (f"BIG BROTHER {config.version} - START HERE\n\n"
             "Choose ONE app:\n\n"
             "1. Recommended: open Installer/" + config.installer + " and follow setup.\n"
             "   Open Big Brother from the Start menu afterward.\n\n"
             "2. Portable: put Portable/" + config.portable + " in a writable folder and open it.\n"
             "   History stays in BigBrother-data beside the executable. Keep that folder.\n\n"
             "TRY THE SAMPLE\n"
             "Choose Explore a replay > Investigation > Open replay.\n"
             "Read Findings and click an event reference to see supporting evidence.\n"
             "Sample events are fabricated; their programs and commands are never executed.\n\n"
             "For a real program, choose Watch a process. Select executable only selects;\n"
             "Launch and watch starts the selected file. Export saves a local report.\n"
             "Closing the window hides to the tray; Stop collection and exit quits.\n\n"
             "Windows 11, 64-bit. No Python, Node, API key or paid service required.\n"
             "Unsigned packages. A finding is not a malware verdict; quiet does not prove safety.\n"
             "The app does not block, quarantine or remove threats.\n\n"
             f"Full illustrated guide: https://github.com/jarvis0626/big-brother/blob/{config.tag}/README.md\n"
             "This repository and downloads are private; sign in with an account that has access.\n")
    bundle = RELEASE / config.bundle
    temporary = bundle.with_suffix(".zip.tmp")
    with zipfile.ZipFile(temporary, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.write(asset_path(config.installer, config), "Installer/" + config.installer)
        archive.write(asset_path(config.portable, config), "Portable/" + config.portable)
        archive.writestr("START-HERE.txt", start)
        archive.writestr("SHA256SUMS.txt", "".join(hashes[name] + "  " + folder + "/" + name + "\n"
            for folder, name in [("Installer", config.installer), ("Portable", config.portable)]))
        archive.writestr("LICENSE.txt", (ROOT / "LICENSE").read_text(encoding="utf8"))
        archive.writestr("THIRD-PARTY-NOTICES.txt", (ROOT / "THIRD_PARTY_NOTICES.md").read_text(encoding="utf8"))
    validate_bundle(temporary, hashes, config)
    temporary.replace(bundle)
    hashes[config.bundle] = sha256(bundle)
    (RELEASE / "SHA256SUMS.txt").write_text("".join(hashes[name] + "  " + name + "\n"
        for name in (config.bundle, config.installer, config.portable)), encoding="utf8", newline="\n")
    manifest = {"version": config.version, "tag": config.tag, "assets": [{"name": name,
        "bytes": asset_path(name, config).stat().st_size, "sha256": sha256(asset_path(name, config))} for name in config.assets]}
    (RELEASE / "release-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf8")
    return manifest


def verify_local(config=None):
    config = config or release_config()
    if release_config() != config:
        raise CheckpointError("Package version changed while preparing the release")
    manifest = json.loads((RELEASE / "release-manifest.json").read_text(encoding="utf8"))
    if manifest.get("tag") != config.tag or manifest.get("version") != config.version:
        raise CheckpointError("Unexpected release manifest")
    rows = manifest.get("assets", [])
    if len(rows) != len(config.assets) or {row["name"] for row in rows} != set(config.assets):
        raise CheckpointError("Manifest has missing or unexpected assets")
    for row in rows:
        path = asset_path(row["name"], config)
        if path.stat().st_size != row["bytes"] or sha256(path) != row["sha256"]:
            raise CheckpointError("Release asset changed after bundle verification")
    return manifest


def upload_endpoint(upload_url, release_id, filename):
    parsed = urllib.parse.urlsplit(upload_url.split("{")[0])
    expected = REPOSITORY_PATH + f"/releases/{release_id}/assets"
    if (parsed.scheme != "https" or parsed.hostname != "uploads.github.com" or parsed.port not in (None, 443)
            or parsed.username or parsed.password or parsed.path != expected or parsed.query or parsed.fragment):
        raise CheckpointError("Unexpected GitHub upload destination")
    return parsed.path + "?" + urllib.parse.urlencode({"name": filename})


def upload(client, release, row, config=None):
    request_path = upload_endpoint(release["upload_url"], release["id"], row["name"])
    connection = http.client.HTTPSConnection("uploads.github.com", timeout=180)
    headers = {"Authorization": "Bearer " + client.token, "Accept": "application/vnd.github+json",
               "X-GitHub-Api-Version": "2026-03-10", "User-Agent": "Big-Brother-Private-Release",
               "Content-Type": mimetypes.guess_type(row["name"])[0] or "application/octet-stream",
               "Content-Length": str(row["bytes"])}
    try:
        connection.putrequest("POST", request_path)
        for name, value in headers.items():
            connection.putheader(name, value)
        connection.endheaders()
        sent, last_notice = 0, 0
        digest = hashlib.sha256()
        with asset_path(row["name"], config).open("rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                connection.send(block)
                digest.update(block)
                sent += len(block)
                if sent - last_notice >= 32 * 1024 * 1024:
                    print(f"Uploading {row['name']}: {sent // 1024**2} MiB", flush=True)
                    last_notice = sent
        response = connection.getresponse()
        payload = response.read(2 * 1024 * 1024)
        if response.status != 201:
            raise CheckpointError(f"GitHub asset upload returned HTTP {response.status}; credentials withheld")
        if sent != row["bytes"] or digest.hexdigest() != row["sha256"]:
            raise CheckpointError("Local asset changed while uploading; release left unpublished")
        return json.loads(payload)
    finally:
        connection.close()


def verify_asset(asset, row):
    if (asset.get("name") != row["name"] or asset.get("size") != row["bytes"] or asset.get("state") != "uploaded"
            or asset.get("digest") != "sha256:" + row["sha256"]):
        raise CheckpointError("GitHub asset size, upload state or server-side SHA256 differs")


def find_release(client, config=None):
    config = config or release_config()
    release = client.request("GET", REPOSITORY_PATH + "/releases/tags/" + config.tag, allow_missing=True)
    if release is not None:
        return release
    # The tag endpoint documents published releases. Authenticated listings also
    # include drafts, so a retry must find our draft rather than create another.
    for page in range(1, 11):
        rows = client.request("GET", REPOSITORY_PATH + f"/releases?per_page=100&page={page}")
        match = next((row for row in rows if row.get("tag_name") == config.tag), None)
        if match is not None:
            return match
        if len(rows) < 100:
            return None
    raise CheckpointError("Release lookup limit reached; no duplicate release was created")


def operate(action):
    if action not in {"draft", "publish", "verify"}:
        raise CheckpointError("Unexpected release action")
    config = release_config()
    manifest = verify_local(config)
    # Untracked local artwork or scratch files are outside the reviewed source
    # commit and never become an asset. Tracked/staged edits still block release.
    if git("status", "--porcelain", "--untracked-files=no").stdout.strip():
        raise CheckpointError("Commit the reviewed source before preparing or publishing its release")
    ensure_remote()
    head = git("rev-parse", "HEAD").stdout.strip()
    tag_ref = "refs/tags/" + config.tag
    if git("cat-file", "-t", tag_ref).stdout.strip() != "tag":
        raise CheckpointError("The release requires an annotated local tag")
    tag_object = git("rev-parse", tag_ref).stdout.strip()
    tagged = git("rev-parse", tag_ref + "^{}").stdout.strip()
    remote_lines = git("ls-remote", "origin", "HEAD", tag_ref, tag_ref + "^{}").stdout.splitlines()
    remote = dict((parts[1], parts[0]) for line in remote_lines if len(parts := line.split()) == 2)
    if (tagged != head or remote.get("HEAD") != head or remote.get(tag_ref) != tag_object or
            remote.get(tag_ref + "^{}") != head):
        raise CheckpointError("Local and private remote annotated release tag must match this source commit")
    client = GitHub()
    client.ensure_private()
    release = find_release(client, config)
    body = (ROOT / "docs" / "releases" / (config.tag + ".md")).read_text(encoding="utf8")
    if release is None:
        if action != "draft":
            raise CheckpointError("Prepare and verify a private draft before publishing")
        release = client.request("POST", REPOSITORY_PATH + "/releases", {"tag_name": config.tag,
            "target_commitish": head, "name": f"Big Brother {config.tag} - Installer + Portable",
            "body": body, "draft": True, "prerelease": False})
    if release.get("tag_name") != config.tag:
        raise CheckpointError("GitHub returned a different release tag; it was preserved")
    release_path = REPOSITORY_PATH + f"/releases/{release['id']}"
    assets = client.request("GET", release_path + "/assets?per_page=100")
    if {a["name"] for a in assets} - set(config.assets):
        raise CheckpointError("Release contains unrelated assets; they were preserved")
    if action == "draft":
        if not release["draft"]:
            raise CheckpointError("Existing release is published; it will not be overwritten")
        for row in manifest["assets"]:
            existing = next((asset for asset in assets if asset["name"] == row["name"]), None)
            asset = existing or upload(client, release, row, config)
            verify_asset(asset, row)
            print("Verified uploaded SHA256: " + row["name"], flush=True)
    else:
        if {a["name"] for a in assets} != set(config.assets):
            raise CheckpointError("Cannot publish a release with missing assets")
        for row in manifest["assets"]:
            verify_asset(next(asset for asset in assets if asset["name"] == row["name"]), row)
        if release["body"] != body:
            raise CheckpointError("Release notes differ from the reviewed source")
        if action == "publish":
            client.ensure_private()
            release = client.request("PATCH", release_path, {"draft": False, "make_latest": "true"})
        elif release["draft"]:
            raise CheckpointError("Release is still an unpublished draft")
    client.ensure_private()
    verified = client.request("GET", release_path)
    if action in ("publish", "verify") and verified.get("draft") is not False:
        raise CheckpointError("GitHub release is still unpublished")
    if verified.get("tag_name") != config.tag:
        raise CheckpointError("The verified GitHub release tag differs from the reviewed release")
    final_assets = verified.get("assets", [])
    if len(final_assets) != len(config.assets) or {asset["name"] for asset in final_assets} != set(config.assets):
        raise CheckpointError("Verified GitHub release has missing or unexpected assets")
    for row in manifest["assets"]:
        verify_asset(next(asset for asset in final_assets if asset["name"] == row["name"]), row)
    return {"url": verified["html_url"], "tag": config.tag, "commit": head, "private": True,
            "draft": verified["draft"], "assets": [{"name": a["name"], "bytes": a["size"],
                "sha256": a["digest"], "download": a["browser_download_url"]} for a in verified["assets"]]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["bundle", "draft", "publish", "verify"])
    args = parser.parse_args()
    try:
        result = build_bundle() if args.action == "bundle" else operate(args.action)
        print(json.dumps(result, indent=2), flush=True)
        return 0
    except CheckpointError as error:
        print("Release stopped: " + str(error), file=sys.stderr)
    except Exception as error:
        print("Release stopped by " + type(error).__name__ + "; credentials and request internals withheld.", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
