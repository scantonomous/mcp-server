"""Invoke task definitions for the mcp-server package.

Standard targets: clean, lint, security, test, build, release.
All tools are invoked via the project venv (use `uv run inv <task>`).

Publishing (tag, wheel, GitHub Release) is handled by the publish GitHub
Actions workflow, triggered automatically when a release PR merges to main.
"""

import glob
import json
import os
import re
import shutil
import tempfile
from collections.abc import Mapping
from typing import Any

from invoke import Context, Exit, task

#: The tracked baseline. Never rewritten by the build -- see
#: :func:`_check_secrets_baseline_is_current`.
SECRETS_BASELINE = ".secrets.baseline"


def _baseline_entry_keys(baseline: Mapping[str, Any]) -> set[tuple[str, str, str]]:
    """Return ``(filename, type, hashed_secret)`` for every entry in *baseline*.

    Deliberately excludes ``line_number``: a finding that merely moved is the
    same finding, and gating on line numbers would fail the build for unrelated
    edits above it.
    """
    keys: set[tuple[str, str, str]] = set()
    for filename, findings in baseline.get("results", {}).items():
        # detect-secrets excludes the baseline by FILENAME, so scanning against a
        # copy under another path makes it scan the tracked baseline and report
        # every `hashed_secret` in it as a Hex High Entropy String. The real
        # baseline never contains itself, so dropping it here is what restores
        # the comparison rather than papering over a finding.
        if os.path.normpath(filename) == os.path.normpath(SECRETS_BASELINE):
            continue
        for finding in findings:
            keys.add(
                (
                    str(finding.get("filename", filename)),
                    str(finding.get("type", "unknown")),
                    str(finding.get("hashed_secret", "")),
                )
            )
    return keys


def _check_secrets_baseline_is_current(ctx: Context) -> None:
    """Scan for secrets WITHOUT rewriting the tracked baseline.

    ``detect-secrets scan --baseline F`` updates ``F`` in place, so running it
    from the build left ``.secrets.baseline`` modified on every single
    invocation -- usually only a ``generated_at`` bump, with nothing found. The
    cost was not the diff; it was what the diff taught. A file that is *always*
    dirty gets reflexively discarded, and the one time the rewrite carries a
    real new finding it is discarded exactly the same way, unread.

    So: scan against a throwaway copy and compare entries, never touching the
    tracked file. A difference fails the build rather than being silently
    absorbed -- adding a finding to the allowlist should be a deliberate,
    reviewable commit.

    Compared on ``(filename, type, hashed_secret)``; ``line_number`` and
    ``generated_at`` are ignored so unrelated edits do not trip it.

    **Scans git-TRACKED files only**, which is detect-secrets' default in a
    repo. An untracked file holding a secret is invisible here -- consistent
    with CI, which only ever sees tracked content.

    :param ctx: Invoke context.
    :raises Exit: If the scan finds entries the baseline does not carry.
    """
    with open(SECRETS_BASELINE, encoding="utf-8") as baseline_file:
        committed = json.load(baseline_file)

    with tempfile.TemporaryDirectory() as tmpdir:
        probe = os.path.join(tmpdir, "baseline.json")
        shutil.copyfile(SECRETS_BASELINE, probe)
        # Writes the updated baseline to `probe`; stdout is the same content and
        # is discarded. `probe` is what we read back.
        ctx.run(f"detect-secrets scan --baseline {probe} > /dev/null", pty=True)
        with open(probe, encoding="utf-8") as probe_file:
            scanned = json.load(probe_file)

    added = _baseline_entry_keys(scanned) - _baseline_entry_keys(committed)
    removed = _baseline_entry_keys(committed) - _baseline_entry_keys(scanned)

    if not added and not removed:
        return

    print(f"{SECRETS_BASELINE} is out of date.")
    for filename, secret_type, _hashed in sorted(added):
        print(f"  NEW      {filename} ({secret_type})")
    for filename, secret_type, _hashed in sorted(removed):
        print(f"  GONE     {filename} ({secret_type})")
    print(
        "\nReview each NEW entry as a real secret first. If it is a false positive"
        f"\n(a digest, a fixture, generated test data), refresh the baseline with:"
        f"\n    uv run detect-secrets scan --baseline {SECRETS_BASELINE}"
        f"\nand commit {SECRETS_BASELINE} as part of the change that introduced it."
    )
    raise Exit(code=1)


@task
def clean(ctx: Context) -> None:
    """Remove build artifacts, caches, and compiled files."""
    patterns = [
        "**/__pycache__",
        ".pytest_cache",
        ".ruff_cache",
        "dist",
        "build",
    ]
    for pattern in patterns:
        for path in glob.glob(pattern, recursive=True):
            if os.path.isdir(path):
                shutil.rmtree(path)
                print(f"  removed {path}/")

    for path in glob.glob("**/*.pyc", recursive=True):
        os.remove(path)

    for path in glob.glob("*.egg-info"):
        if os.path.isdir(path):
            shutil.rmtree(path)
            print(f"  removed {path}/")


@task
def lint(ctx: Context) -> None:
    """Run code quality checks: ruff lint, ruff format, pyright."""
    # tasks.py is in scope: it carries the secrets-baseline gate, so a lint
    # regression there would silently degrade a security check. Pyright is
    # deliberately NOT extended to it -- invoke does not re-export `task` or
    # `Context` from its package root, so every task module trips
    # reportPrivateImportUsage on a third-party typing quirk.
    ctx.run("ruff check src/ tasks.py", pty=True)
    ctx.run("ruff format --check src/ tasks.py", pty=True)
    ctx.run("pyright src/", pty=True)


@task
def security(ctx: Context) -> None:
    """Run security and supply-chain checks: pinstack, bandit, pip-audit, detect-secrets.

    pip-audit targets ONLY runtime dependencies ([project].dependencies), not the
    build-chain ([dependency-groups].build). This is intentional:

    - Runtime deps ship to users and must be vulnerability-free.
    - Build-chain deps (pytest, ruff, pyright, etc.) pull in large transitive trees
      (e.g., pytest → pygments) that may have CVEs irrelevant to production. Auditing
      them creates false positives that block builds for no security benefit.

    pip-audit cannot read uv.lock directly — it only understands requirements files or
    installed environments. We export runtime deps to a requirements file via
    `uv export --no-dev` as a workaround. This keeps uv.lock as the single source of
    truth for dependency resolution.
    """
    ctx.run("pinstack .", pty=True)
    ctx.run("bandit -r src/ -q", pty=True)
    # pip-audit can't read uv.lock, so we export runtime-only deps to a requirements file it can consume.
    # --no-emit-project excludes the editable self-reference (pip-audit can't hash it).
    # The exported file includes hashes, so pip-audit can verify integrity too.
    # --disable-pip tells pip-audit to skip creating an isolated venv and upgrading pip,
    # which avoids network dependencies and the brittle pip bootstrap step. This flag
    # requires hashed input (which uv export provides).
    ctx.run(
        "uv export --no-dev --no-emit-project --format requirements-txt -o .runtime-deps.txt",
        pty=True,
    )
    ctx.run(
        "pip-audit --desc --require-hashes --disable-pip -r .runtime-deps.txt",
        pty=True,
    )
    _check_secrets_baseline_is_current(ctx)
    ctx.run("detect-secrets audit --report .secrets.baseline", pty=True)


@task
def test(ctx: Context) -> None:
    """Run unit tests."""
    if not os.path.isdir("tests"):
        print("  no tests/ directory — skipping")
        return
    ctx.run("python -m pytest tests/ -v", pty=True)


@task(pre=[clean, lint, security, test])
def build(ctx: Context) -> None:
    """Full local CI gate: clean + lint + security + test."""
    print("  build passed")


@task(pre=[build])
def release(ctx: Context, version: str = "") -> None:
    """Create a release PR: bump version, commit to release branch, open PR.

    After the PR is merged to main, the publish workflow (GitHub Actions)
    automatically tags, builds a wheel, and creates a GitHub Release.

    Usage: uv run inv release --version=0.2.7
    """
    if not version:
        raise ValueError("--version is required (e.g., --version=0.2.7)")

    if not re.match(r"^\d+\.\d+\.\d+$", version):
        raise ValueError(f"Invalid version format: {version} (expected X.Y.Z)")

    branch = f"release/v{version}"

    # Create release branch from origin/main
    ctx.run("git fetch origin main", pty=True)
    ctx.run(f"git checkout -b {branch} origin/main", pty=True)

    # Bump version in pyproject.toml
    pyproject_path = "pyproject.toml"
    with open(pyproject_path) as f:
        content = f.read()
    content = re.sub(
        r'version\s*=\s*"[^"]*"',
        f'version = "{version}"',
        content,
        count=1,
    )
    with open(pyproject_path, "w") as f:
        f.write(content)

    # Bump version in __init__.py
    init_path = os.path.join("src", "scantonomous_mcp", "__init__.py")
    with open(init_path) as f:
        content = f.read()
    content = re.sub(
        r'__version__\s*=\s*"[^"]*"',
        f'__version__ = "{version}"',
        content,
    )
    with open(init_path, "w") as f:
        f.write(content)

    # Sync lockfile so uv.lock reflects the new version
    ctx.run("uv lock")

    print(f"  bumped version to {version}")

    # Commit, push, and create PR
    ctx.run(f"git add {pyproject_path} {init_path} uv.lock")
    ctx.run(f'git commit -m "release: v{version}"')
    ctx.run(f"git push -u origin {branch}", pty=True)
    ctx.run(
        f'gh pr create --title "release: v{version}"'
        f' --body "Bump version to {version}.'
        f" Merging this PR will automatically tag, build, and publish the release."
        f' \\n\\nSee publish workflow for details."',
        pty=True,
    )
    print(f"  release PR created for v{version} — merge it to publish")
