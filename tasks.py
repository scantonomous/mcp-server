"""Invoke task definitions for the mcp-server package.

Standard targets: clean, lint, security, test, build, release.
All tools are invoked via the project venv (use `uv run inv <task>`).

Publishing (tag, wheel, GitHub Release) is handled by the publish GitHub
Actions workflow, triggered automatically when a release PR merges to main.
"""

import glob
import os
import re
import shutil

from invoke import Context, task


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
    ctx.run("ruff check src/", pty=True)
    ctx.run("ruff format --check src/", pty=True)
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
        "uv export --no-dev --no-emit-project --format requirements-txt"
        " -o .runtime-deps.txt",
        pty=True,
    )
    ctx.run(
        "pip-audit --desc --require-hashes --disable-pip -r .runtime-deps.txt",
        pty=True,
    )
    ctx.run("detect-secrets scan --baseline .secrets.baseline", pty=True)
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
