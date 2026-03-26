"""Invoke task definitions for the mcp-server package.

Standard targets: clean, lint, security, test, build, release, publish.
All tools are invoked via the project venv (use `uv run inv <task>`).
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

    We use `uv export --no-dev` to produce a hashed requirements file containing only
    runtime deps and their transitive closure, then feed that to pip-audit. This keeps
    uv.lock as the single source of truth for dependency resolution.
    """
    ctx.run("pinstack .", pty=True)
    ctx.run("bandit -r src/ -q", pty=True)
    # Export runtime-only deps from uv.lock (excludes build-chain dependency group).
    # --no-emit-project excludes the editable self-reference (pip-audit can't hash it).
    # The exported file includes hashes, so pip-audit can verify integrity too.
    ctx.run(
        "uv export --no-dev --no-emit-project --format requirements-txt"
        " -o /tmp/runtime-deps.txt",
        pty=True,
    )
    ctx.run("pip-audit --desc --require-hashes -r /tmp/runtime-deps.txt", pty=True)
    ctx.run("detect-secrets scan --baseline .secrets.baseline", pty=True)
    ctx.run("detect-secrets audit --report .secrets.baseline", pty=True)


@task
def test(ctx: Context) -> None:
    """Run unit tests."""
    ctx.run("python -m pytest tests/ -v", pty=True)


@task(pre=[clean, lint, security, test])
def build(ctx: Context) -> None:
    """Full local CI gate: clean + lint + security + test."""
    print("  build passed")


@task(pre=[build])
def release(ctx: Context) -> None:
    """Full pre-publish validation."""
    print("  release checks passed")


@task(pre=[release])
def publish(ctx: Context, version: str = "") -> None:
    """Bump version, build, and create a GitHub Release.

    Usage: uv run inv publish --version=0.2.0
    """
    if not version:
        raise ValueError("--version is required (e.g., --version=0.2.0)")

    if not re.match(r"^\d+\.\d+\.\d+$", version):
        raise ValueError(f"Invalid version format: {version} (expected X.Y.Z)")

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

    print(f"  bumped version to {version}")

    # Commit and tag
    ctx.run(f"git add {pyproject_path} {init_path}")
    ctx.run(f'git commit -m "release: v{version}"')
    ctx.run(f"git tag v{version}")

    # Build wheel
    ctx.run("uv build", pty=True)

    # Push commit and tag
    ctx.run("git push origin main")
    ctx.run(f"git push origin v{version}")

    # Create GitHub Release with wheel
    wheel_path = glob.glob(f"dist/scantonomous_mcp-{version}-*.whl")
    if not wheel_path:
        raise RuntimeError("wheel not found in dist/")

    ctx.run(
        f'gh release create v{version} {wheel_path[0]} --title "v{version}" --generate-notes',
        pty=True,
    )
    print(f"  published v{version}")
