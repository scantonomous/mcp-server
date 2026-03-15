"""Invoke task definitions for the mcp-server package.

Standard targets: test, release, clean, publish.
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
def test(ctx: Context) -> None:
    """Run lint, format check, and type check."""
    ctx.run("ruff check src/", pty=True)
    ctx.run("ruff format --check src/", pty=True)
    ctx.run("pyright src/", pty=True)


@task(pre=[test])
def release(ctx: Context) -> None:
    """Full pre-publish validation."""
    print("  release checks passed")


@task(pre=[release])
def publish(ctx: Context, version: str = "") -> None:
    """Bump version, build, and create a GitHub Release.

    Usage: invoke publish --version=0.2.0
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
    ctx.run("python -m build", pty=True)

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
