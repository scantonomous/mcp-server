"""CLI entry point for the Scantonomous MCP server."""

from __future__ import annotations

import json
import logging
import os
import sys

import click

from .auth import AuthError, AuthManager, get_default_client_id


@click.group()
@click.option("--stage", default="prod", help="Deployment stage (dev, beta, prod).")
@click.option(
    "--client-id",
    envvar="SCANTONOMOUS_MCP_CLIENT_ID",
    help="Cognito MCP Client ID (auto-detected per stage if omitted).",
)
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose logging.")
@click.pass_context
def main(ctx: click.Context, stage: str, client_id: str | None, verbose: bool) -> None:
    """Scantonomous MCP server for AI agent integration."""
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(levelname)s: %(message)s",
        stream=sys.stderr,
    )
    ctx.ensure_object(dict)
    ctx.obj["stage"] = stage
    ctx.obj["client_id"] = client_id


@main.command()
@click.pass_context
def login(ctx: click.Context) -> None:
    """Authenticate via browser-based OAuth flow."""
    client_id = _require_client_id(ctx)
    stage = ctx.obj["stage"]

    manager = AuthManager(client_id=client_id, stage=stage)
    manager.login()
    click.echo("Authenticated successfully.", err=True)


@main.command()
@click.pass_context
def logout(ctx: click.Context) -> None:
    """Clear stored authentication tokens."""
    client_id = _require_client_id(ctx)
    stage = ctx.obj["stage"]

    manager = AuthManager(client_id=client_id, stage=stage)
    manager.logout()
    click.echo("Logged out.", err=True)


@main.command()
@click.pass_context
def status(ctx: click.Context) -> None:
    """Check authentication status."""
    client_id = _require_client_id(ctx)
    stage = ctx.obj["stage"]

    manager = AuthManager(client_id=client_id, stage=stage)
    try:
        manager.get_access_token()
        click.echo("Authenticated.", err=True)
    except (AuthError, KeyError, ValueError) as e:
        click.echo(f"Not authenticated: {e}", err=True)
        sys.exit(1)


@main.command()
@click.pass_context
def serve(ctx: click.Context) -> None:
    """Run the MCP server (stdio transport)."""
    import asyncio

    from mcp.server.stdio import stdio_server

    from .server import create_server

    client_id = _require_client_id(ctx)
    stage = ctx.obj["stage"]

    server = create_server(client_id=client_id, stage=stage)

    async def run() -> None:
        async with stdio_server() as (read_stream, write_stream):
            await server.run(read_stream, write_stream, server.create_initialization_options())

    asyncio.run(run())


@main.command()
@click.option(
    "--local",
    "is_local",
    is_flag=True,
    help="Write to project-level .claude.json instead of global.",
)
@click.pass_context
def init(ctx: click.Context, is_local: bool) -> None:
    """Write MCP server config for Claude Code.

    Adds this server to the Claude Code MCP configuration so the agent
    can discover and use Scantonomous tools automatically. Writes to
    the global config (~/.claude.json) by default.
    """
    _require_client_id(ctx)
    stage = ctx.obj["stage"]

    if is_local:
        config_path = os.path.join(os.getcwd(), ".claude.json")
    else:
        config_path = os.path.expanduser("~/.claude.json")

    # Load existing config or start fresh
    config: dict = {}
    if os.path.exists(config_path):
        with open(config_path) as f:
            config = json.load(f)

    mcp_servers = config.setdefault("mcpServers", {})
    args = ["--stage", stage]
    # Only include --client-id if it was explicitly provided (not the built-in default)
    explicit_client_id = ctx.obj.get("client_id")
    if explicit_client_id:
        args.extend(["--client-id", explicit_client_id])
    args.append("serve")
    mcp_servers["scantonomous"] = {
        "command": "scantonomous-mcp",
        "args": args,
    }

    with open(config_path, "w") as f:
        json.dump(config, f, indent=2)
        f.write("\n")

    click.echo(f"MCP server config written to {config_path}", err=True)
    click.echo(
        "Restart Claude Code to pick up the new MCP server configuration.",
        err=True,
    )


def _require_client_id(ctx: click.Context) -> str:
    """Get client_id from explicit flag, env var, or built-in stage default."""
    client_id = ctx.obj.get("client_id")
    if not client_id:
        client_id = get_default_client_id(ctx.obj["stage"])
    if not client_id:
        click.echo(
            f"Error: No client ID configured for stage '{ctx.obj['stage']}'. "
            "Pass --client-id or set SCANTONOMOUS_MCP_CLIENT_ID.",
            err=True,
        )
        sys.exit(1)
    return client_id
