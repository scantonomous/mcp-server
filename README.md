# Scantonomous MCP Server

MCP (Model Context Protocol) server that connects AI agents to the Scantonomous security scanning platform. Agents can initiate scans, explore findings, apply fixes, and triage issues autonomously.

## Prerequisites

- Python 3.11+
- A Scantonomous account on the target stage (dev, beta, prod)

## Installation

```bash
uv tool install git+https://github.com/scantonomous/mcp-server.git
```

Or with pip:

```bash
pip install git+https://github.com/scantonomous/mcp-server.git
```

## Update

```bash
uv tool upgrade scantonomous-mcp
```

Or with pip:

```bash
pip install --upgrade git+https://github.com/scantonomous/mcp-server.git
```

## Setup

### 1. Authenticate

```bash
scantonomous-mcp --stage dev login
```

This opens your browser to `auth.dev.scntnms.services` for OAuth login. Tokens are stored in your system keychain. No client ID needed — it's auto-detected per stage.

### 2. Configure Your AI Agent

#### Claude Code (CLI)

Automatic:
```bash
scantonomous-mcp --stage dev init
```

Or manual:
```bash
claude mcp add scantonomous -- scantonomous-mcp --stage dev serve
```

Restart Claude Code after configuring.

#### Claude Code (VS Code Extension)

Add to your VS Code `settings.json` or project `.vscode/settings.json`:

```json
{
  "claude-code.mcpServers": {
    "scantonomous": {
      "command": "scantonomous-mcp",
      "args": ["--stage", "dev", "serve"]
    }
  }
}
```

#### Codex

Add to your project's `codex.json` or `~/.codex/config.json`:

```json
{
  "mcpServers": {
    "scantonomous": {
      "command": "scantonomous-mcp",
      "args": ["--stage", "dev", "serve"]
    }
  }
}
```

### 3. Verify

After restarting your agent, you should see Scantonomous tools available (e.g., `list_assets`, `create_scan`, `list_findings`).

## Uninstall

### Remove from Claude Code

```bash
claude mcp remove scantonomous
```

Or if you used `init`, remove the `"scantonomous"` entry from `~/.claude.json` under `mcpServers`.

### Remove from VS Code

Delete the `"scantonomous"` entry from `"claude-code.mcpServers"` in your `settings.json`.

### Remove from Codex

Delete the `"scantonomous"` entry from `"mcpServers"` in `codex.json`.

### Uninstall the CLI

```bash
uv tool uninstall scantonomous-mcp
```

Or with pip:

```bash
pip uninstall scantonomous-mcp
```

### Clear stored credentials

```bash
scantonomous-mcp --stage dev logout
```

## Available Tools

| Tool | Description |
|------|-------------|
| `list_assets` | List connected repositories |
| `create_scan` | Trigger a security scan |
| `get_scan` | Check scan status |
| `create_ai_scan` | Quick AI-powered scan |
| `get_ai_scan_report` | Executive scan summary |
| `list_findings` | Search/filter findings |
| `get_finding` | Full finding details + evidence |
| `get_remediation` | AI-generated fix suggestion |
| `triage_finding` | Mark finding as fixed/FP/accepted |
| `get_findings_summary` | Severity and state statistics |

## CLI Reference

```bash
scantonomous-mcp --stage <stage> login      # Browser-based OAuth login
scantonomous-mcp --stage <stage> logout     # Clear stored tokens
scantonomous-mcp --stage <stage> status     # Check auth status
scantonomous-mcp --stage <stage> serve      # Run MCP server (stdio)
scantonomous-mcp --stage <stage> init       # Write Claude Code MCP config
```

The `--stage` flag defaults to `dev`. Valid stages: `dev`, `beta`, `prod`.

## Development

```bash
pip install -e ".[dev]"
```
