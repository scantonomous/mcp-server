# Scantonomous MCP Server

MCP (Model Context Protocol) server that connects AI agents (Claude Code, Codex) to the Scantonomous security scanning platform. Agents can initiate scans, explore findings, apply fixes, and triage issues autonomously.

## Installation

```bash
pip install -e path/to/mcp-server
```

## Setup

### 1. Authenticate

```bash
scantonomous-mcp --client-id <MCP_CLIENT_ID> --stage dev auth login
```

This opens a browser for OAuth login. Tokens are stored in your system keychain.

### 2. Configure Claude Code

```bash
scantonomous-mcp --client-id <MCP_CLIENT_ID> --stage dev init
```

Or add to `~/.claude.json` manually:

```json
{
  "mcpServers": {
    "scantonomous": {
      "command": "scantonomous-mcp",
      "args": ["--stage", "dev", "--client-id", "<MCP_CLIENT_ID>", "serve"]
    }
  }
}
```

### 3. Restart Claude Code

The MCP server will start automatically when Claude Code launches.

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

## CLI Commands

```bash
scantonomous-mcp auth login    # Browser-based OAuth login
scantonomous-mcp auth logout   # Clear stored tokens
scantonomous-mcp auth status   # Check auth status
scantonomous-mcp serve         # Run MCP server (stdio)
scantonomous-mcp init          # Write Claude Code MCP config
```

## Environment Variables

| Variable | Description |
|----------|-------------|
| `SCANTONOMOUS_MCP_CLIENT_ID` | Cognito MCP App Client ID (alternative to `--client-id`) |

## Development

```bash
pip install -e ".[dev]"
```
