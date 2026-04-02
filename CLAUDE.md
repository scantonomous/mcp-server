# MCP Server — Claude Code Instructions

## Communication Style

- Be concise and technical.
- No re-explaining context unless requested.
- Output only diffs, code, or bullet points.
- No conversational filler.

## Credential & Secret Handling

**NEVER output secrets, passwords, tokens, or credentials in tool results.** All tool
output (Bash, Read, etc.) flows through the Anthropic API. Leaking credentials to any
third party is a critical security violation.

Rules:
- **Fetch and consume credentials in a single Bash command** so values stay in the
  shell and never appear in conversation context.
- **Never use a separate tool call** to fetch credentials and then reference them later.
- **Never echo, print, or cat** credential values.

## What This Repo Is

This is the **Scantonomous MCP server** — a Model Context Protocol server that connects
AI agents (Claude Code, Codex, etc.) to the Scantonomous security scanning platform.
It is a **client-side tool** installed on developers' machines, not a deployed service.

Users install it via `uv tool install git+https://github.com/scantonomous/mcp-server.git`
and configure their AI agent to use it as an MCP server.

### How it fits into the Scantonomous architecture

```
AI Agent (Claude Code, Codex, etc.)
  └── MCP protocol (stdio) ──> scantonomous-mcp (THIS REPO)
        └── HTTPS ──> Scantonomous REST API (services repo)
              ├── Account, Scan, Findings, SCM, AI Scan APIs
              └── Cognito OAuth 2.0 (auth)
```

- **services** (`../services/`) — the backend REST
  API that this MCP server calls. All API endpoints live there.
- **orchestrator** (`../orchestrator/`) — scan
  execution pipeline (Step Functions, ECS Fargate). Not called directly by this repo.
- **common** (`../common/`) — shared Python utils
  (`scntnms-utils`). Not a dependency of this repo.

For the full platform architecture and operational runbooks, see the **documentation**
repo (`../documentation/`):
- `architecture.md` — system design, service boundaries, data flow
- `operations.md` — deployment, monitoring, incident response

### Auth flow

OAuth 2.0 Authorization Code + PKCE. The CLI opens the user's browser to the
productweb consent page, which redirects to Cognito. Tokens are stored in the
system keychain via the `keyring` library. Token refresh is automatic.

## Project Structure

```
src/scantonomous_mcp/
  __init__.py          # version
  cli.py               # click CLI: login, logout, status, serve, init
  auth.py              # OAuth 2.0 + PKCE, keychain token storage
  client.py            # HTTP client for Scantonomous REST API
  server.py            # MCP server setup and tool registration
  tools/
    __init__.py
    scans.py           # create_scan, get_scan, watch_scan
    ai_scans.py        # create_ai_scan, get_ai_scan_report, watch_ai_scan
    findings.py        # list_findings, get_finding, get_findings_summary, get_remediation
    triage.py          # triage_finding
```

## Tooling

- **uv** for dependency management, venv creation, and running tasks.
- **invoke** for build task orchestration (always via `uv run inv <task>`).
- **Ruff** for linting and formatting (not Black/Flake8).
- **Pyright** for type checking (not MyPy).
- **Python 3.13** required.

## Dependencies

Dependencies are split into two groups:

- **`[project].dependencies`** — runtime deps that ship to users (mcp, httpx, keyring,
  click). These are audited by `pip-audit`.
- **`[dependency-groups].build`** — build-chain tools (pytest, ruff, pyright, bandit,
  etc.). These are NOT audited by `pip-audit` because their transitive deps (e.g.,
  pytest -> pygments) can have CVEs irrelevant to production.

All deps use strict `==` pinning. `uv.lock` contains hashes for every package.

## Development Setup

```bash
./scripts/dev-setup.sh
```

This runs `uv sync --locked --group build` (installs runtime + build-chain deps, hash-verified
from `uv.lock`) and configures git hooks. No manual venv creation or activation needed.

## Build & Test

```bash
uv run inv lint          # ruff check + ruff format --check + pyright
uv run inv security      # pinstack + bandit + pip-audit + detect-secrets
uv run inv test          # pytest
uv run inv build         # clean + lint + security + test (full CI gate)
uv run inv clean         # remove caches and build artifacts
```

The pre-commit hook runs `uv run inv build` — all checks must pass before committing.

## Code Rules

- **Never use `assert` in production code** (anything outside `tests/`). `assert`
  statements are stripped by `python -O`. Use explicit `if` checks with proper error
  handling instead. `assert` is fine in test code.
- **Never catch `Exception` or `BaseException`.** Always catch the most specific
  exception type possible.
- Use **Sphinx reST** docstrings (`:param:`, `:returns:`, `:raises:`).

## Pre-Commit Checklist

**NEVER use `--no-verify`.** Pre-commit hooks must always run. No exceptions.

## Git Workflow

- **Never commit directly to `main`.** All work goes on a feature branch.
- Use **Conventional Commits**: `feat:`, `fix:`, `chore:`, `refactor:`, `test:`, `docs:`.
  Include the Linear issue ID: `feat: add scan timeout tool (SCA-42)`.
- Branch naming: `sca-<issue-number>-<short-description>` (lowercase, hyphens).
- Always branch off `origin/main`:
  ```bash
  git fetch origin && git checkout -b sca-<number>-<short-desc> origin/main
  ```

## Linear Integration

- Team: **Scantonamous**, issue prefix: `SCA-`
- When creating a PR, link it to the Linear issue.

## Testing the MCP Server Locally

```bash
# 1. Authenticate against a stage
scantonomous-mcp --stage dev login

# 2. Run the server in stdio mode (how AI agents connect)
scantonomous-mcp --stage dev serve

# 3. Check auth status
scantonomous-mcp --stage dev status
```

The `--stage` flag defaults to `dev`. Valid stages: `dev`, `beta`, `prod`.

## API Base URLs

| Stage | API URL |
|-------|---------|
| dev   | `https://api.dev.scantonomous.ai/v1` |
| beta  | `https://api.beta.scantonomous.ai/v1` |
| prod  | `https://api.scantonomous.ai/v1` |

## Publishing a Release

```bash
uv run inv release --version=X.Y.Z
```

This creates a `release/vX.Y.Z` branch, bumps the version in `pyproject.toml` and
`__init__.py`, syncs `uv.lock`, commits, pushes, and opens a PR. Runs the full build
gate first.

When the release PR is merged to `main`, the **publish** GitHub Actions workflow
automatically tags the commit, builds a wheel, and creates a GitHub Release.
