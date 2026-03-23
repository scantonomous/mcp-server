"""MCP server setup and tool registration."""

from __future__ import annotations

import json
import logging

from mcp.server import Server
from mcp.types import TextContent, Tool

from .auth import AuthError, AuthManager
from .client import ApiError, ScantonomousClient
from .tools import ai_scans, findings, scans, triage

logger = logging.getLogger(__name__)


def create_server(client_id: str, stage: str = "dev") -> Server:
    """Create and configure the MCP server with all tools.

    :param client_id: Cognito MCP App Client ID.
    :param stage: Deployment stage (dev, beta, prod).
    :returns: Configured MCP Server instance.
    """
    auth = AuthManager(client_id=client_id, stage=stage)
    api = ScantonomousClient(auth)
    server = Server(
        "scantonomous",
        instructions=(
            "Scantonomous is a security scanning platform. Use these tools to scan "
            "repositories for security vulnerabilities, review findings, get AI-generated "
            "remediation suggestions, and triage issues.\n\n"
            "When to use these tools:\n"
            "- When the user asks about security vulnerabilities, findings, or scans\n"
            "- After significant code changes, to check for newly introduced issues\n"
            "- When the user asks you to run a security scan or review security posture\n"
            "- When triaging findings: get the finding details, read the actual source "
            "code, decide if it's a true positive or false positive, then fix or triage it\n\n"
            "Triage workflow:\n"
            "1. list_findings to see unresolved findings\n"
            "2. get_finding for full details (file path, line numbers, evidence)\n"
            "3. get_remediation for AI-suggested fix\n"
            "4. Read the actual source file to verify\n"
            "5. If true positive: apply the fix, then triage_finding with state=fixed\n"
            "6. If false positive: triage_finding with state=false_positive and explain why\n"
            "7. If accepted risk: triage_finding with state=accepted_risk with justification\n"
            "8. If will fix later: triage_finding with state=will_fix, ecd=YYYY-MM-DD, "
            "and reason explaining the plan\n"
            "9. When multiple findings share the same triage outcome, use finding_ids to "
            "batch-triage up to 25 at once\n\n"
            "Prioritize critical and high severity findings first."
        ),
    )

    @server.list_tools()
    async def handle_list_tools() -> list[Tool]:
        return [
            Tool(
                name="list_assets",
                description=(
                    "List connected repositories and assets. Returns asset_id and "
                    "repo_path (e.g. 'scantonomous/services') for each asset. Use "
                    "the asset_id with create_scan or list_findings."
                ),
                inputSchema={
                    "type": "object",
                    "properties": {
                        "query": {
                            "type": "string",
                            "description": "Optional search query to filter assets by name.",
                        },
                        "limit": {
                            "type": "integer",
                            "description": "Maximum number of results (default 25).",
                            "default": 25,
                        },
                    },
                },
            ),
            Tool(
                name="create_scan",
                description=(
                    "Trigger a security scan on a connected repository. "
                    "Returns the scan ID which can be used to check status and retrieve findings."
                ),
                inputSchema={
                    "type": "object",
                    "properties": {
                        "asset_id": {
                            "type": "string",
                            "description": "The asset (repository) ID to scan.",
                        },
                        "ref": {
                            "type": "string",
                            "description": "Optional git ref (branch, tag, commit SHA) to scan. Defaults to the default branch.",
                        },
                    },
                    "required": ["asset_id"],
                },
            ),
            Tool(
                name="get_scan",
                description="Check the status and details of a security scan.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "scan_id": {
                            "type": "string",
                            "description": "The scan ID to look up.",
                        },
                    },
                    "required": ["scan_id"],
                },
            ),
            Tool(
                name="watch_scan",
                description=(
                    "Wait for a scan to complete by polling every ~30 seconds. "
                    "Returns the final scan result once it reaches a terminal status "
                    "(completed, failed, or canceled). Use this after create_scan "
                    "to wait for results instead of polling manually."
                ),
                inputSchema={
                    "type": "object",
                    "properties": {
                        "scan_id": {
                            "type": "string",
                            "description": "The scan ID to watch.",
                        },
                        "timeout_minutes": {
                            "type": "integer",
                            "description": "Maximum time to wait in minutes (default 30).",
                            "default": 30,
                        },
                    },
                    "required": ["scan_id"],
                },
            ),
            Tool(
                name="create_ai_scan",
                description=(
                    "Create a quick AI-powered security scan. Faster than a full scan "
                    "but may not catch all issues."
                ),
                inputSchema={
                    "type": "object",
                    "properties": {
                        "asset_ids": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Optional list of asset IDs. If omitted, scans all connected assets.",
                        },
                    },
                },
            ),
            Tool(
                name="get_ai_scan_report",
                description="Get the executive summary report for an AI scan, including severity breakdown and key findings.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "ai_scan_id": {
                            "type": "string",
                            "description": "The AI scan ID.",
                        },
                    },
                    "required": ["ai_scan_id"],
                },
            ),
            Tool(
                name="watch_ai_scan",
                description=(
                    "Wait for an AI scan to complete by polling every ~30 seconds. "
                    "Returns the final AI scan result once it reaches a terminal status "
                    "(completed, completed_partial, or failed). Use this after create_ai_scan "
                    "to wait for results instead of polling manually."
                ),
                inputSchema={
                    "type": "object",
                    "properties": {
                        "ai_scan_id": {
                            "type": "string",
                            "description": "The AI scan ID to watch.",
                        },
                        "timeout_minutes": {
                            "type": "integer",
                            "description": "Maximum time to wait in minutes (default 30).",
                            "default": 30,
                        },
                    },
                    "required": ["ai_scan_id"],
                },
            ),
            Tool(
                name="list_findings",
                description=(
                    "Search and filter security findings. Defaults to showing unresolved (untriaged) findings. "
                    "Use severity and state filters to narrow results. Use asset_id to get findings "
                    "from the most recent completed scan of a specific repository."
                ),
                inputSchema={
                    "type": "object",
                    "properties": {
                        "severity": {
                            "type": "string",
                            "enum": ["critical", "high", "medium", "low", "info"],
                            "description": "Filter by severity level.",
                        },
                        "state": {
                            "type": "string",
                            "enum": [
                                "untriaged",
                                "fixed",
                                "false_positive",
                                "accepted_risk",
                                "will_fix",
                                "duplicate",
                                "reopened",
                            ],
                            "description": "Filter by triage state. Defaults to 'untriaged'.",
                        },
                        "query": {
                            "type": "string",
                            "description": "Free-text search query.",
                        },
                        "scan_id": {
                            "type": "string",
                            "description": "Filter to findings from a specific scan.",
                        },
                        "asset_id": {
                            "type": "string",
                            "description": "Filter to findings for this asset/repository. Queries all findings across all scans.",
                        },
                        "limit": {
                            "type": "integer",
                            "description": "Maximum number of results (default 25).",
                            "default": 25,
                        },
                    },
                },
            ),
            Tool(
                name="get_finding",
                description=(
                    "Get full details of a security finding, including code evidence, "
                    "file path, line numbers, and description. Use this to understand "
                    "the finding before triaging or fixing it."
                ),
                inputSchema={
                    "type": "object",
                    "properties": {
                        "finding_id": {
                            "type": "string",
                            "description": "The finding ID.",
                        },
                    },
                    "required": ["finding_id"],
                },
            ),
            Tool(
                name="get_remediation",
                description=(
                    "Get an AI-generated remediation suggestion for a finding, "
                    "including a suggested code fix and explanation."
                ),
                inputSchema={
                    "type": "object",
                    "properties": {
                        "finding_id": {
                            "type": "string",
                            "description": "The finding ID.",
                        },
                    },
                    "required": ["finding_id"],
                },
            ),
            Tool(
                name="triage_finding",
                description=(
                    "Record a triage decision on one or more findings. Mark as fixed (after applying "
                    "a fix), false_positive (with explanation), accepted_risk (with compensating "
                    "controls), will_fix (with ecd date), or duplicate. Use finding_ids to "
                    "batch-triage up to 25 findings with the same state and reason in one call."
                ),
                inputSchema={
                    "type": "object",
                    "properties": {
                        "finding_id": {
                            "type": "string",
                            "description": "A single finding ID to triage. Use this OR finding_ids, not both.",
                        },
                        "finding_ids": {
                            "type": "array",
                            "items": {"type": "string"},
                            "maxItems": 25,
                            "description": (
                                "A list of finding IDs to triage with the same state and reason "
                                "(max 25). Use this OR finding_id, not both."
                            ),
                        },
                        "state": {
                            "type": "string",
                            "enum": [
                                "fixed",
                                "false_positive",
                                "accepted_risk",
                                "will_fix",
                                "duplicate",
                            ],
                            "description": "The triage decision.",
                        },
                        "ecd": {
                            "type": "string",
                            "description": (
                                "Expected completion date (YYYY-MM-DD). Required when "
                                "state is 'will_fix'. Must be a future date within the "
                                "severity-based SLA limit (critical: 21 days, high: 60 days)."
                            ),
                        },
                        "reason": {
                            "type": "string",
                            "description": (
                                "Explanation for the decision. Required for false_positive "
                                "and accepted_risk. For fixed, describe the fix applied."
                            ),
                        },
                        "ai_model": {
                            "type": "string",
                            "description": (
                                "The AI model and version performing the triage "
                                "(e.g., 'Claude Opus 4.6', 'GPT-4o'). "
                                "Self-report your model name."
                            ),
                        },
                    },
                    "required": ["state", "reason", "ai_model"],
                    "oneOf": [
                        {"required": ["finding_id"]},
                        {"required": ["finding_ids"]},
                    ],
                },
            ),
            Tool(
                name="get_findings_summary",
                description="Get aggregate statistics for findings: severity breakdown, state counts, totals.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "scan_id": {
                            "type": "string",
                            "description": "Optional scan ID to scope stats to a specific scan.",
                        },
                    },
                },
            ),
        ]

    @server.call_tool()
    async def handle_call_tool(name: str, arguments: dict | None) -> list[TextContent]:
        args = arguments or {}

        try:
            result = await _dispatch_tool(api, name, args)
            return [TextContent(type="text", text=json.dumps(result, indent=2))]
        except AuthError as e:
            return [
                TextContent(
                    type="text",
                    text=f"Authentication required: {e}\n\nPlease ask the user to run: scantonomous-mcp auth login",
                )
            ]
        except ApiError as e:
            return [TextContent(type="text", text=f"API error: {e}")]

    return server


async def _dispatch_tool(api: ScantonomousClient, name: str, args: dict) -> dict:
    """Route a tool call to the appropriate handler."""
    match name:
        case "list_assets":
            return scans.list_assets(api, query=args.get("query"), limit=args.get("limit", 25))
        case "create_scan":
            return scans.create_scan(api, asset_id=args["asset_id"], ref=args.get("ref"))
        case "get_scan":
            return scans.get_scan(api, scan_id=args["scan_id"])
        case "watch_scan":
            return await scans.watch_scan(
                api,
                scan_id=args["scan_id"],
                timeout_minutes=args.get("timeout_minutes", 30),
            )
        case "create_ai_scan":
            return ai_scans.create_ai_scan(api, asset_ids=args.get("asset_ids"))
        case "get_ai_scan_report":
            return ai_scans.get_ai_scan_report(api, ai_scan_id=args["ai_scan_id"])
        case "watch_ai_scan":
            return await ai_scans.watch_ai_scan(
                api,
                ai_scan_id=args["ai_scan_id"],
                timeout_minutes=args.get("timeout_minutes", 30),
            )
        case "list_findings":
            return findings.list_findings(
                api,
                severity=args.get("severity"),
                state=args.get("state"),
                query=args.get("query"),
                scan_id=args.get("scan_id"),
                asset_id=args.get("asset_id"),
                limit=args.get("limit", 25),
            )
        case "get_finding":
            return findings.get_finding(api, finding_id=args["finding_id"])
        case "get_remediation":
            return findings.get_remediation(api, finding_id=args["finding_id"])
        case "triage_finding":
            return triage.triage_finding(
                api,
                state=args["state"],
                reason=args["reason"],
                ai_model=args["ai_model"],
                finding_id=args.get("finding_id"),
                finding_ids=args.get("finding_ids"),
                ecd=args.get("ecd"),
            )
        case "get_findings_summary":
            return triage.get_findings_summary(api, scan_id=args.get("scan_id"))
        case _:
            return {"error": f"Unknown tool: {name}"}
