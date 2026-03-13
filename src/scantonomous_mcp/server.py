"""MCP server setup and tool registration."""

from __future__ import annotations

import json
import logging
import os

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
            "7. If accepted risk: triage_finding with state=accepted_risk with justification\n\n"
            "Prioritize critical and high severity findings first."
        ),
    )

    @server.list_tools()
    async def handle_list_tools() -> list[Tool]:
        return [
            Tool(
                name="list_assets",
                description="List connected repositories and assets in your Scantonomous account.",
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
                name="list_findings",
                description=(
                    "Search and filter security findings. Defaults to showing unresolved (new) findings. "
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
                            "enum": ["new", "fixed", "false_positive", "accepted_risk"],
                            "description": "Filter by triage state. Defaults to 'new'.",
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
                            "description": "Filter to findings from the most recent completed scan of this asset/repository.",
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
                    "Record a triage decision on a finding. Mark it as fixed (after applying a fix), "
                    "false_positive (with explanation), or accepted_risk (with compensating controls)."
                ),
                inputSchema={
                    "type": "object",
                    "properties": {
                        "finding_id": {
                            "type": "string",
                            "description": "The finding ID to triage.",
                        },
                        "state": {
                            "type": "string",
                            "enum": ["fixed", "false_positive", "accepted_risk"],
                            "description": "The triage decision.",
                        },
                        "reason": {
                            "type": "string",
                            "description": (
                                "Explanation for the decision. Required for false_positive "
                                "and accepted_risk. For fixed, describe the fix applied."
                            ),
                        },
                    },
                    "required": ["finding_id", "state", "reason"],
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
            result = _dispatch_tool(api, name, args)
            return [TextContent(type="text", text=json.dumps(result, indent=2))]
        except AuthError as e:
            return [TextContent(
                type="text",
                text=f"Authentication required: {e}\n\nPlease ask the user to run: scantonomous-mcp auth login",
            )]
        except ApiError as e:
            return [TextContent(type="text", text=f"API error: {e}")]

    return server


def _dispatch_tool(api: ScantonomousClient, name: str, args: dict) -> dict:
    """Route a tool call to the appropriate handler."""
    match name:
        case "list_assets":
            return scans.list_assets(api, query=args.get("query"), limit=args.get("limit", 25))
        case "create_scan":
            return scans.create_scan(api, asset_id=args["asset_id"], ref=args.get("ref"))
        case "get_scan":
            return scans.get_scan(api, scan_id=args["scan_id"])
        case "create_ai_scan":
            return ai_scans.create_ai_scan(api, asset_ids=args.get("asset_ids"))
        case "get_ai_scan_report":
            return ai_scans.get_ai_scan_report(api, ai_scan_id=args["ai_scan_id"])
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
                finding_id=args["finding_id"],
                state=args["state"],
                reason=args["reason"],
            )
        case "get_findings_summary":
            return triage.get_findings_summary(api, scan_id=args.get("scan_id"))
        case _:
            return {"error": f"Unknown tool: {name}"}
