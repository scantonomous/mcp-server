---
name: scantonomous
description: Security scanning and finding triage workflow using Scantonomous MCP tools
---

# Scantonomous Security Workflow

You have access to Scantonomous security scanning tools via MCP. Use them to scan code for vulnerabilities, review findings, and triage issues.

## When to Scan

- After significant code changes (new features, refactors, dependency updates)
- Before opening a pull request
- When the user asks for a security review
- Periodically during long coding sessions

Use `create_scan` for thorough analysis or `create_ai_scan` for a quick check.

## Triage Workflow

When reviewing findings, follow this process for each finding:

1. **Get details:** Call `get_finding` to see the full description, code evidence, file path, and line numbers
2. **Get remediation:** Call `get_remediation` for the AI-suggested fix
3. **Read the source:** Read the actual source file at the indicated location to understand the context
4. **Decide:**
   - **True positive (fixable):** Apply the fix, verify tests pass, then call `triage_finding` with `state=fixed`
   - **False positive:** Call `triage_finding` with `state=false_positive` and explain why (see FP heuristics below)
   - **Accepted risk:** Call `triage_finding` with `state=accepted_risk` and document compensating controls
5. **Batch triage:** When multiple findings share the same outcome and reason (e.g., several false positives in test code), use `finding_ids` to triage up to 25 at once instead of calling `triage_finding` repeatedly

## Prioritization

Always address findings in this order:
1. **Critical** severity — immediate action required
2. **High** severity — address before merging
3. **Medium** severity — address if time permits
4. **Low/Info** — document and move on unless easy to fix

Use `get_findings_summary` to see the overall picture before diving into individual findings.

## False Positive Heuristics

Mark as `false_positive` when:
- The finding is in **test code** that never runs in production
- The code path is **unreachable** due to prior validation or control flow
- Input is **already validated** before reaching the flagged code
- The framework provides **built-in protection** (e.g., ORM parameterized queries, template auto-escaping)
- The finding is about a **dev dependency** not included in production builds

Always explain your reasoning in the `reason` field.

## Accepted Risk Patterns

Mark as `accepted_risk` when:
- A **WAF or API gateway** provides protection at a higher layer
- The service runs in a **private network** with no external access
- Input is **validated upstream** by a trusted service
- It's an **intentional design decision** with documented trade-offs
- The **compensating controls** adequately mitigate the risk

Always document the compensating controls in the `reason` field.

## Tips

- Use `list_assets` first to find the correct asset_id for the repository you're working on
- After `create_scan`, poll `get_scan` until status is `completed` before fetching findings
- Use `list_findings` with `scan_id` to see findings from a specific scan
- The `get_finding` response includes enough context (file path, line numbers, code snippet) to locate and fix the issue
