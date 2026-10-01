# DeepSeek Flash Security Agent

Xdigitex uses DeepSeek Flash as the planning and reporting brain for a prompt-first authorized security assessment while scanner execution remains inside Xdigitex-owned scope, SSRF, request-limit and registered-check controls.

## Configuration

```env
DEEPSEEK_API_KEY=your_key_here
DEEPSEEK_BASE_URL=https://api.deepseek.com
DEEPSEEK_MODEL=deepseek-flash
```

The integration calls `POST /chat/completions` with `model: deepseek-flash` and JSON output. The model name is fixed in the runtime integration so assessment planning and report generation use DeepSeek Flash even if a stale model name remains in an older environment file.

## One-prompt workflow

Ownership verification remains a one-time prerequisite for each target. After a target is verified, one natural-language instruction starts the operation.

1. Add the site under **Assets** and complete ownership verification.
2. Open **AI Security Agent**.
3. Enter one instruction describing the assessment outcome you want.
4. Xdigitex resolves the verified target and immutable scope.
5. The worker maps the first-party application.
6. DeepSeek Flash converts the instruction and application map into a structured mission.
7. Registered safe checks execute through the bounded HTTP/browser layer.
8. Findings and sanitized evidence are persisted.
9. Before the scan is marked complete, DeepSeek Flash receives the stored finding summaries and coverage metadata and produces the final structured report.
10. The scan becomes **Report Ready** only after that report has been saved.

## Final report

Every newly completed operation stores a full report in `Scan.agentReport`. The report contains:

- executive summary
- security-posture interpretation
- severity and confidence overview
- assessment coverage
- attack-surface summary
- highest-priority findings
- ordered P0/P1/P2/P3 remediation actions
- concrete validation/retest steps
- technical assessment summary
- positive observations where supported
- limitations and testing boundaries
- recommended next actions

The completed scan page exposes the executive view immediately. `/scans/:id/report` shows the complete on-screen report and `GET /api/scans/:id/report` exports the same assessment as PDF.

Older completed scans that only contain the legacy short report are upgraded on first opening of the new full-report page or PDF endpoint.

## Evidence rule

DeepSeek Flash is never treated as the vulnerability source of truth. The reporting prompt explicitly restricts the model to the stored scanner findings and coverage supplied by Xdigitex. It must not invent vulnerabilities, endpoints, credentials, exploitation success, users, or impact.

If the DeepSeek API is unavailable or `DEEPSEEK_API_KEY` is not configured, Xdigitex stores a deterministic fallback report so the scan can still finish with a complete report structure.

## Execution boundary

DeepSeek Flash cannot directly:

- run shell commands
- choose unrelated target hosts
- bypass ownership verification
- bypass scope or SSRF protection
- disable request limits
- perform destructive exploitation
- retrieve raw test-account credentials from the database

A model-selected check executes only when that check already exists in the Xdigitex scanner registry.
