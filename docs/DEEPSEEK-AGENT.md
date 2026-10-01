# DeepSeek Security Agent

Xdigitex supports a simple prompt-driven assessment workflow while keeping scanner execution inside the existing authorization and safety boundaries.

## Configuration

```env
DEEPSEEK_API_KEY=your_key_here
DEEPSEEK_BASE_URL=https://api.deepseek.com
DEEPSEEK_MODEL=deepseek-flash
```

The integration calls the OpenAI-compatible DeepSeek `POST /chat/completions` endpoint and requests JSON output.

## User workflow

1. Add the site under **Assets**.
2. Complete ownership verification.
3. Open **AI Security Agent**.
4. Enter one prompt, for example:

```text
Assess https://app.example.com. Find security weaknesses, safely verify their real impact, prioritize confirmed issues, and prepare a clear remediation report.
```

5. Xdigitex creates the scan and maps the first-party application.
6. DeepSeek receives the application map and the catalog of registered scanner modules.
7. DeepSeek returns only the IDs of modules it wants prioritized plus rationale/priorities.
8. Xdigitex validates those IDs against its own registry. Unknown IDs are discarded.
9. Registered scanner modules execute through the centralized bounded HTTP/browser layer.
10. The scan page shows discovered findings and the DeepSeek plan.
11. After completion, **Download PDF Report** produces the security report.

## Important architecture rule

DeepSeek is the reasoning and reporting layer, not an unrestricted execution engine.

It cannot directly:

- run shell commands
- choose unrelated target hosts
- bypass ownership verification
- bypass scope/SSRF protection
- disable request limits
- perform destructive exploitation
- retrieve raw test-account credentials from the database

A model-selected check runs only when that check already exists in the Xdigitex scanner registry.

## Proof of impact

The scanner may safely verify a weakness using the minimum non-destructive proof required by the registered module. Evidence is sanitized before storage. If establishing impact would require destructive behavior, unrelated-user access, real financial actions, or destabilizing traffic, the scanner stops at the safe exploitation boundary and reports the evidence available.

## PDF report

`GET /api/scans/:id/report` builds a PDF containing:

- target and scan metadata
- DeepSeek-assisted executive summary
- security posture
- finding counts
- highest-risk confirmed issues
- full recorded technical findings
- affected URLs/methods
- sanitized evidence excerpts
- impact
- remediation
- prioritized fixes
- assessment boundaries and limitations

DeepSeek receives only the stored finding summaries for report writing and is instructed not to invent vulnerabilities or exploitation results. If DeepSeek is unavailable, Xdigitex still generates a deterministic PDF report from the scan findings.
