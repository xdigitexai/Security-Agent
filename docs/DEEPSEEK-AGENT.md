# DeepSeek Security Agent

Xdigitex supports a prompt-first assessment workflow while keeping scanner execution inside the existing authorization and safety boundaries.

## Configuration

```env
DEEPSEEK_API_KEY=your_key_here
DEEPSEEK_BASE_URL=https://api.deepseek.com
DEEPSEEK_MODEL=deepseek-flash
```

The integration calls the OpenAI-compatible DeepSeek `POST /chat/completions` endpoint and requests JSON output.

## One-prompt workflow

Ownership verification remains a one-time prerequisite for each target. After a target is verified, the assessment itself is controlled by one natural-language instruction.

1. Add the site under **Assets** and complete ownership verification.
2. Open **AI Security Agent**.
3. Enter one prompt describing the outcome you want.

Examples:

```text
Perform a complete security assessment. Map the application, prioritize the highest-risk first-party surfaces, safely verify weaknesses, and prepare a remediation-focused report.
```

```text
Assess app.example.com with emphasis on authentication, authorization, APIs and sensitive data exposure. Put confirmed high-risk issues first and give developers clear fixes.
```

```text
Perform a comprehensive end-to-end assessment of app.example.com and produce a management-friendly summary plus developer remediation priorities.
```

### Target resolution

- If the organization has exactly one verified, enabled asset, the prompt does not need to contain a URL or domain.
- If there are multiple verified assets, naming one verified hostname in the prompt is enough; a full `https://...` URL is optional.
- If the prompt contains an explicit URL, that hostname and protocol must match an ownership-verified enabled asset.
- A prompt cannot expand assessment scope to an unrelated or unverified host.

## What the single prompt controls

The prompt is translated into a structured assessment mission containing:

- mission summary
- focused, balanced, or comprehensive execution style
- registered security modules to prioritize
- first-party focus areas
- execution priorities
- report emphasis

A request containing terms such as `full`, `complete`, `comprehensive`, `all checks`, or `end-to-end` is forced to the complete registered safe-check set so the model cannot accidentally narrow a requested comprehensive assessment.

## Execution flow

1. Xdigitex resolves the prompt to an ownership-verified target.
2. The scan worker validates immutable target scope and configured limits.
3. Xdigitex maps the first-party application.
4. DeepSeek receives the user request, application map, and registered scanner catalog.
5. DeepSeek returns a structured assessment mission using only known scanner IDs.
6. Xdigitex validates every selected ID against its own registry. Unknown IDs are discarded.
7. Registered scanner modules execute through the centralized bounded HTTP/browser layer.
8. The live assessment page shows the original prompt, AI mission, focus areas, priorities, approved modules, findings, and activity log.
9. The completed PDF report receives the original prompt, structured plan, and stored findings so its summary and remediation ordering reflect the user's requested outcome without inventing evidence.

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
- prompt-aware DeepSeek-assisted executive summary
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

DeepSeek receives only the stored finding summaries plus the assessment prompt/plan for report writing and is instructed not to invent vulnerabilities or exploitation results. If DeepSeek is unavailable, Xdigitex still generates a deterministic PDF report from the scan findings.
