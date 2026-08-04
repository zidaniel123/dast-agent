# Evidence and Finding Format

How the pentest phase structures findings and evidence. This maps directly onto
the `WalkVulns` / `WalkVuln` / `WalkVulnEvidences` output schemas.

## Finding structure

Each vulnerability record contains:

| Field | Meaning |
|-------|---------|
| `name` | Short, specific title (e.g. "Username enumeration on login"). |
| `description` | What the weakness is and why it matters. |
| `observation` | What was actually observed in this application. |
| `cwe_id` | Strict `CWE-<NUM>` identifier (see below). |
| `severity` | One of the severity enum values (see below). |
| `reproduction_steps` | Ordered, concrete steps another tester can follow to reproduce the finding. |
| `remediation` | The specific fix and the secure pattern to adopt — not a generic platitude. |
| `remediation_references` | Authoritative fix URLs (CWE page, OWASP cheat sheet, framework docs). |
| `evidences` | One or more evidence records (see below). |

## Evidence records

Each entry in `evidences` captures a single request/response pair:

| Field | Meaning |
|-------|---------|
| `name` | Short label for this piece of evidence. |
| `description` | What this request/response demonstrates. |
| `http_request` | The raw HTTP request, including the `X-Pentest-Case` header. |
| `http_response` | The raw HTTP response (status line, headers, relevant body). |
| `screenshot_path` | Filename of the screenshot captured while the weakness was visible (saved into the output directory). Empty only when there is no rendered page to show. |

Capture requests and responses verbatim. Every request shown as evidence must
carry the `X-Pentest-Case` header whose value is the executed test case name, so
the traffic is attributable and reproducible.

Capture the screenshot with the Playwright `browser_take_screenshot` tool using a
`filename` of the form `finding-<n>-<short-slug>.png`; the browser saves into the
run's output directory, so record just the filename in `screenshot_path`. The
report embeds it inline as an image next to the HTTP evidence.

### Example evidence

```http
POST /api/login HTTP/1.1
Host: staging.example.com
Content-Type: application/json
X-Pentest-Case: Username enumeration on login

{"username":"nonexistent@example.com","password":"x"}
```

```http
HTTP/1.1 404 Not Found
Content-Type: application/json

{"error":"No account found for that email"}
```

The distinct 404 / "No account found" response (versus a generic failure for a
valid username) is what makes this a positive result.

## CWE format

Always express the weakness as `CWE-<NUM>` with no surrounding prose in the
`cwe_id` field -- for example `CWE-307`, `CWE-89`, `CWE-384`. Reference
`web-test-cases.md` for the CWE associated with each test.

## Severity rubric

Use exactly one of these values:

| Severity | When |
|----------|------|
| `Critical` | Direct account takeover, authentication bypass, or injection with full impact. |
| `High` | Serious weakness with a clear, practical exploitation path. |
| `Medium` | Real weakness requiring specific conditions or with limited impact. |
| `Low` | Minor issue or missing hardening with low practical impact. |
| `Informational` | Defense-in-depth observation with no direct exploitability. |

Only report findings confirmed against the running application, and back every
finding with request/response evidence.
