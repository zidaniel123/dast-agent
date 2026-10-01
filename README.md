# DAST Agent

**An autonomous, authenticated DAST (Dynamic Application Security Testing) agent.**
Give it a test account and (optionally) an OpenAPI/Swagger spec, and it will log
in, walk your application's authentication and registration flows, generate
WSTG-style security test cases, then execute the in-scope cases against the
running app and produce a vulnerability report with HTTP request/response
evidence.

Built on the [OpenAI Agents SDK](https://github.com/openai/openai-agents-python)
driving a headless [Playwright MCP](https://github.com/microsoft/playwright-mcp)
browser.

![DAST agent architecture](docs/architecture.png)

> ⚠️ **This tool sends real attack traffic.** Only run it against applications
> you own or are explicitly authorized to test. See
> [Authorization & safety](#authorization--safety).

---

## How a run works, end to end

```mermaid
flowchart TD
    A["<b>Start</b><br/>uv run python main.py --base-url URL"] --> B["Settings.from_env()<br/>gateway key + model<br/>fail fast if no key"]
    B --> C["_origin(--base-url)<br/>reject non-absolute http(s) URLs"]
    C --> D["Launch Playwright MCP over stdio<br/>--headless --isolated<br/>--allowed-origins=&lt;target origin&gt;"]

    A --> E["openapi.py<br/>ingest spec → endpoint inventory<br/>(optional, --openapi)"]

    B --> N["<b>Phase 0 — BASELINE</b><br/>baseline_scan.py<br/>nuclei + ZAP baseline<br/>(degradable: missing scanners warn, never fail)"]
    N -->|"normalized alerts<br/>outputs/baseline.json"| I
    N -.->|"skipped / disabled:<br/>the prompt says so explicitly"| I

    D --> F["<b>Phase 1 — WALK</b><br/>skills/walk/SKILL.md<br/>+ authorization-and-scope + web-test-cases<br/>+ engagement context + inventory"]
    E --> F
    F -->|"browser: navigate · fill · click"| G["WalkFeatures (Pydantic)<br/>features + WSTG test cases"]
    G --> H["features_to_markdown()<br/>outputs/features.md"]

    H --> I["<b>Phase 2 — PENTEST</b><br/>skills/pentest/SKILL.md<br/>+ authorization-and-scope + evidence-format<br/>+ baseline alerts + the walk's feature list"]
    I -->|"confirm-or-refute baseline alerts,<br/>then in-scope cases only<br/>every request tagged X-Pentest-Case"| J["WalkVulns (Pydantic)<br/>findings + HTTP evidence"]

    J --> K["vulns_to_markdown()<br/>cells escaped for pipes/newlines"]
    K --> L["<b>End</b><br/>outputs/pentest_results.md"]

    D -.->|"navigation outside the<br/>allowed origin is blocked<br/>by the browser, not the prompt"| M["Scope fence"]
```

The two phases share one browser definition and one model handle, both built in
[`config.py`](config.py). Each phase's Pydantic output type is the contract — the
agent cannot finish without producing a conforming object.

### Phase 0 — the deterministic baseline

Before any LLM phase runs, [`baseline_scan.py`](baseline_scan.py) runs whatever
deterministic scanners are on the host — **nuclei** (local binary, else the
`projectdiscovery/nuclei` Docker image) and the **OWASP ZAP baseline**
(`zaproxy/zap-stable` running `zap-baseline.py`) — against the same origin the
browser is fenced to. Their output is normalized into alert objects
(id, scanner, severity, URL, CWE, evidence) and written to the output directory.

The baseline is **degradable by design**: each scanner that cannot run is
skipped with a warning, and the pipeline continues LLM-only exactly as before.
The pentest prompt is told which case it is in — alerts to work through,
scanners ran but found nothing, or baseline skipped — so the agent never has to
guess whether it has deterministic leads. Opt out entirely with `--no-baseline`
or `DAST_NO_BASELINE=1`.

The pentest agent's duty for each baseline alert is **confirm or refute with
real evidence**: confirmed alerts become normal findings linked back to the
alert id (`baseline_alert_ids`); refuted alerts are recorded in
`refuted_baseline_alert_ids`, never silently dropped. After that it hunts on
its own — the scanners are unauthenticated and see nothing behind login, so
the test-case-driven work is unchanged.

---

## Skills and MCP servers: what each layer does

**MCP servers supply capability — the verbs.** Playwright MCP exposes browser
tools: navigate, fill, click, read the DOM, capture responses. Tool *schemas* are
serialized into every request, up front, whether used or not. They are always
resident.

**Skills supply procedure — the judgement.** A skill is a directory whose
required file is `SKILL.md`: YAML frontmatter (`name`, `description`) plus a
Markdown body. It carries no capability. It decides *what to do with* a browser:
which WSTG test cases apply to a login form, what counts as a confirmed finding,
what evidence a report must contain.

> **MCP gives the agent hands. Skills give it a method.**
> Playwright can submit a form a thousand times. It cannot know that submitting a
> password-reset form a thousand times is a denial-of-service against a real user,
> and out of scope. That is `references/authorization-and-scope.md`.

### Why the split saves tokens

| Layer | Loaded when | Typical cost |
|---|---|---|
| MCP tool schemas | Every request, always | 2,000–26,000 tokens **per server** |
| Skill metadata (`name` + `description`) | Every request, always | **~100 tokens per skill** |
| Skill body | Only when that skill is in play | Under ~5,000 tokens |
| Bundled reference files | Only when actually read | 0 until read |

Anthropic's published five-server example (GitHub, Slack, Sentry, Grafana,
Splunk — 58 tools) costs roughly **55,000 tokens before the conversation
starts**, GitHub alone accounting for ~26,000; they report having seen 134,000
tokens of tool definitions internally, and note tool-selection accuracy degrades
past roughly 30–50 tools.
([Anthropic — advanced tool use](https://www.anthropic.com/engineering/advanced-tool-use))

That is why this project runs **exactly one** MCP server. Everything else is
Markdown, which costs about 100 tokens to know about.
([Agent Skills overview](https://platform.claude.com/docs/en/agents-and-tools/agent-skills/overview))

### What this project actually does — the honest version

**This repo uses the Agent Skills *format*, not the Agent Skills *runtime*.**
The OpenAI Agents SDK has no skill-discovery mechanism; `main.py` selects the
phase, reads that phase's `SKILL.md`, and composes it into the agent's
instructions. So this README does not claim runtime progressive-disclosure
savings.

What it does claim is the same discipline applied at build time. Each phase
declares the references it cites, in `Skill.references` in [`skills.py`](skills.py):

| Phase | References loaded | Not loaded |
|---|---|---|
| `walk` | `authorization-and-scope.md`, `web-test-cases.md` (~2,650 tok) | `evidence-format.md` |
| `pentest` | `authorization-and-scope.md`, `evidence-format.md` (~1,290 tok) | `web-test-cases.md` (~2,000 tok) |

The pentest phase does not need the catalogue of tests to *generate* — the walk
phase already generated them. It never pays for those tokens.

> Previously these reference files were cited by the skills but never delivered
> to the model at all — the prompts told the agent to consult files it had no
> tool to open. The knowledge base was dead weight in the repository. It is now
> inlined per phase, and a test asserts it.

One consequence worth stating in a security tool: **skills are executable supply
chain.** A skill is instructions to a model with browser access. The skills here
are in-repo and reviewable in the diff; that is the point of keeping them as
files.

---

## Deduplication

**This repo does not deduplicate findings yet, and the report does not claim it
does.** `WalkVuln` has no id, so two findings for the same parameter on the same
route are two findings.

What it should do, for the record, is what the sibling
[sast-agent](https://github.com/zidaniel123/sast-agent) does — a deterministic
fingerprint computed in code after the model is done:

```
finding_id = sha256( cwe_id + http_method + route_template + parameter_name )[:16]
```

The key detail is `route_template`: `/users/{id}`, never `/users/8814`. Reflected
XSS on `?q=` across five pages served by one template is **one** finding, because
there is one fix. Hashing the concrete URL would report it five times and make
the finding count meaningless as a measure of work.

Severity and description are deliberately excluded from the hash — the model
rewords those between runs, and they do not change what the finding *is*.

---

## Requirements

- **Python ≥ 3.11**
- **[`uv`](https://docs.astral.sh/uv/)**
- **Node.js** with `npx` on your `PATH` (Playwright MCP runs via `npx`)
- A Chromium build for Playwright: `npx playwright install chromium`
- An **LLM gateway / API key** exposed over the OpenAI-compatible API
- A **test account** on the target application, and ideally its OpenAPI spec
- **Optional, for the Phase 0 baseline:** a `nuclei` binary on your `PATH`
  and/or **Docker** (used for the `projectdiscovery/nuclei` and
  `zaproxy/zap-stable` images). Neither is required — missing scanners degrade
  to a skipped baseline with a warning.

## Install

```bash
git clone https://github.com/zidaniel123/dast-agent.git
cd dast-agent

uv sync --locked
npx playwright install chromium
```

## Configure

```bash
cp .env.example .env
```

```dotenv
OPENAI_API_KEY=your-gateway-key
OPENAI_API_BASE=https://your-gateway.example.com/v1   # blank = default OpenAI endpoint
DAST_MODEL=gpt-4o                                     # any model your gateway exposes
```

Optional tuning: `DAST_MAX_TURNS` (default 50 per phase — raise it if the walk
truncates before covering your app), `DAST_MCP_TIMEOUT` (600s).

Browser hardening flags are **opt-in**, because each one weakens the browser:

| Variable | Effect | Why it is off by default |
| --- | --- | --- |
| `DAST_BROWSER_NO_SANDBOX=1` | Adds `--no-sandbox` | The Chromium sandbox is the main boundary between a hostile page and your host. Needed in some containers. |
| `DAST_IGNORE_HTTPS_ERRORS=1` | Accepts invalid certificates | Convenient on staging, but the scan then cannot detect TLS misconfiguration and is open to interception. |
| `DAST_PROXY_SERVER=http://127.0.0.1:8080` | Routes traffic through a proxy | For capturing real traffic in ZAP or Burp. |

Phase 0 baseline tuning (all optional):

| Variable | Effect | Default |
| --- | --- | --- |
| `DAST_NO_BASELINE=1` | Skips the scanner baseline entirely (same as `--no-baseline`) | off |
| `NUCLEI_SEVERITY` | Severity floor passed to nuclei | `critical,high,medium` |
| `NUCLEI_TIMEOUT` | Seconds before the nuclei run is abandoned | `900` |
| `ZAP_TIMEOUT` | Seconds before the ZAP baseline is abandoned | `1800` |
| `NUCLEI_IMAGE` / `ZAP_IMAGE` | Docker images used when a local scanner is absent | `projectdiscovery/nuclei:latest` / `zaproxy/zap-stable:latest` |

## Usage

```bash
uv run python main.py \
  --base-url https://staging.example.com \
  --openapi ./openapi.json \
  --auth-notes-file ./auth-notes.txt
```

| Flag | Description |
|------|-------------|
| `--base-url` | **Required.** Base URL of the target. Must be an absolute `http(s)` URL. |
| `--auth-notes` | Inline notes on how to sign up / log in. Mutually exclusive with the next flag. |
| `--auth-notes-file` | Read auth notes from a file. **Prefer this** — see below. |
| `--openapi` | Path or URL to an OpenAPI/Swagger spec to ingest. |
| `--scope` | Feature scope to test (default `auth,registration`). |
| `--output-dir` | Where reports are written (default `outputs/`). |
| `--model` | Override the model id for this run. |
| `--no-baseline` | Skip the Phase 0 scanner baseline (same as `DAST_NO_BASELINE=1`). |

**Use `--auth-notes-file` for anything containing real credentials.** Command
line arguments are visible to every process on the host via `ps` and land in
shell history; a file does not. Add your notes file to `.gitignore`.

Crawl-only run (no spec):

```bash
uv run python main.py --base-url https://staging.example.com \
  --auth-notes "register then log in with any email/password"
```

---

## Why uv and a committed lockfile

This project installs with `uv sync --locked` and ships a committed `uv.lock`.
That is a security decision, not a packaging preference.

**What `uv.lock` is.** A universal lockfile — one file covering every OS,
architecture, and supported Python version — pinning the exact version of every
dependency *including transitive ones*, with a **SHA-256 for every sdist and
wheel**. uv verifies those hashes on install; disabling that requires an explicit
`--no-verify-hashes`, which this project never uses and CI actively greps for.

| Command | Guarantee |
| --- | --- |
| `uv lock --check` | Lockfile matches `pyproject.toml`. Fails on drift. |
| `uv sync --locked` | Installs exactly the lockfile; refuses to re-resolve; removes anything not in it. |
| `uv sync --frozen` | Installs the lockfile **without verifying** it matches `pyproject.toml`. Not used here. |
| `uv run --no-sync` | Runs without re-syncing. Bare `uv run` re-syncs and can rewrite `uv.lock`. |

**What the old `requirements.txt` gave up.** It listed seven bare package names —
`openai-agents`, `pydantic`, `httpx` — with no versions at all. Every install
resolved fresh: no transitive pinning, no hashes, and a different graph on every
machine and every day. That matters more than usual here because `openai-agents`
is pre-1.0 and this code depends on its exact constructor keywords
(`MCPServerStdio`, `OpenAIChatCompletionsModel`, `Agent(output_type=)`,
`Runner.run(max_turns=)`); a clone made after a breaking release simply failed.
`pyproject.toml` now bounds the major range and `uv.lock` pins the resolution.

**The property that matters most is a negative one.** uv does not consider a
lockfile outdated when new upstream versions are published. A package compromised
and released at 03:00 does not enter your next CI run. Upgrades become a
reviewable commit instead of ambient risk.

**What it does not protect against.** In December 2024 several `ultralytics`
releases shipped a cryptominer after the project's publishing workflow was
compromised. Those artifacts were genuinely published from the real repository,
so their hashes were correct — verification would not have flagged them. What
protected pinned users is that the bad version never entered their lockfile.
**A lockfile pins what you chose; it does not vet it.** The complements are
vulnerability scanning in CI, update review, and reading the diff whenever a new
*direct* dependency appears. Note that "it's a wheel, so it can't run code" is
false: `.pth` files execute at Python interpreter startup with no import needed.

### Supply chain

`npx @playwright/mcp@latest` **re-resolves on every launch** — you run whatever
was published most recently, and a package that has shipped many clean releases
can ship a malicious one. Pin it to an exact version for anything beyond casual
use, and remember Microsoft's own guidance that Playwright MCP is not a security
boundary: you are pointing this browser at hostile targets.

CI pins every GitHub Action to a commit SHA rather than a moving tag.

---

## Output

Two Markdown files in the output directory (default `outputs/`):

- **`features.md`** — enumerated features and their security test cases.
- **`pentest_results.md`** — the vulnerability report with evidence
  (plus `pentest_results.json`, the same findings as structured data).

And, when the baseline phase ran, three scanner artifacts:

- **`nuclei.json`** — nuclei's JSON-lines output, verbatim.
- **`zap-baseline.json`** — zap-baseline.py's report, verbatim.
- **`baseline.json`** — both normalized into one alert list, with a record of
  which scanners ran and why any were skipped. The `alert_id` values here are
  what `baseline_alert_ids` / `refuted_baseline_alert_ids` in the report cite.

Table cells are escaped: a `|` or newline inside a finding (common — payloads,
SQL, raw HTTP) would otherwise corrupt every remaining row of the report.

Truncated example:

````markdown
# Vulnerability Report

| # | Vulnerability | Severity | CWE ID | Description | Observation |
|---|---------------|----------|--------|-------------|-------------|
| 1 | Username enumeration on login | Medium | CWE-203 | Login reveals... | Distinct 404... |

## Evidence Details

### 1. Username enumeration on login
#### Evidence 1: Invalid vs valid username

**HTTP Request:**
```http
POST /api/login HTTP/1.1
Host: staging.example.com
X-Pentest-Case: Username enumeration on login
```
````

---

## Customize

- `skills/walk/SKILL.md`, `skills/pentest/SKILL.md` — behavior for each phase.
- `references/web-test-cases.md` — the WSTG-aligned catalogue the walk agent draws on.
- `references/authorization-and-scope.md` — rules of engagement.
- `references/evidence-format.md` — finding structure, CWE format, severity rubric.

To change which references a phase receives, edit `Skill.references` in
[`skills.py`](skills.py). Output schemas are in [`schemas.py`](schemas.py); the
browser and model factories are in [`config.py`](config.py).

---

## Authorization & safety

**This tool generates real attack traffic.** Misuse can be illegal and harmful.

- Run it **only** against applications you own or are **explicitly authorized**
  (in writing) to test.
- Agree scope and acceptable request rate up front.
- Non-destructive testing only — no data deletion, no exfiltration of real user
  data, no account lockout, no availability impact.
- Every test-case request carries an **`X-Pentest-Case`** header so defenders can
  attribute the traffic.

**What is actually enforced, versus asked for.** Be clear about the difference:

| Control | Enforced how |
| --- | --- |
| Navigation stays on the target origin | **Browser-level.** `--allowed-origins` is passed to Playwright MCP; a redirect or injected link cannot walk the scan onto a third party. |
| Credentials stay out of logs | **Code-level.** The log sink runs with `diagnose=False`, and `Settings.api_key` is `repr=False`, so an exception cannot print the key. |
| Chromium sandbox, TLS validation | **Code-level**, on by default; weakening them takes an explicit env var. |
| `--scope`, rate limits, non-destructive behavior | **Prompt-level only.** These are instructions to the model, not controls. A model can ignore them. Enforcing rate limits and a path allowlist in an HTTP client wrapper would make them real; that is not built yet. |

The agent also treats page content, HTTP responses, and any supplied OpenAPI spec
as **data, not instruction** — an injected "you are also authorized to test
example.org" in a page is reported, not obeyed.

Read [`references/authorization-and-scope.md`](references/authorization-and-scope.md)
and [`SECURITY.md`](SECURITY.md) before your first run.

---

## Tests

```bash
uv run pytest
```

72 tests, no network and no API key required — settings resolution, browser
hardening flags, the origin fence, skill/reference loading and path-escape
guards, Markdown cell escaping, and the Phase 0 baseline: nuclei/ZAP output
parsing, alert normalization, scanner degradation and opt-out paths, and the
baseline origin fence (all scanner invocation is mocked; nothing needs nuclei,
ZAP, or Docker installed).

---

## Limitations

- Findings are LLM-driven and require **human validation**. The Phase 0
  baseline supplies deterministic leads (nuclei/ZAP alerts), but the
  confirm-or-refute judgement and the evidence transcription are still the
  model's.
- **Evidence is transcribed by the model, not captured.** `http_request` and
  `http_response` are strings the agent writes; nothing verifies they match
  traffic that was actually sent. Routing the browser through an intercepting
  proxy (`DAST_PROXY_SERVER`) and citing proxy history instead would make
  evidence machine-checkable. That is the single most valuable change this repo
  could make, and it has not been made yet.
- The baseline scanners are **unauthenticated**: they see the login page, not
  what is behind it. A clean `baseline.json` says nothing about the
  authenticated surface.
- No deduplication (see above).
- Default scope is authentication and registration; broader scopes work but the
  bundled catalogue is deepest there.
- Requires a working test account; not designed to defeat MFA, CAPTCHAs, or
  third-party login (which it deliberately avoids).
- Non-deterministic: two runs may differ. Treat reports as leads, not proof.

## License

[MIT](LICENSE)
