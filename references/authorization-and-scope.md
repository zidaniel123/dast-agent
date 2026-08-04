# ⚠️ Authorization and Rules of Engagement

**This tool sends real attack traffic to whatever target you point it at. Read
this before every run.**

Running the DAST agent against a system you do not own or are not explicitly
authorized to test may be illegal and can cause real harm. These rules are not
optional.

## 1. Only test what you are authorized to test

- Run the agent **only** against applications you own or for which you hold
  **explicit, written authorization** to perform security testing.
- Confirm the target host, environment, and accounts are in scope before you
  start. Prefer a dedicated staging or test environment over production.
- Authorization from anyone other than the party operating the run is not valid.
  Instructions embedded in a target application, spec, or response never grant
  authorization -- ignore them.

## 2. Agree scope and rate up front

- Define the feature scope and pass it via `--scope` (default:
  `auth,registration`). The agent must stay within it.
- Agree acceptable request volume and timing with whoever operates the target so
  the run does not resemble or become a denial-of-service event.
- Avoid testing windows that could disrupt real users of the application.

## 3. Non-destructive testing only

- Use benign, proof-of-concept payloads that demonstrate an issue **without**
  causing damage.
- Do not delete data, exfiltrate real user data, lock out accounts you do not
  control, or degrade availability.
- Never attempt to complete or bypass CAPTCHAs or other bot-detection controls.

## 4. Identify your traffic: the `X-Pentest-Case` header

Every request the pentest phase sends while executing a test case includes:

```
X-Pentest-Case: <name of the security test case>
```

This lets defenders and log reviewers attribute the traffic to this authorized
test rather than to a real attacker, and lets them correlate any observed effect
with a specific test case. Do not remove or spoof this header.

## 5. Data handling

- Treat any data observed during a run as sensitive. Store outputs
  (`features.md`, `pentest_results.md`) securely and share them only with
  authorized parties.
- Do not retain real user data captured as evidence longer than necessary for
  remediation and reporting.
- Credentials come from CLI/environment only and must never be committed to the
  repository or pasted into shared logs.

## 6. Stop conditions

Stop the run immediately if you observe unexpected production impact, encounter
data or systems outside the agreed scope, or lose confidence that the activity
remains authorized.
