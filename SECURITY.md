# Security Policy

## This tool generates real attack traffic

The DAST agent drives a real browser and sends real security-testing traffic --
including injection probes and authentication attacks -- to whatever target it
is pointed at. Treat it accordingly.

## Authorized use only

- Run this tool **only** against applications you own or are **explicitly
  authorized in writing** to test.
- Agree scope, environment, accounts, and acceptable request rate before you
  start, and keep the run within the configured `--scope`.
- Perform **non-destructive** testing only. Do not delete data, exfiltrate real
  user data, lock out accounts you do not control, or degrade availability.
- Every request sent while executing a test case carries an `X-Pentest-Case`
  header so defenders can attribute the traffic. Do not remove or spoof it.

See [`references/authorization-and-scope.md`](references/authorization-and-scope.md)
for the full rules of engagement.

## Handling credentials and output

- Credentials are supplied via CLI flags or environment variables only. Never
  hardcode or commit them. `.env` is gitignored -- keep it that way.
- Output reports (`features.md`, `pentest_results.md`) may contain sensitive
  data captured as evidence. Store them securely, share only with authorized
  parties, and retain them no longer than necessary.

## Reporting a vulnerability in this project

If you discover a security issue in this tool itself, please report it
responsibly rather than opening a public issue:

1. Open a private security advisory on the repository, or contact the
   maintainers directly.
2. Include a clear description, affected version/commit, and reproduction steps.
3. Allow a reasonable disclosure window before any public discussion.

We will acknowledge the report, investigate, and coordinate a fix and
disclosure timeline with you.
