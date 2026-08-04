# Web Security Test Case Catalog

A practical, WSTG-aligned catalog the walk agent draws on when generating
security test cases. It is organized by feature area. Each test case lists **what
to test**, **how to test it**, the associated **CWE**, and **what a positive
(vulnerable) result looks like**.

This catalog is knowledge, not a checklist to blindly run. Only generate test
cases for functionality inside the configured engagement scope (default:
authentication and registration).

---

## 1. Authentication

### 1.1 Weak or missing rate limiting on login (credential stuffing / brute force)
- **What:** Whether the login endpoint throttles repeated failed attempts.
- **How:** Submit many login attempts for a known username with varying
  passwords; observe whether lockout, CAPTCHA, or delay is enforced.
- **CWE:** CWE-307 (Improper Restriction of Excessive Authentication Attempts).
- **Positive result:** Unlimited attempts accepted with no lockout, throttling,
  or challenge.

### 1.2 Username enumeration
- **What:** Whether responses reveal which accounts exist.
- **How:** Compare responses/timing for a valid vs. invalid username on login,
  password reset, and registration.
- **CWE:** CWE-203 (Observable Discrepancy).
- **Positive result:** Distinguishable messages, status codes, or response times
  that confirm account existence.

### 1.3 Weak password policy
- **What:** Whether trivial passwords are accepted.
- **How:** Register or change password using very short/common values
  (`123456`, `password`).
- **CWE:** CWE-521 (Weak Password Requirements).
- **Positive result:** A weak password is accepted.

### 1.4 Credentials transmitted or stored insecurely
- **What:** Whether credentials travel over cleartext or appear in URLs/logs.
- **How:** Inspect requests for credentials in query strings, missing HTTPS, or
  reflected secrets.
- **CWE:** CWE-319 (Cleartext Transmission of Sensitive Information).
- **Positive result:** Credentials in a GET query string or sent over HTTP.

### 1.5 Insecure "remember me" / persistent auth
- **What:** Whether persistent tokens are predictable or long-lived without
  revocation.
- **How:** Inspect the persistent cookie/token structure and lifetime.
- **CWE:** CWE-539 (Use of Persistent Cookies Containing Sensitive Information).
- **Positive result:** A guessable or non-expiring persistent credential.

---

## 2. Registration and Session Management

### 2.1 Missing verification allows arbitrary account creation
- **What:** Whether accounts are usable without email/phone verification.
- **How:** Register and attempt to use privileged flows before verifying.
- **CWE:** CWE-620 (Unverified Password Change) / CWE-287 (Improper
  Authentication).
- **Positive result:** Full access granted with no verification step.

### 2.2 Session fixation
- **What:** Whether the session identifier is rotated on authentication.
- **How:** Capture the pre-login session id, authenticate, and check whether the
  same id remains valid.
- **CWE:** CWE-384 (Session Fixation).
- **Positive result:** The pre-authentication session id is honored after login.

### 2.3 Insecure session cookie attributes
- **What:** Whether session cookies set `HttpOnly`, `Secure`, and `SameSite`.
- **How:** Inspect `Set-Cookie` headers.
- **CWE:** CWE-614 (Sensitive Cookie Without Secure Attribute) / CWE-1004
  (Missing HttpOnly).
- **Positive result:** Session cookie missing `HttpOnly` or `Secure`.

### 2.4 Session does not expire / no logout invalidation
- **What:** Whether logout and idle timeout invalidate the server-side session.
- **How:** Log out or wait, then replay the old session token.
- **CWE:** CWE-613 (Insufficient Session Expiration).
- **Positive result:** The old token still authenticates after logout/timeout.

### 2.5 Weak or predictable password-reset tokens
- **What:** Whether reset tokens are guessable, reusable, or non-expiring.
- **How:** Trigger multiple reset tokens and analyze structure, reuse, and TTL.
- **CWE:** CWE-640 (Weak Password Recovery Mechanism).
- **Positive result:** Predictable, reusable, or long-lived reset tokens.

---

## 3. Access Control

### 3.1 Insecure Direct Object Reference (IDOR)
- **What:** Whether object identifiers can be swapped to reach other accounts'
  data.
- **How:** Change an id in a request (path, query, body) to another user's id
  while authenticated as a low-privilege user.
- **CWE:** CWE-639 (Authorization Bypass Through User-Controlled Key).
- **Positive result:** Access to another account's data or actions.

### 3.2 Missing function-level authorization
- **What:** Whether privileged endpoints check authorization, not just
  authentication.
- **How:** Call admin/privileged endpoints as a standard user.
- **CWE:** CWE-285 (Improper Authorization).
- **Positive result:** A privileged action succeeds for an unprivileged user.

### 3.3 Forced browsing to unlinked resources
- **What:** Whether protected resources are reachable by direct URL.
- **How:** Request known/guessable protected paths without navigation.
- **CWE:** CWE-425 (Direct Request / Forced Browsing).
- **Positive result:** Protected content served without authorization.

---

## 4. Input Validation and Injection

### 4.1 SQL injection
- **What:** Whether inputs reach a database query unsafely.
- **How:** Submit benign SQL metacharacters and boolean/time-based probes in
  fields such as login username, search, and filters.
- **CWE:** CWE-89 (SQL Injection).
- **Positive result:** SQL errors, boolean-differential responses, or
  time-delayed responses.

### 4.2 Reflected / stored cross-site scripting (XSS)
- **What:** Whether user input is rendered without encoding.
- **How:** Submit a benign marker payload and observe whether it executes or is
  reflected unencoded.
- **CWE:** CWE-79 (Improper Neutralization of Input During Web Page Generation).
- **Positive result:** The payload executes or is reflected without encoding.

### 4.3 Command / template / NoSQL injection
- **What:** Whether inputs reach a shell, template engine, or NoSQL query.
- **How:** Submit context-appropriate benign probes and observe evaluation.
- **CWE:** CWE-77 (Command Injection) / CWE-1336 (Template Injection) / CWE-943
  (Improper Neutralization in a Data Query).
- **Positive result:** Evidence the input was evaluated server-side.

### 4.4 Open redirect
- **What:** Whether a redirect parameter accepts external destinations.
- **How:** Set a `redirect`/`next`/`returnUrl` parameter to an external host.
- **CWE:** CWE-601 (URL Redirection to Untrusted Site).
- **Positive result:** The application redirects to the attacker-controlled host.

### 4.5 Cross-site request forgery (CSRF)
- **What:** Whether state-changing requests require an unpredictable token.
- **How:** Replay a state-changing request without/with a forged CSRF token.
- **CWE:** CWE-352 (Cross-Site Request Forgery).
- **Positive result:** The action succeeds without a valid anti-CSRF token.

---

## 5. Error Handling and Information Exposure

### 5.1 Verbose errors / stack traces
- **What:** Whether errors leak stack traces, framework, or query details.
- **How:** Trigger malformed input and inspect the response body/headers.
- **CWE:** CWE-209 (Generation of Error Message Containing Sensitive
  Information).
- **Positive result:** Internal details exposed in responses.

### 5.2 Sensitive data in responses or headers
- **What:** Whether responses leak tokens, PII, or internal identifiers.
- **How:** Inspect responses and headers across the in-scope flows.
- **CWE:** CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor).
- **Positive result:** Sensitive values returned unnecessarily.

---

## Severity guidance

Assign severity from impact and exploitability. Authentication bypass, account
takeover, and injection with real impact trend Critical/High; missing hardening
attributes and information disclosure trend Medium/Low; defense-in-depth gaps
trend Low/Informational. Always express the CWE as `CWE-<NUM>`.
