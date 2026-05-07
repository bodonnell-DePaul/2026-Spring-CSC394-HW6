# Homework 6: Secure Authentication System

---

## Overview

Authentication is the most security-critical feature in any web application. A single vulnerability can expose every user's data. In this homework, you will:

1. **Fix a broken, insecure app** — identify and remediate 5 real-world authentication vulnerabilities in a React + ASP.NET Core application.
2. **Implement OAuth/OIDC** in the provided `insecure-auth-app/` using Authorization Code flow with PKCE.
3. **Write a security report** reflecting on AI-generated auth code and the risks it introduces.

---

## Part 1: Fix the Insecure Auth App 

You are provided a React front end and ASP.NET Core backend in `insecure-auth-app/` that simulate an OAuth-based authentication system. It contains **5 intentional security vulnerabilities**. Your job is to identify, explain, and fix each one.

### Setup

```bash
cd insecure-auth-app
npm install
npm start
```

Open `http://localhost:5173` in your browser. The React front end runs on port 5173 and the ASP.NET Core backend runs on port 5000. Explore the login flow, dashboard, reports route, and API endpoints before making changes.

> Requirements: Node.js 20+ and .NET SDK 8+.

### Starter Vulnerability Locations

| # | Vulnerability | Starter location |
|---|---|---|
| 1 | JWT in localStorage, no expiration check | `insecure-auth-app/frontend/src/App.jsx` |
| 2 | Missing PKCE in OAuth flow | `insecure-auth-app/backend/Program.cs` |
| 3 | Unvalidated API endpoint | `insecure-auth-app/backend/Program.cs` |
| 4 | Client secret in front-end code | `insecure-auth-app/frontend/src/App.jsx` |
| 5 | Missing HTTPS redirect and HSTS | `insecure-auth-app/backend/Program.cs` |

### Vulnerabilities to Fix

#### Vulnerability 1: JWT in localStorage with No Expiration Check

The app stores JWTs in `localStorage` and never checks if they are expired before using them.

**Why it's dangerous:**
- `localStorage` is accessible to any JavaScript running on the page, making it vulnerable to XSS attacks.
- Without expiration checks, a stolen token can be used indefinitely.

**Your task:**
- Check token expiration before using it on the client side.
- Move token storage to a more secure mechanism (e.g., `httpOnly` cookies).
- Ensure expired tokens are cleared and the user is redirected to login.

#### Vulnerability 2: Missing PKCE in OAuth Flow

The OAuth implementation for a Single Page Application does not use PKCE (Proof Key for Code Exchange).

**Why it's dangerous:**
- Without PKCE, the authorization code can be intercepted and exchanged for tokens by an attacker (authorization code interception attack).
- PKCE is **required** for public clients (SPAs, mobile apps) per OAuth 2.1.

**Your task:**
- Generate a cryptographically random `code_verifier`.
- Derive a `code_challenge` using SHA-256.
- Send `code_challenge` and `code_challenge_method=S256` in the authorization request.
- Send `code_verifier` in the token exchange request.
- Validate the verifier against the challenge on the server side.

#### Vulnerability 3: Unvalidated API Endpoint

The `GET /api/user/profile` endpoint does not validate the access token — it trusts whatever is sent.

**Why it's dangerous:**
- Anyone can forge a request with arbitrary user data and access any user's profile.
- This is a broken access control vulnerability (OWASP Top 10 #1).

**Your task:**
- Add token validation middleware that verifies the JWT signature and checks expiration.
- Return `401 Unauthorized` if the token is missing, invalid, or expired.
- Extract user info only from the validated token, not from unverified request data.

#### Vulnerability 4: Hardcoded Client Secret in Front-End

The OAuth `client_secret` is hardcoded in the React code that is served to the browser.

**Why it's dangerous:**
- Anyone can view the page source and extract the client secret.
- With the client secret, an attacker can impersonate your application to the OAuth provider.

**Your task:**
- Remove the `client_secret` from all front-end code.
- Keep all confidential OAuth client credential handling on the ASP.NET Core backend.
- Verify the secret is not present in any file served to the browser.

#### Vulnerability 5: Missing HTTPS Redirect

The app does not enforce HTTPS in production.

**Why it's dangerous:**
- Tokens, credentials, and user data are sent in plain text over HTTP.
- Attackers on the same network can intercept everything (man-in-the-middle attack).

**Your task:**
- Add middleware that redirects HTTP requests to HTTPS in production.
- Set the `Strict-Transport-Security` header.
- Ensure cookies are marked `Secure` so they are only sent over HTTPS.

### Submission Format for Part 1

For **each** vulnerability, include in your submission:

1. **Explanation** — What is the vulnerability and why is it dangerous? (2–3 sentences)
2. **Before** — The vulnerable code (copy from the provided app)
3. **After** — Your fixed code
4. **Justification** — How your fix addresses the vulnerability (2–3 sentences)

---

## Part 2: Implement OAuth/OIDC in `insecure-auth-app/` 

Implement OAuth 2.0 / OpenID Connect authentication in the same `insecure-auth-app/` React + ASP.NET Core application. Do not move this part to a separate course project. Your final app should remain inside this repository.

### Choose a Provider

Pick one:
- **Google** — [Google Identity docs](https://developers.google.com/identity/protocols/oauth2)
- **Microsoft** — [Microsoft Identity Platform docs](https://learn.microsoft.com/en-us/azure/active-directory/develop/)

### Requirements

- Authorization Code flow with PKCE
- Secure token storage (NOT localStorage)
- Login flow (redirect → callback → store tokens)
- Logout (clear tokens, revoke if supported)
- Token refresh (handle expiration gracefully)
- Protect at least 2 front-end routes
- Protect at least 2 API endpoints (return 401)

### Implementation Checklist

- [ ] Register your app with the OAuth provider (get client ID)
- [ ] Implement authorization request with PKCE (`code_challenge`, `code_challenge_method=S256`)
- [ ] Implement callback handler (exchange code for tokens with `code_verifier`)
- [ ] Store tokens securely (httpOnly cookies or secure session)
- [ ] Validate tokens on the server (verify signature, check expiration, check audience)
- [ ] Implement token refresh before expiration
- [ ] Add auth middleware to protect API routes
- [ ] Add route guards to protect front-end pages
- [ ] Implement logout (clear tokens, redirect)
- [ ] Test with expired tokens, invalid tokens, and missing tokens

### AI Usage Policy

You **may** use AI tools (GitHub Copilot, ChatGPT, etc.) to scaffold your OAuth implementation. However:

- You **must** review every line of AI-generated auth code
- You **must** identify at least 3 security issues in the generated code (see Part 3)
- You **must** document your prompts in an AI prompt log
- You are **responsible** for the security of your final implementation

---

## Part 3: Security Report

Write a security report (1–2 pages, markdown format) covering:

### Required Sections

1. **AI Tools Used** 
   - Which AI tool(s) did you use?
   - What prompts did you give for auth-related code?

2. **Security Issues Found in AI-Generated Code** 
   - Identify a **minimum of 3** security issues in the AI-generated code
   - For each issue:
      - What was the issue?
      - Why is it a security risk?
      - How did you fix it?
      - What could happen if it was deployed unfixed?

3. **Security Review Template** 
   - Complete the security review template from `resources/security-review-template.md`
   - Include it in your submission

4. **Reflection** 
   - Would you trust AI to write production auth code without review? Why or why not?
   - What surprised you about the AI-generated auth code?
   - What would you do differently next time?

---

## Submission Requirements

Submit the following to the course assignment page:

- [ ] **GitHub repository link** with all code changes
- [ ] **Meaningful commit messages** (e.g., "Fix: add PKCE to OAuth flow", not "update code")
- [ ] **Part 1 fixes** — either in a markdown file or as comments in the fixed code
- [ ] **Part 2 implementation** — working OAuth/OIDC in `insecure-auth-app/`
- [ ] **Security report** — `security-report.md` in your repo root
- [ ] **Completed security review template** — included in or alongside the security report
- [ ] **AI prompt log** — `ai-prompts.md` in your repo root

---

## Grading Rubric

| Category | Criteria |
|---|---|
| **Part 1** | Vulnerability 1: JWT/localStorage fix with explanation |
| **Part 1** | Vulnerability 2: PKCE implementation with explanation |
| **Part 1** | Vulnerability 3: Token validation middleware with explanation |
| **Part 1** | Vulnerability 4: Client secret moved server-side with explanation |
| **Part 1** | Vulnerability 5: HTTPS redirect with HSTS with explanation |
| **Part 2** | Auth Code flow with PKCE implemented correctly |
| **Part 2** | Secure token storage |
| **Part 2** | Login flow works end-to-end |
| **Part 2** | Logout clears tokens properly |
| **Part 2** | Token refresh handles expiration |
| **Part 2** | Front-end route protection (2+ routes) |
| **Part 2** | API endpoint protection with 401 (2+ endpoints) |
| **Part 3** | AI tools and prompts documented |
| **Part 3** | 3+ security issues identified and explained |
| **Part 3** | Security review template completed |
| **Part 3** | Thoughtful reflection |

### Late Policy

- 10% deduction per day late, up to 3 days
- No submissions accepted after 3 days without prior approval
- Security report and prompt log are **required** — missing either results in a deduction

---

## Resources

- [OAuth 2.0 RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749)
- [PKCE RFC 7636](https://datatracker.ietf.org/doc/html/rfc7636)
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [JWT Best Practices](https://datatracker.ietf.org/doc/html/rfc8725)
- Course slides: Week 5 — Authentication & Authorization
- `resources/security-review-template.md`

---

## Academic Integrity

This is an individual assignment. You may discuss concepts with classmates, but all code and writing must be your own. AI-generated code must be reviewed, understood, and documented. Submitting AI output without review is an academic integrity violation.
