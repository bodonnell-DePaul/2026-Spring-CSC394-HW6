# Insecure Auth App

Intentionally insecure React + ASP.NET Core starter app for CSC 436 Homework 5. This project is for security review practice only and should not be deployed.

## Stack

- React front end with Vite in `frontend/`
- ASP.NET Core backend in `backend/`
- Mock OAuth/OIDC provider endpoints implemented inside the backend

## Setup

Requirements:

- Node.js 20+
- .NET SDK 8+

```bash
npm install
npm start
```

Then open `http://localhost:5173`.

The backend runs at `http://localhost:5000` and the React dev server proxies API requests to it.

## Intentional Vulnerabilities

| # | Vulnerability | Starter location |
|---|---|---|
| 1 | JWT in localStorage with no expiration check | `frontend/src/App.jsx` |
| 2 | Missing PKCE in OAuth flow | `backend/Program.cs` |
| 3 | Unvalidated API endpoint | `backend/Program.cs` |
| 4 | Hardcoded client secret in front-end code | `frontend/src/App.jsx` |
| 5 | Missing HTTPS redirect and HSTS | `backend/Program.cs` |

## Notes

The OAuth flow is intentionally implemented in this app, not in a separate course project. Students should fix and improve the React front end and ASP.NET Core backend as part of the assignment.
