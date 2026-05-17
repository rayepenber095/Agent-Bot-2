# VulnLab Pro

A full-stack intentionally vulnerable cybersecurity training platform with all OWASP Top 10 vulnerabilities, a one-click vulnerable/hardened mode toggle, real-time chat (Socket.io), and 10 pre-seeded users.

## Run & Operate

- `pnpm --filter @workspace/api-server run dev` — run the API server (port from workflow)
- `pnpm --filter @workspace/vulnlab-pro run dev` — run the frontend (port 24452)
- `pnpm run typecheck` — full typecheck across all packages
- `pnpm run build` — typecheck + build all packages
- `pnpm --filter @workspace/api-spec run codegen` — regenerate API hooks and Zod schemas from the OpenAPI spec
- Required env: `DATABASE_URL` — Postgres connection string, `SESSION_SECRET` — session key

## Stack

- pnpm workspaces, Node.js 24, TypeScript 5.9
- API: Express 5 + Socket.io (real-time chat)
- DB: PostgreSQL + raw `pg` Pool (intentional raw SQL for SQLi demos) + Drizzle ORM for schema
- Validation: Zod (`zod/v4`), `drizzle-zod`
- API codegen: Orval (from OpenAPI spec)
- Build: esbuild (CJS bundle)
- Frontend: React + Vite + Tailwind CSS + wouter + React Query

## Where things live

- `artifacts/api-server/src/app.ts` — Express app, Socket.io, route mounting
- `artifacts/api-server/src/lib/security.ts` — security mode cache (reads from DB)
- `artifacts/api-server/src/lib/jwt.ts` — JWT sign/verify (weak in vuln mode)
- `artifacts/api-server/src/middleware/auth.ts` — requireAuth, optionalAuth, requireAdmin
- `artifacts/api-server/src/routes/` — all route files (auth, users, products, channels, messages, transactions, social, cart, admin, debug)
- `artifacts/vulnlab-pro/src/App.tsx` — all routes
- `artifacts/vulnlab-pro/src/contexts/` — AuthContext, SecurityContext
- `artifacts/vulnlab-pro/src/pages/` — Dashboard, Channels, Marketplace, Wallet, Feed, Users, Admin, Debug, Login, Register, Cart, Orders

## Architecture decisions

- Security mode stored in `app_settings` DB table (id=1), cached in memory for 10s
- Vulnerable mode: raw string concatenation in SQL (SQLi), dangerouslySetInnerHTML (XSS), JWT with 'secret' key and no expiry
- Hardened mode: parameterized queries, sanitized HTML, bcrypt(12), strict JWT (1h expiry), rate limiting, CSP headers, account lockout after 5 failed attempts
- Socket.io path: `/api/socket.io` (path-based routing via shared proxy)
- All vulnerabilities annotated with [VULN-A01] through [VULN-A10] comments

## Product

- **Login/Register** — with 10 pre-seeded demo users (admin/sudo, regular users, seller, moderator)
- **Dashboard** — OWASP Top 10 status cards + quick navigation
- **Channels** — real-time chat (Socket.io) with stored XSS in vulnerable mode
- **Marketplace** — 50 products, SQLi search in vulnerable mode, add-to-cart
- **Wallet** — money transfers (negative amounts steal money in vuln mode), transaction history, IDOR-exposed SSN/plaintext password
- **Social Feed** — posts, likes, comments with stored XSS in vulnerable mode
- **Users** — user enumeration, IDOR demo panel showing any user's sensitive data
- **Debug Lab** — interactive RCE (eval), command injection (ping), env var exposure, SSRF, path traversal, open redirect
- **Admin Panel** — user management (lock/unlock/delete/role change/balance), request logs, security event log, mode toggle

## Demo Accounts

| Username | Password  | Role      |
|----------|-----------|-----------|
| admin    | Admin@123 | sudo      |
| john     | john123   | user      |
| alice    | password  | user      |
| mike     | 123456    | user      |
| diana    | diana123  | seller    |
| eve      | eve123    | user      |
| frank    | test123   | user      |
| grace    | grace123  | moderator |
| henry    | 111111    | seller    |
| ivan     | qwerty    | admin     |

## User preferences

- Dark cybersecurity aesthetic (#0d1117 background, red for vulnerable, green for hardened)
- All vulnerabilities annotated with OWASP A0X codes in code comments
- Educational-only disclaimer in UI

## Gotchas

- After changing security mode via the sidebar toggle, wait ~10s for mode cache to expire in API
- The `pg` package must be externalized in `build.mjs` (not bundled)
- Socket.io path must match `${BASE}/socket.io` on both server and client
- User passwords were re-hashed after seeding — correct passwords are in the table above

## Pointers

- See the `pnpm-workspace` skill for workspace structure, TypeScript setup, and package details
- OpenAPI spec at `lib/api-spec/openapi.yaml`
- Generated hooks at `lib/api-client-react/src/`
