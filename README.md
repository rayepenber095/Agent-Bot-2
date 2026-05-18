# VulnLab Pro

A full-stack **intentionally vulnerable** cybersecurity training platform covering all **OWASP Top 10** vulnerabilities. Includes a one-click toggle between vulnerable and hardened mode, real-time chat (Socket.io), 10 pre-seeded demo users, and interactive exploit labs.

> **EDUCATIONAL USE ONLY** — Do not use real credentials or deploy on a public network without understanding the risks. This application is intentionally insecure.

---

## Features

| Module | What it demos |
|---|---|
| Login / Register | SQL injection auth bypass, weak JWT, bcrypt vs plaintext |
| Dashboard | OWASP Top 10 status overview |
| Channels (Chat) | Stored XSS via Socket.io, real-time message delivery |
| Marketplace | SQL injection in search, IDOR on product detail |
| Wallet | Negative transfer amounts (money theft), IDOR on /api/users/:id exposing SSN |
| Social Feed | Stored XSS in posts/comments |
| Users | User enumeration, IDOR sensitive data exposure |
| Debug Lab | RCE via eval(), command injection (ping), SSRF, path traversal, env dump, open redirect |
| Admin Panel | Full user management, security event log, mode toggle |

---

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

---

## Local Setup on Kali Linux

### 1. Install Node.js 20+ (via nvm — recommended)

```bash
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.7/install.sh | bash
source ~/.bashrc
nvm install 20
nvm use 20
node --version   # should print v20.x.x
```

### 2. Install pnpm

```bash
npm install -g pnpm
pnpm --version   # should print 9.x.x or higher
```

### 3. Install PostgreSQL

```bash
sudo apt update
sudo apt install -y postgresql postgresql-contrib

# Start the service
sudo systemctl start postgresql
sudo systemctl enable postgresql   # auto-start on boot
```

### 4. Create the database and user

```bash
sudo -u postgres psql << 'SQL'
CREATE USER vulnlab WITH PASSWORD 'vulnlab';
CREATE DATABASE vulnlabdb OWNER vulnlab;
GRANT ALL PRIVILEGES ON DATABASE vulnlabdb TO vulnlab;
SQL
```

Your `DATABASE_URL` will be:
```
postgresql://vulnlab:vulnlab@localhost/vulnlabdb?sslmode=disable
```

### 5. Clone / enter the project

```bash
# If cloning fresh:
git clone <repo-url> vulnlab-pro
cd vulnlab-pro

# Or if already in the folder:
cd /path/to/vulnlab-pro
```

### 6. Install dependencies

```bash
pnpm install
```

### 7. Set environment variables

Create a `.env` file in the **project root**:

```bash
cat > .env << 'EOF'
DATABASE_URL=postgresql://vulnlab:vulnlab@localhost/vulnlabdb?sslmode=disable
SESSION_SECRET=change-this-to-a-long-random-string-in-production
EOF
```

> On Kali, `export` them directly if you prefer:
> ```bash
> export DATABASE_URL="postgresql://vulnlab:vulnlab@localhost/vulnlabdb?sslmode=disable"
> export SESSION_SECRET="dev-secret-key"
> ```

### 8. Run database migrations and seed data

```bash
pnpm --filter @workspace/api-server run db:push
pnpm --filter @workspace/api-server run db:seed
```

If `db:push` / `db:seed` scripts are not available, apply the schema manually:

```bash
PGPASSWORD=vulnlab psql -h localhost -U vulnlab -d vulnlabdb \
  -f artifacts/api-server/src/db/schema.sql
```

Or run the seed script directly:

```bash
cd artifacts/api-server
node --loader ts-node/esm src/db/seed.ts
```

### 9. Start the API server

Open **terminal 1**:

```bash
PORT=8080 BASE_PATH=/api \
  DATABASE_URL="postgresql://vulnlab:vulnlab@localhost/vulnlabdb?sslmode=disable" \
  SESSION_SECRET="dev-secret-key" \
  pnpm --filter @workspace/api-server run dev
```

You should see:
```
VulnLab Pro API listening port=8080
DB connected
```

### 10. Start the frontend

Open **terminal 2**:

```bash
PORT=3000 BASE_PATH=/ \
  pnpm --filter @workspace/vulnlab-pro run dev
```

You should see:
```
  VITE v7.x  ready in Xms
  ➜  Local: http://localhost:3000/
```

### 11. Open in browser

```
http://localhost:3000
```

Log in with any account from the demo accounts table above (e.g. `admin` / `Admin@123`).

---

## Running in Production (local self-hosted)

### Build everything

```bash
# Build API server
PORT=8080 BASE_PATH=/api \
  pnpm --filter @workspace/api-server run build

# Build frontend
PORT=3000 BASE_PATH=/ \
  pnpm --filter @workspace/vulnlab-pro run build
```

### Serve the API

```bash
PORT=8080 DATABASE_URL="postgresql://vulnlab:vulnlab@localhost/vulnlabdb?sslmode=disable" \
  SESSION_SECRET="change-me" \
  node --enable-source-maps artifacts/api-server/dist/index.mjs
```

### Serve the frontend (static)

Install a simple static file server if needed:

```bash
npm install -g serve
serve -s artifacts/vulnlab-pro/dist/public -l 3000
```

Or use nginx (see proxy setup below).

### nginx reverse proxy (optional — puts both on port 80)

```nginx
server {
    listen 80;
    server_name localhost;

    # Frontend static files
    root /path/to/vulnlab-pro/artifacts/vulnlab-pro/dist/public;
    index index.html;

    location / {
        try_files $uri $uri/ /index.html;
    }

    # API proxy
    location /api/ {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }

    # Socket.io
    location /api/socket.io/ {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
    }
}
```

Apply:

```bash
sudo cp vulnlab.conf /etc/nginx/sites-available/vulnlab
sudo ln -s /etc/nginx/sites-available/vulnlab /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
```

---

## Project Structure

```
vulnlab-pro/
├── artifacts/
│   ├── api-server/          # Express 5 + Socket.io backend
│   │   ├── src/
│   │   │   ├── app.ts       # Express app + Socket.io init
│   │   │   ├── index.ts     # HTTP server + listen
│   │   │   ├── routes/      # auth, users, products, channels, messages,
│   │   │   │                #   transactions, social, cart, admin, debug
│   │   │   ├── middleware/  # auth.ts (requireAuth, requireAdmin)
│   │   │   ├── lib/         # security.ts, jwt.ts, db.ts, logger.ts
│   │   │   └── db/          # drizzle schema + seed script
│   │   └── build.mjs        # esbuild bundler config
│   └── vulnlab-pro/         # React + Vite + Tailwind frontend
│       └── src/
│           ├── App.tsx       # Router + ProtectedRoute
│           ├── contexts/     # AuthContext, SecurityContext
│           ├── pages/        # Dashboard, Channels, Marketplace, Wallet,
│           │                 #   Feed, Users, Admin, Debug, Login, Register
│           ├── components/   # Layout, Sidebar, UI primitives
│           └── lib/          # axios.ts (API client), socket.ts, queryClient.ts
├── lib/
│   ├── api-spec/            # OpenAPI 3.1 spec (openapi.yaml)
│   └── api-client-react/    # Auto-generated React Query hooks (Orval)
└── scripts/                 # Shared utility scripts
```

---

## Switching Between Vulnerable and Hardened Mode

1. Log in as `admin` (Admin@123)
2. Click the red **VULNERABLE** / green **HARDENED** toggle in the sidebar
3. Wait ~10 seconds for the server-side cache to expire
4. Re-run any exploit to see the hardened behavior

**What changes in hardened mode:**

| Area | Vulnerable | Hardened |
|---|---|---|
| SQL queries | String concatenation | Parameterized queries |
| Passwords | Stored in plaintext field | bcrypt(12) only |
| HTML output | `dangerouslySetInnerHTML` | DOMPurify sanitized |
| JWT | `HS256`, key=`secret`, no expiry | `HS256`, strong key, 1h expiry |
| Rate limiting | None | express-rate-limit on auth routes |
| Account lockout | None | 5 failed attempts |
| CSP headers | None | Strict Content-Security-Policy |

---

## Regenerating the API Client

If you modify `lib/api-spec/openapi.yaml`:

```bash
pnpm --filter @workspace/api-spec run codegen
```

This regenerates React Query hooks in `lib/api-client-react/src/`.

---

## Troubleshooting

**Login says "Invalid credentials" for all users**

The seed may have set a wrong password hash. Fix with:

```bash
node --input-type=module << 'EOF'
import bcrypt from "bcrypt";
const users = [
  [1,"Admin@123"],[2,"john123"],[3,"password"],[4,"123456"],
  [5,"diana123"],[6,"eve123"],[7,"test123"],[8,"grace123"],
  [9,"111111"],[10,"qwerty"]
];
for (const [id, pw] of users) {
  const h = await bcrypt.hash(pw, 10);
  console.log(`UPDATE users SET password='${h}' WHERE id=${id};`);
}
EOF
```

Pipe the output into psql to apply the updates.

**Frontend shows a blank page after build**

Run the frontend build before starting:

```bash
PORT=3000 BASE_PATH=/ pnpm --filter @workspace/vulnlab-pro run build
```

**Socket.io chat not connecting**

Ensure the API server is running and that the `socket.io` path is `/api/socket.io` in both the server config and the client `socket.ts`.

**`pg` module not found in production build**

`pg` is intentionally excluded from the esbuild bundle. Make sure `node_modules` is present alongside `dist/index.mjs` when running in production, or run `pnpm install --prod` in `artifacts/api-server/`.

---

## Security Note

This project runs **intentionally vulnerable code**. Never expose it to the public internet or use real personal data. Use in an isolated VM, lab network, or local machine only.
