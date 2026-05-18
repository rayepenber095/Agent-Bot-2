import asyncio
import hashlib
import hmac
import json
import os
import re
import sqlite3
import subprocess
import time
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

import jwt
import requests
import socketio
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, RedirectResponse
from pydantic import BaseModel

BASE_PATH = os.getenv("BASE_PATH", "/api").rstrip("/") or "/api"
DB_PATH = Path(os.getenv("PYTHON_BACKEND_DB", "python-backend/vulnlab.db")).resolve()
JWT_WEAK_SECRET = "secret"
JWT_STRONG_SECRET = os.getenv("JWT_SECRET", "very_strong_secret_change_me_in_production_64bytes")
ADMIN_ROLES = {"admin", "sudo", "moderator"}
OWNER_OR_ADMIN_ROLES = {"admin", "sudo"}
SUSPICIOUS_SUBSTRINGS = ("union select", "<script", "javascript:", "../", "169.254", "localhost")

DB_PATH.parent.mkdir(parents=True, exist_ok=True)


@contextmanager
def db_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def hash_password(raw: str) -> str:
    salt = os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", raw.encode(), salt, 200_000)
    return f"pbkdf2${salt.hex()}${digest.hex()}"


def verify_password(raw: str, encoded: str) -> bool:
    try:
        _, salt_hex, digest_hex = encoded.split("$", 2)
        digest = hashlib.pbkdf2_hmac("sha256", raw.encode(), bytes.fromhex(salt_hex), 200_000)
        return hmac.compare_digest(digest.hex(), digest_hex)
    except Exception:
        return False


def sanitize_text_hardened(text: str) -> str:
    # Keep this sanitizer simple and linear-time to avoid regex DoS risks.
    escaped = text.replace("<", "&lt;").replace(">", "&gt;")
    return escaped.replace("javascript:", "[REMOVED]").replace("JAVASCRIPT:", "[REMOVED]")


def create_schema() -> None:
    with db_conn() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS app_settings (
              id INTEGER PRIMARY KEY,
              security_mode TEXT NOT NULL,
              app_name TEXT NOT NULL,
              allow_register INTEGER NOT NULL DEFAULT 1,
              updated_at TEXT,
              updated_by INTEGER
            );

            CREATE TABLE IF NOT EXISTS users (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              username TEXT UNIQUE NOT NULL,
              email TEXT UNIQUE,
              password TEXT NOT NULL,
              password_plain TEXT,
              full_name TEXT,
              avatar_url TEXT,
              bio TEXT,
              phone TEXT,
              address TEXT,
              role TEXT NOT NULL DEFAULT 'user',
              balance REAL NOT NULL DEFAULT 0,
              ssn TEXT,
              secret_note TEXT,
              is_active INTEGER NOT NULL DEFAULT 1,
              is_locked INTEGER NOT NULL DEFAULT 0,
              failed_logins INTEGER NOT NULL DEFAULT 0,
              last_login TEXT,
              last_ip TEXT,
              created_at TEXT NOT NULL,
              updated_at TEXT
            );

            CREATE TABLE IF NOT EXISTS follows (
              follower_id INTEGER NOT NULL,
              followed_id INTEGER NOT NULL,
              PRIMARY KEY (follower_id, followed_id)
            );

            CREATE TABLE IF NOT EXISTS products (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              name TEXT NOT NULL,
              description TEXT,
              price REAL NOT NULL,
              original_price REAL,
              stock INTEGER NOT NULL,
              category TEXT,
              brand TEXT,
              sku TEXT,
              image_url TEXT,
              seller_id INTEGER,
              is_active INTEGER NOT NULL DEFAULT 1,
              rating REAL,
              created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS channels (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              name TEXT NOT NULL,
              slug TEXT UNIQUE NOT NULL,
              description TEXT,
              is_private INTEGER NOT NULL DEFAULT 0,
              created_by INTEGER,
              created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS channel_members (
              channel_id INTEGER NOT NULL,
              user_id INTEGER NOT NULL,
              role TEXT DEFAULT 'member',
              PRIMARY KEY (channel_id, user_id)
            );

            CREATE TABLE IF NOT EXISTS messages (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              channel_id INTEGER NOT NULL,
              sender_id INTEGER NOT NULL,
              content TEXT NOT NULL,
              file_url TEXT,
              file_name TEXT,
              is_deleted INTEGER NOT NULL DEFAULT 0,
              is_pinned INTEGER NOT NULL DEFAULT 0,
              created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS direct_messages (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              sender_id INTEGER NOT NULL,
              receiver_id INTEGER NOT NULL,
              content TEXT NOT NULL,
              is_read INTEGER NOT NULL DEFAULT 0,
              created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS transactions (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              sender_id INTEGER,
              receiver_id INTEGER,
              amount REAL NOT NULL,
              type TEXT NOT NULL,
              status TEXT NOT NULL DEFAULT 'completed',
              note TEXT,
              reference TEXT,
              created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS cart_items (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              user_id INTEGER NOT NULL,
              product_id INTEGER NOT NULL,
              quantity INTEGER NOT NULL,
              added_at TEXT NOT NULL,
              UNIQUE(user_id, product_id)
            );

            CREATE TABLE IF NOT EXISTS orders (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              buyer_id INTEGER NOT NULL,
              total REAL NOT NULL,
              status TEXT NOT NULL,
              shipping_address TEXT,
              created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS order_items (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              order_id INTEGER NOT NULL,
              product_id INTEGER NOT NULL,
              quantity INTEGER NOT NULL,
              price_at_purchase REAL NOT NULL
            );

            CREATE TABLE IF NOT EXISTS posts (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              author_id INTEGER NOT NULL,
              content TEXT NOT NULL,
              image_url TEXT,
              created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS post_likes (
              post_id INTEGER NOT NULL,
              user_id INTEGER NOT NULL,
              PRIMARY KEY (post_id, user_id)
            );

            CREATE TABLE IF NOT EXISTS comments (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              post_id INTEGER NOT NULL,
              author_id INTEGER NOT NULL,
              content TEXT NOT NULL,
              created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS request_logs (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              timestamp TEXT NOT NULL,
              event_type TEXT NOT NULL,
              method TEXT,
              path TEXT,
              query_string TEXT,
              user_id INTEGER,
              username TEXT,
              ip_address TEXT,
              user_agent TEXT,
              status_code INTEGER,
              duration_ms INTEGER,
              security_mode TEXT,
              is_suspicious INTEGER NOT NULL DEFAULT 0,
              severity TEXT NOT NULL DEFAULT 'low',
              details TEXT
            );
            """
        )


def seed_data() -> None:
    with db_conn() as conn:
        settings = conn.execute("SELECT id FROM app_settings WHERE id=1").fetchone()
        if not settings:
            conn.execute(
                "INSERT INTO app_settings (id, security_mode, app_name, allow_register, updated_at) VALUES (1, 'vulnerable', 'VulnLab Pro', 1, ?)",
                (now_iso(),),
            )

        users_count = conn.execute("SELECT COUNT(*) AS c FROM users").fetchone()["c"]
        if users_count == 0:
            demo_users = [
                ("admin", "admin@example.com", "Admin@123", "sudo", 5000.0, "111-11-1111", "Top secret admin note"),
                ("john", "john@example.com", "john123", "user", 1200.0, "222-22-2222", "John note"),
                ("alice", "alice@example.com", "password", "user", 980.0, "333-33-3333", "Alice note"),
                ("mike", "mike@example.com", "123456", "user", 860.0, "444-44-4444", "Mike note"),
                ("diana", "diana@example.com", "diana123", "seller", 2300.0, "555-55-5555", "Diana note"),
                ("eve", "eve@example.com", "eve123", "user", 740.0, "666-66-6666", "Eve note"),
                ("frank", "frank@example.com", "test123", "user", 660.0, "777-77-7777", "Frank note"),
                ("grace", "grace@example.com", "grace123", "moderator", 1800.0, "888-88-8888", "Grace note"),
                ("henry", "henry@example.com", "111111", "seller", 2100.0, "999-99-9999", "Henry note"),
                ("ivan", "ivan@example.com", "qwerty", "admin", 3200.0, "000-00-0000", "Ivan note"),
            ]
            for uname, email, pwd, role, bal, ssn, secret in demo_users:
                conn.execute(
                    """
                    INSERT INTO users (
                      username, email, password, password_plain, role, balance, ssn, secret_note,
                      is_active, is_locked, failed_logins, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, 0, 0, ?)
                    """,
                    (uname, email, hash_password(pwd), pwd, role, bal, ssn, secret, now_iso()),
                )

        products_count = conn.execute("SELECT COUNT(*) AS c FROM products").fetchone()["c"]
        if products_count == 0:
            seller_id = conn.execute("SELECT id FROM users WHERE username='diana'").fetchone()["id"]
            products = [
                ("Wireless Keyboard", "Low-profile keyboard", 49.99, 69.99, 25, "Electronics", "KeyPro", "https://picsum.photos/seed/kb/400"),
                ("Red Team Handbook", "Security training book", 29.99, None, 50, "Books", "SecPress", "https://picsum.photos/seed/book/400"),
                ("Hoodie", "Dark mode hoodie", 39.99, 59.99, 30, "Clothing", "NightOps", "https://picsum.photos/seed/hoodie/400"),
                ("Pentest Toolkit", "Starter toolkit", 99.99, 129.99, 15, "Tools", "HackLab", "https://picsum.photos/seed/tools/400"),
            ]
            for idx, p in enumerate(products, start=1):
                conn.execute(
                    """
                    INSERT INTO products (
                      name, description, price, original_price, stock, category, brand, sku,
                      image_url, seller_id, is_active, rating, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
                    """,
                    (
                        p[0], p[1], p[2], p[3], p[4], p[5], p[6], f"SKU-{idx:04d}", p[7], seller_id, 4.2 + idx / 10, now_iso(),
                    ),
                )

        channels_count = conn.execute("SELECT COUNT(*) AS c FROM channels").fetchone()["c"]
        if channels_count == 0:
            admin_id = conn.execute("SELECT id FROM users WHERE username='admin'").fetchone()["id"]
            channels = [("general", "General chat"), ("exploits", "Exploit payloads"), ("off-topic", "Off topic")]
            for name, desc in channels:
                slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
                cur = conn.execute(
                    "INSERT INTO channels (name, slug, description, is_private, created_by, created_at) VALUES (?, ?, ?, 0, ?, ?)",
                    (name, slug, desc, admin_id, now_iso()),
                )
                channel_id = cur.lastrowid
                conn.execute(
                    "INSERT OR IGNORE INTO channel_members (channel_id, user_id, role) VALUES (?, ?, 'owner')",
                    (channel_id, admin_id),
                )


def get_mode() -> str:
    with db_conn() as conn:
        row = conn.execute("SELECT security_mode FROM app_settings WHERE id=1").fetchone()
        return (row["security_mode"] if row else "vulnerable")


def sign_token(user: dict[str, Any], mode: str) -> str:
    payload = {"id": user["id"], "username": user["username"], "role": user["role"]}
    if mode == "vulnerable":
        return jwt.encode(payload, JWT_WEAK_SECRET, algorithm="HS256")
    payload["exp"] = datetime.now(timezone.utc) + timedelta(hours=1)
    return jwt.encode(payload, JWT_STRONG_SECRET, algorithm="HS256")


def verify_token(token: str, mode: str) -> Optional[dict[str, Any]]:
    try:
        if mode == "vulnerable":
            return jwt.decode(token, JWT_WEAK_SECRET, algorithms=["HS256"])  # type: ignore[return-value]
        return jwt.decode(token, JWT_STRONG_SECRET, algorithms=["HS256"])  # type: ignore[return-value]
    except Exception:
        return None


def row_to_user(row: sqlite3.Row, include_sensitive: bool = False) -> dict[str, Any]:
    user = {
        "id": row["id"],
        "username": row["username"],
        "email": row["email"],
        "full_name": row["full_name"],
        "avatar_url": row["avatar_url"],
        "bio": row["bio"],
        "phone": row["phone"],
        "address": row["address"],
        "role": row["role"],
        "balance": row["balance"],
        "is_active": bool(row["is_active"]),
        "is_locked": bool(row["is_locked"]),
        "failed_logins": int(row["failed_logins"]),
        "last_login": row["last_login"],
        "created_at": row["created_at"],
    }
    if include_sensitive:
        user["ssn"] = row["ssn"]
        user["secret_note"] = row["secret_note"]
        user["password_plain"] = row["password_plain"]
    return user


class AuthInput(BaseModel):
    username: str
    password: str


class RegisterInput(AuthInput):
    email: str


class TransferInput(BaseModel):
    toUsername: str
    amount: float
    note: Optional[str] = None


create_schema()
seed_data()

app = FastAPI(title="VulnLab Pro Python API")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

sio = socketio.AsyncServer(async_mode="asgi", cors_allowed_origins="*")


@app.middleware("http")
async def security_mode_and_logging(request: Request, call_next):
    request.state.security_mode = get_mode()
    auth = request.headers.get("authorization", "")
    token = auth[7:] if auth.startswith("Bearer ") else None
    request.state.user = None
    if token:
        payload = verify_token(token, request.state.security_mode)
        if payload:
            request.state.user = payload

    start = time.time()
    try:
        response = await call_next(request)
    except Exception as exc:
        if request.state.security_mode == "vulnerable":
            response = JSONResponse(status_code=500, content={"error": str(exc)})
        else:
            response = JSONResponse(status_code=500, content={"error": "Internal server error"})

    duration_ms = int((time.time() - start) * 1000)
    raw = f"{request.url.path} {request.url.query}"
    suspicious = int(any(p in raw.lower() for p in SUSPICIOUS_SUBSTRINGS))
    severity = "high" if suspicious or response.status_code >= 500 else ("medium" if response.status_code >= 400 else "low")

    with db_conn() as conn:
        conn.execute(
            """
            INSERT INTO request_logs (
              timestamp, event_type, method, path, query_string, user_id, username,
              ip_address, user_agent, status_code, duration_ms, security_mode,
              is_suspicious, severity, details
            ) VALUES (?, 'http_request', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                now_iso(),
                request.method,
                request.url.path,
                request.url.query,
                request.state.user.get("id") if request.state.user else None,
                request.state.user.get("username") if request.state.user else None,
                request.client.host if request.client else None,
                request.headers.get("user-agent"),
                response.status_code,
                duration_ms,
                request.state.security_mode,
                suspicious,
                severity,
                "suspicious pattern detected" if suspicious else None,
            ),
        )
    return response


def require_auth(request: Request) -> dict[str, Any]:
    user = request.state.user
    if not user:
        raise HTTPException(status_code=401, detail="No token provided")
    return user


def require_admin(request: Request) -> dict[str, Any]:
    user = require_auth(request)
    if user.get("role") in ADMIN_ROLES:
        return user
    if request.state.security_mode == "vulnerable" and request.headers.get("x-admin-override") == "true":
        return user
    raise HTTPException(status_code=403, detail="Insufficient privileges")


@app.get(f"{BASE_PATH}/healthz")
def healthz(request: Request):
    return {"status": "ok", "mode": request.state.security_mode, "timestamp": now_iso()}


@app.post(f"{BASE_PATH}/auth/register")
def register(payload: RegisterInput, request: Request):
    mode = request.state.security_mode
    with db_conn() as conn:
        exists = conn.execute("SELECT id FROM users WHERE username=? OR email=?", (payload.username, payload.email)).fetchone()
        if exists:
            raise HTTPException(status_code=409, detail="Username or email already exists")
        if mode == "hardened" and len(payload.password) < 8:
            raise HTTPException(status_code=400, detail="Password must be at least 8 characters")
        conn.execute(
            """
            INSERT INTO users (username, email, password, password_plain, role, balance, is_active, is_locked, failed_logins, created_at)
            VALUES (?, ?, ?, ?, 'user', 1000, 1, 0, 0, ?)
            """,
            (
                payload.username,
                payload.email,
                hash_password(payload.password),
                payload.password if mode == "vulnerable" else "",
                now_iso(),
            ),
        )
        row = conn.execute("SELECT * FROM users WHERE username=?", (payload.username,)).fetchone()
    user = row_to_user(row, include_sensitive=(mode == "vulnerable"))
    token = sign_token(user, mode)
    return {"token": token, "user": user, "expiresIn": None if mode == "vulnerable" else 3600}


@app.post(f"{BASE_PATH}/auth/login")
def login(payload: AuthInput, request: Request):
    mode = request.state.security_mode
    with db_conn() as conn:
        row = conn.execute("SELECT * FROM users WHERE username=?", (payload.username,)).fetchone()
        if not row:
            raise HTTPException(status_code=401, detail="Invalid credentials")
        if mode == "hardened" and row["is_locked"]:
            raise HTTPException(status_code=403, detail="Account locked due to too many failed attempts")
        if mode == "hardened" and not row["is_active"]:
            raise HTTPException(status_code=403, detail="Account disabled")
        if not verify_password(payload.password, row["password"]):
            if mode == "hardened":
                failed = int(row["failed_logins"]) + 1
                conn.execute(
                    "UPDATE users SET failed_logins=?, is_locked=? WHERE id=?",
                    (failed, 1 if failed >= 5 else 0, row["id"]),
                )
            raise HTTPException(status_code=401, detail="Invalid credentials")
        conn.execute(
            "UPDATE users SET failed_logins=0, last_login=?, last_ip=? WHERE id=?",
            (now_iso(), request.client.host if request.client else None, row["id"]),
        )
        row = conn.execute("SELECT * FROM users WHERE id=?", (row["id"],)).fetchone()

    user = row_to_user(row, include_sensitive=(mode == "vulnerable"))
    token = sign_token(user, mode)
    return {"token": token, "user": user, "expiresIn": None if mode == "vulnerable" else 3600}


@app.post(f"{BASE_PATH}/auth/logout")
def logout():
    return {"ok": True, "message": "Logged out"}


@app.get(f"{BASE_PATH}/auth/me")
def auth_me(request: Request):
    mode = request.state.security_mode
    user = require_auth(request)
    with db_conn() as conn:
        row = conn.execute("SELECT * FROM users WHERE id=?", (user["id"],)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="User not found")
    return row_to_user(row, include_sensitive=(mode == "vulnerable"))


@app.get(f"{BASE_PATH}/users")
def list_users(request: Request, search: Optional[str] = None, limit: int = 20, offset: int = 0):
    mode = request.state.security_mode
    q = "SELECT * FROM users"
    args: list[Any] = []
    if search:
        q += " WHERE username LIKE ? OR full_name LIKE ? OR email LIKE ?"
        s = f"%{search}%"
        args.extend([s, s, s])
    q += " ORDER BY id LIMIT ? OFFSET ?"
    args.extend([limit, offset])
    with db_conn() as conn:
        rows = conn.execute(q, args).fetchall()
    return [row_to_user(r, include_sensitive=(mode == "vulnerable")) for r in rows]


@app.get(f"{BASE_PATH}/users/{{id}}")
def get_user(id: str, request: Request):
    mode = request.state.security_mode
    with db_conn() as conn:
        row = conn.execute("SELECT * FROM users WHERE id=?", (id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="User not found")
        user = row_to_user(row, include_sensitive=(mode == "vulnerable"))
        user["followers_count"] = conn.execute("SELECT COUNT(*) AS c FROM follows WHERE followed_id=?", (id,)).fetchone()["c"]
        user["following_count"] = conn.execute("SELECT COUNT(*) AS c FROM follows WHERE follower_id=?", (id,)).fetchone()["c"]
    return user


@app.put(f"{BASE_PATH}/users/{{id}}")
async def update_user(id: str, request: Request):
    mode = request.state.security_mode
    actor = require_auth(request)
    body = await request.json()
    allowed = ["full_name", "bio", "phone", "address", "avatar_url"]
    if mode == "vulnerable":
        allowed.append("role")
    else:
        if int(id) != int(actor["id"]) and actor["role"] not in OWNER_OR_ADMIN_ROLES:
            raise HTTPException(status_code=403, detail="Cannot edit other user's profile")
    updates = {k: body.get(k) for k in allowed if k in body}
    if not updates:
        raise HTTPException(status_code=400, detail="Nothing to update")
    with db_conn() as conn:
        current = conn.execute("SELECT * FROM users WHERE id=?", (id,)).fetchone()
        if not current:
            raise HTTPException(status_code=404, detail="User not found")
        full_name = updates.get("full_name", current["full_name"])
        bio = updates.get("bio", current["bio"])
        phone = updates.get("phone", current["phone"])
        address = updates.get("address", current["address"])
        avatar_url = updates.get("avatar_url", current["avatar_url"])
        role = updates.get("role", current["role"])
        conn.execute(
            """
            UPDATE users
            SET full_name=?, bio=?, phone=?, address=?, avatar_url=?, role=?, updated_at=?
            WHERE id=?
            """,
            (full_name, bio, phone, address, avatar_url, role, now_iso(), id),
        )
        row = conn.execute("SELECT * FROM users WHERE id=?", (id,)).fetchone()
    return row_to_user(row, include_sensitive=(mode == "vulnerable"))


@app.post(f"{BASE_PATH}/users/{{id}}/follow")
def follow_user(id: str, request: Request):
    actor = require_auth(request)
    if int(id) == int(actor["id"]):
        raise HTTPException(status_code=400, detail="Cannot follow yourself")
    with db_conn() as conn:
        conn.execute("INSERT OR IGNORE INTO follows (follower_id, followed_id) VALUES (?, ?)", (actor["id"], id))
    return {"ok": True}


@app.delete(f"{BASE_PATH}/users/{{id}}/follow")
def unfollow_user(id: str, request: Request):
    actor = require_auth(request)
    with db_conn() as conn:
        conn.execute("DELETE FROM follows WHERE follower_id=? AND followed_id=?", (actor["id"], id))
    return {"ok": True}


def product_with_seller(conn: sqlite3.Connection, row: sqlite3.Row) -> dict[str, Any]:
    product = dict(row)
    product["is_active"] = bool(product["is_active"])
    if product.get("seller_id"):
        seller = conn.execute("SELECT * FROM users WHERE id=?", (product["seller_id"],)).fetchone()
        if seller:
            product["seller"] = {
                "id": seller["id"],
                "username": seller["username"],
                "avatar_url": seller["avatar_url"],
            }
    return product


@app.get(f"{BASE_PATH}/products")
def list_products(search: Optional[str] = None, category: Optional[str] = None, limit: int = 20, offset: int = 0):
    q = "SELECT * FROM products WHERE is_active=1"
    args: list[Any] = []
    if search:
        s = f"%{search}%"
        q += " AND (name LIKE ? OR description LIKE ? OR brand LIKE ? OR category LIKE ?)"
        args.extend([s, s, s, s])
    if category:
        q += " AND category=?"
        args.append(category)
    q += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
    args.extend([limit, offset])
    with db_conn() as conn:
        rows = conn.execute(q, args).fetchall()
        return [product_with_seller(conn, r) for r in rows]


@app.get(f"{BASE_PATH}/products/{{id}}")
def get_product(id: str):
    with db_conn() as conn:
        row = conn.execute("SELECT * FROM products WHERE id=?", (id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Product not found")
        return product_with_seller(conn, row)


@app.post(f"{BASE_PATH}/products")
async def create_product(request: Request):
    user = require_auth(request)
    body = await request.json()
    if not body.get("name") or body.get("price") is None or body.get("stock") is None:
        raise HTTPException(status_code=400, detail="name, price, and stock are required")
    sku = f"USR-{user['id']}-{int(time.time())}"
    with db_conn() as conn:
        cur = conn.execute(
            """
            INSERT INTO products (name, description, price, original_price, stock, category, brand, sku, image_url, seller_id, is_active, rating, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
            """,
            (
                body.get("name"),
                body.get("description"),
                body.get("price"),
                body.get("original_price"),
                body.get("stock"),
                body.get("category"),
                body.get("brand"),
                sku,
                body.get("image_url") or body.get("imageUrl"),
                user["id"],
                4.5,
                now_iso(),
            ),
        )
        row = conn.execute("SELECT * FROM products WHERE id=?", (cur.lastrowid,)).fetchone()
        return JSONResponse(status_code=201, content=product_with_seller(conn, row))


@app.put(f"{BASE_PATH}/products/{{id}}")
async def update_product(id: str, request: Request):
    mode = request.state.security_mode
    user = require_auth(request)
    body = await request.json()
    with db_conn() as conn:
        row = conn.execute("SELECT * FROM products WHERE id=?", (id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Product not found")
        if mode == "hardened" and int(row["seller_id"] or 0) != int(user["id"]) and user["role"] not in OWNER_OR_ADMIN_ROLES:
            raise HTTPException(status_code=403, detail="Not authorized to edit this product")
        image_url = body.get("image_url", body.get("imageUrl", row["image_url"]))
        conn.execute(
            """
            UPDATE products
            SET name=?, description=?, price=?, original_price=?, stock=?, category=?, brand=?, image_url=?
            WHERE id=?
            """,
            (
                body.get("name", row["name"]),
                body.get("description", row["description"]),
                body.get("price", row["price"]),
                body.get("original_price", row["original_price"]),
                body.get("stock", row["stock"]),
                body.get("category", row["category"]),
                body.get("brand", row["brand"]),
                image_url,
                id,
            ),
        )
        row = conn.execute("SELECT * FROM products WHERE id=?", (id,)).fetchone()
        return product_with_seller(conn, row)


@app.delete(f"{BASE_PATH}/products/{{id}}")
def delete_product(id: str, request: Request):
    mode = request.state.security_mode
    user = require_auth(request)
    with db_conn() as conn:
        row = conn.execute("SELECT * FROM products WHERE id=?", (id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Not found")
        if mode == "hardened" and int(row["seller_id"] or 0) != int(user["id"]) and user["role"] not in OWNER_OR_ADMIN_ROLES:
            raise HTTPException(status_code=403, detail="Not authorized")
        conn.execute("DELETE FROM products WHERE id=?", (id,))
    return {"ok": True}


@app.post(f"{BASE_PATH}/products/fetch-image")
async def fetch_product_image(request: Request):
    mode = request.state.security_mode
    require_auth(request)
    body = await request.json()
    image_url = body.get("imageUrl")
    if not image_url:
        raise HTTPException(status_code=400, detail="imageUrl required")
    if mode == "hardened":
        u = image_url.lower()
        if not (u.startswith("http://") or u.startswith("https://")):
            raise HTTPException(status_code=400, detail="Only http/https URLs are allowed")
        for b in ["localhost", "127.0.0.1", "169.254.", "192.168.", "10.", "172."]:
            if b in u:
                raise HTTPException(status_code=400, detail="Internal URLs are not allowed")
        return {"url": image_url, "saved": True}
    try:
        response = requests.get(image_url, timeout=5)
        return {"url": image_url, "saved": True, "content": response.text[:2000]}
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.get(f"{BASE_PATH}/channels")
def list_channels(request: Request):
    mode = request.state.security_mode
    uid = request.state.user["id"] if request.state.user else None
    with db_conn() as conn:
        if mode == "hardened" and uid:
            rows = conn.execute(
                """
                SELECT * FROM channels WHERE is_private=0 OR id IN (
                  SELECT channel_id FROM channel_members WHERE user_id=?
                ) ORDER BY id
                """,
                (uid,),
            ).fetchall()
        else:
            rows = conn.execute("SELECT * FROM channels ORDER BY id").fetchall()

        out = []
        for c in rows:
            member_count = conn.execute("SELECT COUNT(*) AS c FROM channel_members WHERE channel_id=?", (c["id"],)).fetchone()["c"]
            message_count = conn.execute("SELECT COUNT(*) AS c FROM messages WHERE channel_id=? AND is_deleted=0", (c["id"],)).fetchone()["c"]
            creator = None
            if c["created_by"]:
                u = conn.execute("SELECT id, username, avatar_url FROM users WHERE id=?", (c["created_by"],)).fetchone()
                if u:
                    creator = dict(u)
            out.append({**dict(c), "is_private": bool(c["is_private"]), "creator": creator, "member_count": member_count, "message_count": message_count})
        return out


@app.get(f"{BASE_PATH}/channels/{{id}}")
def get_channel(id: str):
    with db_conn() as conn:
        row = conn.execute("SELECT * FROM channels WHERE id=? OR slug=?", (id, id)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Channel not found")
        member_count = conn.execute("SELECT COUNT(*) AS c FROM channel_members WHERE channel_id=?", (row["id"],)).fetchone()["c"]
        message_count = conn.execute("SELECT COUNT(*) AS c FROM messages WHERE channel_id=? AND is_deleted=0", (row["id"],)).fetchone()["c"]
        creator = conn.execute("SELECT id, username, avatar_url FROM users WHERE id=?", (row["created_by"],)).fetchone()
        return {**dict(row), "is_private": bool(row["is_private"]), "creator": dict(creator) if creator else None, "member_count": member_count, "message_count": message_count}


@app.post(f"{BASE_PATH}/channels")
async def create_channel(request: Request):
    user = require_auth(request)
    body = await request.json()
    name = body.get("name")
    if not name:
        raise HTTPException(status_code=400, detail="name required")
    slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-") or f"channel-{int(time.time())}"
    with db_conn() as conn:
        cur = conn.execute(
            "INSERT INTO channels (name, slug, description, is_private, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (name, slug, body.get("description"), 1 if body.get("isPrivate") else 0, user["id"], now_iso()),
        )
        conn.execute(
            "INSERT OR IGNORE INTO channel_members (channel_id, user_id, role) VALUES (?, ?, 'owner')",
            (cur.lastrowid, user["id"]),
        )
        row = conn.execute("SELECT * FROM channels WHERE id=?", (cur.lastrowid,)).fetchone()
        return JSONResponse(status_code=201, content={**dict(row), "is_private": bool(row["is_private"]), "member_count": 1, "message_count": 0})


@app.post(f"{BASE_PATH}/channels/{{id}}/join")
def join_channel(id: str, request: Request):
    user = require_auth(request)
    with db_conn() as conn:
        conn.execute("INSERT OR IGNORE INTO channel_members (channel_id, user_id) VALUES (?, ?)", (id, user["id"]))
    return {"ok": True}


@app.post(f"{BASE_PATH}/channels/{{id}}/leave")
def leave_channel(id: str, request: Request):
    user = require_auth(request)
    with db_conn() as conn:
        conn.execute("DELETE FROM channel_members WHERE channel_id=? AND user_id=?", (id, user["id"]))
    return {"ok": True}


@app.get(f"{BASE_PATH}/channels/{{id}}/messages")
def list_channel_messages(id: str, request: Request, limit: int = 50, offset: int = 0):
    mode = request.state.security_mode
    with db_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM messages WHERE channel_id=? AND is_deleted=0 ORDER BY created_at ASC LIMIT ? OFFSET ?",
            (id, min(limit, 200), max(offset, 0)),
        ).fetchall()
        out = []
        for m in rows:
            sender = conn.execute("SELECT id, username, avatar_url, role FROM users WHERE id=?", (m["sender_id"],)).fetchone()
            content = m["content"]
            if mode == "hardened":
                content = sanitize_text_hardened(content)
            out.append({**dict(m), "is_deleted": bool(m["is_deleted"]), "is_pinned": bool(m["is_pinned"]), "content": content, "sender": dict(sender) if sender else None})
        return out


@app.post(f"{BASE_PATH}/channels/{{id}}/messages")
async def send_message(id: str, request: Request):
    mode = request.state.security_mode
    user = require_auth(request)
    body = await request.json()
    content = body.get("content")
    if not content:
        raise HTTPException(status_code=400, detail="content required")
    if mode == "hardened":
        content = sanitize_text_hardened(content)
    with db_conn() as conn:
        cur = conn.execute(
            "INSERT INTO messages (channel_id, sender_id, content, file_url, created_at) VALUES (?, ?, ?, ?, ?)",
            (id, user["id"], content, body.get("fileUrl"), now_iso()),
        )
        row = conn.execute("SELECT * FROM messages WHERE id=?", (cur.lastrowid,)).fetchone()
        sender = conn.execute("SELECT id, username, avatar_url, role FROM users WHERE id=?", (user["id"],)).fetchone()
        payload = {**dict(row), "is_deleted": False, "is_pinned": False, "sender": dict(sender) if sender else None}

    asyncio.create_task(sio.emit("new_message", payload, room=f"channel:{id}"))
    return JSONResponse(status_code=201, content=payload)


@app.get(f"{BASE_PATH}/messages/search")
def search_messages(channelId: Optional[str] = None, q: Optional[str] = None):
    query = "SELECT * FROM messages WHERE is_deleted=0"
    args: list[Any] = []
    if channelId:
        query += " AND channel_id=?"
        args.append(channelId)
    if q:
        query += " AND content LIKE ?"
        args.append(f"%{q}%")
    query += " ORDER BY created_at DESC LIMIT 50"
    with db_conn() as conn:
        rows = conn.execute(query, args).fetchall()
        out = []
        for m in rows:
            sender = conn.execute("SELECT id, username, avatar_url FROM users WHERE id=?", (m["sender_id"],)).fetchone()
            out.append({**dict(m), "sender": dict(sender) if sender else None})
        return out


@app.get(f"{BASE_PATH}/dm/{{userId}}")
def get_dm(userId: str, request: Request):
    user = require_auth(request)
    with db_conn() as conn:
        rows = conn.execute(
            """
            SELECT * FROM direct_messages
            WHERE (sender_id=? AND receiver_id=?) OR (sender_id=? AND receiver_id=?)
            ORDER BY created_at ASC
            """,
            (user["id"], userId, userId, user["id"]),
        ).fetchall()
        conn.execute("UPDATE direct_messages SET is_read=1 WHERE receiver_id=? AND sender_id=?", (user["id"], userId))
        out = []
        for r in rows:
            sender = conn.execute("SELECT id, username, avatar_url FROM users WHERE id=?", (r["sender_id"],)).fetchone()
            out.append({**dict(r), "is_read": bool(r["is_read"]), "sender": dict(sender) if sender else None})
        return out


@app.post(f"{BASE_PATH}/dm/{{userId}}")
async def send_dm(userId: str, request: Request):
    user = require_auth(request)
    body = await request.json()
    if not body.get("content"):
        raise HTTPException(status_code=400, detail="content required")
    with db_conn() as conn:
        conn.execute(
            "INSERT INTO direct_messages (sender_id, receiver_id, content, is_read, created_at) VALUES (?, ?, ?, 0, ?)",
            (user["id"], userId, body["content"], now_iso()),
        )
    return JSONResponse(status_code=201, content={"ok": True})


@app.get(f"{BASE_PATH}/transactions")
def list_transactions(request: Request):
    mode = request.state.security_mode
    user = require_auth(request)
    uid = user["id"]
    if mode == "vulnerable":
        uid = request.query_params.get("userId", uid)
    with db_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM transactions WHERE sender_id=? OR receiver_id=? ORDER BY created_at DESC LIMIT 50",
            (uid, uid),
        ).fetchall()
        out = []
        for t in rows:
            sender = conn.execute("SELECT id, username, avatar_url FROM users WHERE id=?", (t["sender_id"],)).fetchone() if t["sender_id"] else None
            receiver = conn.execute("SELECT id, username, avatar_url FROM users WHERE id=?", (t["receiver_id"],)).fetchone() if t["receiver_id"] else None
            out.append({**dict(t), "sender": dict(sender) if sender else None, "receiver": dict(receiver) if receiver else None})
        return out


@app.get(f"{BASE_PATH}/transactions/{{id}}")
def get_transaction(id: str, request: Request):
    mode = request.state.security_mode
    user = require_auth(request)
    with db_conn() as conn:
        tx = conn.execute("SELECT * FROM transactions WHERE id=?", (id,)).fetchone()
        if not tx:
            raise HTTPException(status_code=404, detail="Not found")
        if mode == "hardened" and user["id"] not in {tx["sender_id"], tx["receiver_id"]}:
            raise HTTPException(status_code=403, detail="Access denied")
        sender = conn.execute("SELECT id, username, avatar_url FROM users WHERE id=?", (tx["sender_id"],)).fetchone() if tx["sender_id"] else None
        receiver = conn.execute("SELECT id, username, avatar_url FROM users WHERE id=?", (tx["receiver_id"],)).fetchone() if tx["receiver_id"] else None
        return {**dict(tx), "sender": dict(sender) if sender else None, "receiver": dict(receiver) if receiver else None}


@app.post(f"{BASE_PATH}/transactions/transfer")
async def transfer(request: Request):
    mode = request.state.security_mode
    user = require_auth(request)
    body = await request.json()
    to_username = body.get("toUsername")
    raw_amount = body.get("amount")
    try:
        amount = float(raw_amount)
    except (TypeError, ValueError):
        raise HTTPException(status_code=400, detail="toUsername and amount are required")
    note = body.get("note")
    if not to_username:
        raise HTTPException(status_code=400, detail="toUsername and amount are required")

    with db_conn() as conn:
        receiver = conn.execute("SELECT * FROM users WHERE username=?", (to_username,)).fetchone()
        if not receiver:
            raise HTTPException(status_code=404, detail="Recipient not found")
        sender = conn.execute("SELECT * FROM users WHERE id=?", (user["id"],)).fetchone()
        if mode == "hardened":
            if amount <= 0:
                raise HTTPException(status_code=400, detail="Amount must be positive")
            if amount > 10000:
                raise HTTPException(status_code=400, detail="Transfer limit is $10,000")
            if receiver["id"] == sender["id"]:
                raise HTTPException(status_code=400, detail="Cannot transfer to yourself")
            if float(sender["balance"]) < amount:
                raise HTTPException(status_code=400, detail="Insufficient funds")

        conn.execute("UPDATE users SET balance = balance - ? WHERE id=?", (amount, sender["id"]))
        conn.execute("UPDATE users SET balance = balance + ? WHERE id=?", (amount, receiver["id"]))
        ref = f"TXN-{int(time.time() * 1000)}"
        cur = conn.execute(
            "INSERT INTO transactions (sender_id, receiver_id, amount, type, status, note, reference, created_at) VALUES (?, ?, ?, 'transfer', 'completed', ?, ?, ?)",
            (sender["id"], receiver["id"], amount, note, ref, now_iso()),
        )
        tx = conn.execute("SELECT * FROM transactions WHERE id=?", (cur.lastrowid,)).fetchone()
        sender_obj = conn.execute("SELECT id, username, avatar_url FROM users WHERE id=?", (sender["id"],)).fetchone()
        receiver_obj = conn.execute("SELECT id, username, avatar_url FROM users WHERE id=?", (receiver["id"],)).fetchone()
        return {**dict(tx), "sender": dict(sender_obj), "receiver": dict(receiver_obj)}


@app.get(f"{BASE_PATH}/cart")
def get_cart(request: Request):
    user = require_auth(request)
    with db_conn() as conn:
        rows = conn.execute(
            """
            SELECT ci.*, p.*
            FROM cart_items ci JOIN products p ON p.id = ci.product_id
            WHERE ci.user_id=?
            """,
            (user["id"],),
        ).fetchall()
        out = []
        for r in rows:
            product = {
                "id": r["product_id"],
                "name": r["name"],
                "price": r["price"],
                "original_price": r["original_price"],
                "image_url": r["image_url"],
                "stock": r["stock"],
                "category": r["category"],
                "brand": r["brand"],
            }
            out.append({"id": r["id"], "product_id": r["product_id"], "quantity": r["quantity"], "added_at": r["added_at"], "product": product})
        return out


@app.post(f"{BASE_PATH}/cart")
async def add_to_cart(request: Request):
    mode = request.state.security_mode
    user = require_auth(request)
    body = await request.json()
    product_id = body.get("productId")
    qty = int(body.get("quantity", 1))
    if not product_id:
        raise HTTPException(status_code=400, detail="productId required")
    if mode == "hardened" and (qty < 1 or qty > 100):
        raise HTTPException(status_code=400, detail="Quantity must be 1-100")
    with db_conn() as conn:
        existing = conn.execute("SELECT id, quantity FROM cart_items WHERE user_id=? AND product_id=?", (user["id"], product_id)).fetchone()
        if existing:
            conn.execute("UPDATE cart_items SET quantity = quantity + ? WHERE id=?", (qty, existing["id"]))
        else:
            conn.execute("INSERT INTO cart_items (user_id, product_id, quantity, added_at) VALUES (?, ?, ?, ?)", (user["id"], product_id, qty, now_iso()))
    return {"ok": True}


@app.delete(f"{BASE_PATH}/cart/{{productId}}")
def remove_from_cart(productId: str, request: Request):
    user = require_auth(request)
    with db_conn() as conn:
        conn.execute("DELETE FROM cart_items WHERE user_id=? AND product_id=?", (user["id"], productId))
    return {"ok": True}


def hydrate_order(conn: sqlite3.Connection, row: sqlite3.Row) -> dict[str, Any]:
    items = conn.execute("SELECT * FROM order_items WHERE order_id=?", (row["id"],)).fetchall()
    hydrated_items = []
    for i in items:
        p = conn.execute("SELECT * FROM products WHERE id=?", (i["product_id"],)).fetchone()
        hydrated_items.append({
            "id": i["id"],
            "product_id": i["product_id"],
            "quantity": i["quantity"],
            "price_at_purchase": i["price_at_purchase"],
            "product": product_with_seller(conn, p) if p else None,
        })
    return {**dict(row), "items": hydrated_items}


@app.get(f"{BASE_PATH}/orders")
def list_orders(request: Request):
    mode = request.state.security_mode
    user = require_auth(request)
    uid = user["id"]
    if mode == "vulnerable":
        uid = request.query_params.get("userId", uid)
    with db_conn() as conn:
        rows = conn.execute("SELECT * FROM orders WHERE buyer_id=? ORDER BY created_at DESC", (uid,)).fetchall()
        return [hydrate_order(conn, r) for r in rows]


@app.get(f"{BASE_PATH}/orders/{{id}}")
def get_order(id: str, request: Request):
    mode = request.state.security_mode
    user = require_auth(request)
    with db_conn() as conn:
        row = conn.execute("SELECT * FROM orders WHERE id=?", (id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Not found")
        if mode == "hardened" and int(row["buyer_id"]) != int(user["id"]):
            raise HTTPException(status_code=403, detail="Access denied")
        return hydrate_order(conn, row)


@app.post(f"{BASE_PATH}/orders")
async def checkout(request: Request):
    mode = request.state.security_mode
    user = require_auth(request)
    body = await request.json()
    with db_conn() as conn:
        cart = conn.execute(
            "SELECT ci.*, p.price, p.stock, p.name FROM cart_items ci JOIN products p ON p.id = ci.product_id WHERE ci.user_id=?",
            (user["id"],),
        ).fetchall()
        if not cart:
            raise HTTPException(status_code=400, detail="Cart is empty")
        total = 0.0
        for item in cart:
            if mode == "hardened" and int(item["stock"]) < int(item["quantity"]):
                raise HTTPException(status_code=400, detail=f"{item['name']} is out of stock")
            total += float(item["price"]) * int(item["quantity"])
        user_row = conn.execute("SELECT * FROM users WHERE id=?", (user["id"],)).fetchone()
        if mode == "hardened" and float(user_row["balance"]) < total:
            raise HTTPException(status_code=400, detail="Insufficient balance")
        conn.execute("UPDATE users SET balance = balance - ? WHERE id=?", (total, user["id"]))
        cur = conn.execute(
            "INSERT INTO orders (buyer_id, total, status, shipping_address, created_at) VALUES (?, ?, 'confirmed', ?, ?)",
            (user["id"], total, body.get("shippingAddress"), now_iso()),
        )
        order_id = cur.lastrowid
        for item in cart:
            conn.execute(
                "INSERT INTO order_items (order_id, product_id, quantity, price_at_purchase) VALUES (?, ?, ?, ?)",
                (order_id, item["product_id"], item["quantity"], item["price"]),
            )
            if mode == "hardened":
                conn.execute("UPDATE products SET stock = stock - ? WHERE id=?", (item["quantity"], item["product_id"]))
        conn.execute(
            "INSERT INTO transactions (sender_id, receiver_id, amount, type, status, note, reference, created_at) VALUES (?, NULL, ?, 'purchase', 'completed', ?, ?, ?)",
            (user["id"], total, f"Order #{order_id}", f"ORDER-{order_id}-{int(time.time())}", now_iso()),
        )
        conn.execute("DELETE FROM cart_items WHERE user_id=?", (user["id"],))
        order = conn.execute("SELECT * FROM orders WHERE id=?", (order_id,)).fetchone()
        return JSONResponse(status_code=201, content=hydrate_order(conn, order))


@app.get(f"{BASE_PATH}/feed")
def get_feed(request: Request, limit: int = 20, offset: int = 0):
    uid = request.state.user["id"] if request.state.user else None
    with db_conn() as conn:
        rows = conn.execute("SELECT * FROM posts ORDER BY created_at DESC LIMIT ? OFFSET ?", (min(limit, 100), max(offset, 0))).fetchall()
        out = []
        for p in rows:
            author = conn.execute("SELECT id, username, avatar_url, full_name FROM users WHERE id=?", (p["author_id"],)).fetchone()
            like_count = conn.execute("SELECT COUNT(*) AS c FROM post_likes WHERE post_id=?", (p["id"],)).fetchone()["c"]
            comment_count = conn.execute("SELECT COUNT(*) AS c FROM comments WHERE post_id=?", (p["id"],)).fetchone()["c"]
            liked_by_me = False
            if uid:
                liked_by_me = bool(conn.execute("SELECT 1 FROM post_likes WHERE post_id=? AND user_id=?", (p["id"], uid)).fetchone())
            out.append({**dict(p), "author": dict(author) if author else None, "like_count": like_count, "comment_count": comment_count, "liked_by_me": liked_by_me})
        return out


@app.post(f"{BASE_PATH}/posts")
async def create_post(request: Request):
    mode = request.state.security_mode
    user = require_auth(request)
    body = await request.json()
    content = body.get("content")
    if not content:
        raise HTTPException(status_code=400, detail="content required")
    if mode == "hardened":
        content = sanitize_text_hardened(content)
    with db_conn() as conn:
        cur = conn.execute(
            "INSERT INTO posts (author_id, content, image_url, created_at) VALUES (?, ?, ?, ?)",
            (user["id"], content, body.get("imageUrl"), now_iso()),
        )
        row = conn.execute("SELECT * FROM posts WHERE id=?", (cur.lastrowid,)).fetchone()
    return JSONResponse(status_code=201, content={**dict(row), "author": {"id": user["id"], "username": user["username"]}, "like_count": 0, "comment_count": 0, "liked_by_me": False})


@app.get(f"{BASE_PATH}/posts/{{id}}")
def get_post(id: str, request: Request):
    uid = request.state.user["id"] if request.state.user else None
    with db_conn() as conn:
        p = conn.execute("SELECT * FROM posts WHERE id=?", (id,)).fetchone()
        if not p:
            raise HTTPException(status_code=404, detail="Post not found")
        author = conn.execute("SELECT id, username, avatar_url FROM users WHERE id=?", (p["author_id"],)).fetchone()
        like_count = conn.execute("SELECT COUNT(*) AS c FROM post_likes WHERE post_id=?", (id,)).fetchone()["c"]
        comment_count = conn.execute("SELECT COUNT(*) AS c FROM comments WHERE post_id=?", (id,)).fetchone()["c"]
        liked_by_me = bool(uid and conn.execute("SELECT 1 FROM post_likes WHERE post_id=? AND user_id=?", (id, uid)).fetchone())
        return {**dict(p), "author": dict(author) if author else None, "like_count": like_count, "comment_count": comment_count, "liked_by_me": liked_by_me}


@app.delete(f"{BASE_PATH}/posts/{{id}}")
def delete_post(id: str, request: Request):
    mode = request.state.security_mode
    user = require_auth(request)
    with db_conn() as conn:
        p = conn.execute("SELECT * FROM posts WHERE id=?", (id,)).fetchone()
        if not p:
            raise HTTPException(status_code=404, detail="Not found")
        if mode == "hardened" and int(p["author_id"]) != int(user["id"]) and user["role"] not in ADMIN_ROLES:
            raise HTTPException(status_code=403, detail="Not authorized")
        conn.execute("DELETE FROM posts WHERE id=?", (id,))
        conn.execute("DELETE FROM post_likes WHERE post_id=?", (id,))
        conn.execute("DELETE FROM comments WHERE post_id=?", (id,))
    return {"ok": True}


@app.post(f"{BASE_PATH}/posts/{{id}}/like")
def like_post(id: str, request: Request):
    user = require_auth(request)
    with db_conn() as conn:
        exists = conn.execute("SELECT 1 FROM post_likes WHERE post_id=? AND user_id=?", (id, user["id"])).fetchone()
        if exists:
            conn.execute("DELETE FROM post_likes WHERE post_id=? AND user_id=?", (id, user["id"]))
            return {"ok": True, "liked": False}
        conn.execute("INSERT OR IGNORE INTO post_likes (post_id, user_id) VALUES (?, ?)", (id, user["id"]))
        return {"ok": True, "liked": True}


@app.get(f"{BASE_PATH}/posts/{{id}}/comments")
def get_comments(id: str):
    with db_conn() as conn:
        rows = conn.execute("SELECT * FROM comments WHERE post_id=? ORDER BY created_at ASC", (id,)).fetchall()
        out = []
        for c in rows:
            author = conn.execute("SELECT id, username, avatar_url FROM users WHERE id=?", (c["author_id"],)).fetchone()
            out.append({**dict(c), "author": dict(author) if author else None})
        return out


@app.post(f"{BASE_PATH}/posts/{{id}}/comments")
async def add_comment(id: str, request: Request):
    mode = request.state.security_mode
    user = require_auth(request)
    body = await request.json()
    content = body.get("content")
    if not content:
        raise HTTPException(status_code=400, detail="content required")
    if mode == "hardened":
        content = sanitize_text_hardened(content)
    with db_conn() as conn:
        cur = conn.execute(
            "INSERT INTO comments (post_id, author_id, content, created_at) VALUES (?, ?, ?, ?)",
            (id, user["id"], content, now_iso()),
        )
        row = conn.execute("SELECT * FROM comments WHERE id=?", (cur.lastrowid,)).fetchone()
        payload = {**dict(row), "author": {"id": user["id"], "username": user["username"]}}
        return JSONResponse(status_code=201, content=payload)


@app.get(f"{BASE_PATH}/admin/security-mode")
def get_security_mode(request: Request):
    require_auth(request)
    with db_conn() as conn:
        row = conn.execute("SELECT security_mode, app_name, allow_register, updated_at FROM app_settings WHERE id=1").fetchone()
        return {
            "mode": row["security_mode"],
            "security_mode": row["security_mode"],
            "app_name": row["app_name"],
            "allow_register": bool(row["allow_register"]),
            "updated_at": row["updated_at"],
        }


@app.post(f"{BASE_PATH}/admin/security-mode")
async def set_security_mode(request: Request):
    actor = require_admin(request)
    body = await request.json()
    mode = body.get("mode")
    if mode not in {"vulnerable", "hardened"}:
        raise HTTPException(status_code=400, detail="mode must be 'vulnerable' or 'hardened'")
    with db_conn() as conn:
        conn.execute("UPDATE app_settings SET security_mode=?, updated_at=?, updated_by=? WHERE id=1", (mode, now_iso(), actor["id"]))
    return {"ok": True, "message": f"Security mode set to: {mode}"}


@app.get(f"{BASE_PATH}/admin/users")
def admin_list_users(request: Request):
    require_admin(request)
    with db_conn() as conn:
        rows = conn.execute("SELECT * FROM users ORDER BY id").fetchall()
        return [row_to_user(r, include_sensitive=True) for r in rows]


@app.patch(f"{BASE_PATH}/admin/users/{{id}}/balance")
async def admin_update_balance(id: str, request: Request):
    require_admin(request)
    body = await request.json()
    raw_delta = body.get("delta")
    try:
        delta = float(raw_delta)
    except (TypeError, ValueError):
        raise HTTPException(status_code=400, detail="delta required")
    note = body.get("note") or "Admin balance adjustment"
    with db_conn() as conn:
        conn.execute("UPDATE users SET balance = balance + ? WHERE id=?", (delta, id))
        conn.execute(
            "INSERT INTO transactions (sender_id, receiver_id, amount, type, status, note, reference, created_at) VALUES (NULL, ?, ?, 'admin_adjustment', 'completed', ?, ?, ?)",
            (id, abs(delta), note, f"ADJ-{int(time.time())}", now_iso()),
        )
    return {"ok": True}


@app.patch(f"{BASE_PATH}/admin/users/{{id}}/role")
async def admin_update_role(id: str, request: Request):
    require_admin(request)
    body = await request.json()
    role = body.get("role")
    if role not in {"user", "seller", "moderator", "admin", "sudo"}:
        raise HTTPException(status_code=400, detail="Invalid role")
    with db_conn() as conn:
        conn.execute("UPDATE users SET role=? WHERE id=?", (role, id))
    return {"ok": True}


@app.delete(f"{BASE_PATH}/admin/users/{{id}}")
def admin_delete_user(id: str, request: Request):
    require_admin(request)
    with db_conn() as conn:
        conn.execute("DELETE FROM users WHERE id=?", (id,))
    return {"ok": True}


@app.post(f"{BASE_PATH}/admin/users/{{id}}/lock")
def admin_lock_user(id: str, request: Request):
    require_admin(request)
    with db_conn() as conn:
        conn.execute("UPDATE users SET is_locked=1 WHERE id=?", (id,))
    return {"ok": True}


@app.post(f"{BASE_PATH}/admin/users/{{id}}/unlock")
def admin_unlock_user(id: str, request: Request):
    require_admin(request)
    with db_conn() as conn:
        conn.execute("UPDATE users SET is_locked=0, failed_logins=0 WHERE id=?", (id,))
    return {"ok": True}


@app.get(f"{BASE_PATH}/admin/logs")
def get_request_logs(request: Request, limit: int = 100, offset: int = 0, type: Optional[str] = None):
    require_admin(request)
    q = "SELECT * FROM request_logs"
    args: list[Any] = []
    if type:
        q += " WHERE event_type=?"
        args.append(type)
    q += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
    args.extend([limit, offset])
    with db_conn() as conn:
        rows = conn.execute(q, args).fetchall()
        return [{**dict(r), "is_suspicious": bool(r["is_suspicious"])} for r in rows]


@app.get(f"{BASE_PATH}/admin/security-events")
def get_security_events(request: Request, limit: int = 100, offset: int = 0):
    require_admin(request)
    with db_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM request_logs WHERE is_suspicious=1 ORDER BY timestamp DESC LIMIT ? OFFSET ?",
            (limit, offset),
        ).fetchall()
        return [{**dict(r), "is_suspicious": bool(r["is_suspicious"])} for r in rows]


@app.get(f"{BASE_PATH}/debug/ping")
def debug_ping(request: Request, host: Optional[str] = None):
    mode = request.state.security_mode
    if not host:
        raise HTTPException(status_code=400, detail="host param required")
    if mode == "hardened" and not re.match(r"^[a-zA-Z0-9.\-]{1,253}$", host):
        raise HTTPException(status_code=400, detail="Invalid host")
    try:
        cmd = ["ping", "-c", "2", host]
        if mode == "vulnerable":
            # Intentionally vulnerable for training: command injection demo.
            proc = subprocess.run(" ".join(cmd), shell=True, capture_output=True, text=True, timeout=8)
        else:
            proc = subprocess.run(cmd, shell=False, capture_output=True, text=True, timeout=8)
        output = (proc.stdout + proc.stderr)[:6000]
        return {"output": output}
    except Exception as exc:
        return {"output": "", "error": str(exc)}


@app.get(f"{BASE_PATH}/debug/env")
def debug_env(request: Request):
    mode = request.state.security_mode
    if mode == "vulnerable":
        return {"output": json.dumps(dict(os.environ), indent=2)}
    safe = {"PORT": os.getenv("PORT"), "BASE_PATH": BASE_PATH, "PYTHON_BACKEND_DB": str(DB_PATH)}
    return {"output": json.dumps(safe, indent=2)}


@app.get(f"{BASE_PATH}/debug/version")
def debug_version(request: Request):
    mode = request.state.security_mode
    if mode == "vulnerable":
        pkg = Path(__file__).resolve().parent.parent / "package.json"
        if pkg.exists():
            return {"output": pkg.read_text()[:10000]}
    return {"output": "VulnLab Pro API Python backend v1.0.0"}


@app.post(f"{BASE_PATH}/debug/eval")
async def debug_eval(request: Request):
    mode = request.state.security_mode
    body = await request.json()
    code = str(body.get("code", ""))
    if mode == "hardened":
        raise HTTPException(status_code=403, detail="This endpoint is disabled in hardened mode.")
    try:
        # Intentionally vulnerable for training: RCE demo in vulnerable mode.
        result = str(eval(code))  # noqa: S307
        return {"output": result}
    except Exception as exc:
        return {"output": "", "error": str(exc)}


@app.post(f"{BASE_PATH}/webhooks/test")
async def test_webhook(request: Request):
    mode = request.state.security_mode
    body = await request.json()
    url = body.get("url")
    payload = body.get("payload", {})
    if not url:
        raise HTTPException(status_code=400, detail="url required")
    if mode == "hardened":
        u = str(url).lower()
        if not (u.startswith("http://") or u.startswith("https://")):
            raise HTTPException(status_code=400, detail="Internal URLs not allowed")
        for b in ["localhost", "127.0.0.1", "169.254.", "10.", "192.168.", "172."]:
            if b in u:
                raise HTTPException(status_code=400, detail="Internal URLs not allowed")
    try:
        # Intentionally vulnerable for training when mode == vulnerable: SSRF demo.
        r = requests.post(url, json=payload, timeout=5)
        return {"ok": True, "message": f"Webhook sent. Status: {r.status_code}"}
    except Exception as exc:
        return {"ok": False, "message": str(exc)}


@app.get(f"{BASE_PATH}/redirect")
def open_redirect(request: Request, url: Optional[str] = None):
    if not url:
        raise HTTPException(status_code=400, detail="url required")
    if request.state.security_mode == "hardened" and not (url.startswith("/") and not url.startswith("//")):
        raise HTTPException(status_code=400, detail="Only relative redirects are allowed")
    # Intentionally vulnerable for training when mode == vulnerable: open redirect demo.
    return RedirectResponse(url)


@app.get(f"{BASE_PATH}/files/download")
def download_file(request: Request, name: Optional[str] = None):
    if not name:
        raise HTTPException(status_code=400, detail="name required")
    uploads_dir = (Path(__file__).resolve().parent / "uploads").resolve()
    uploads_dir.mkdir(exist_ok=True)

    if request.state.security_mode == "vulnerable":
        # Intentionally vulnerable for training: path traversal demo.
        # This is deliberately weak and bypassable via encoded traversal (`..%2f`),
        # double-encoding, absolute paths, and separator tricks.
        try_paths = [uploads_dir / name, Path("/") / name.replace("../", "")]
        for p in try_paths:
            if p.exists() and p.is_file():
                return {"content": p.read_text()[:10000]}
        raise HTTPException(status_code=404, detail="File not found")

    safe_path = (uploads_dir / name).resolve()
    if not str(safe_path).startswith(str(uploads_dir)):
        raise HTTPException(status_code=400, detail="Path traversal detected")
    if not safe_path.exists() or not safe_path.is_file():
        raise HTTPException(status_code=404, detail="File not found")
    return {"content": safe_path.read_text()[:10000]}


@sio.event
async def connect(sid, environ, auth):
    qs = environ.get("QUERY_STRING", "")
    params = {k: v for k, _, v in (part.partition("=") for part in qs.split("&") if part)}
    channel_id = params.get("channelId")
    if channel_id:
        await sio.enter_room(sid, f"channel:{channel_id}")


@sio.on("join_channel")
async def join_channel_socket(sid, channel_id):
    await sio.enter_room(sid, f"channel:{channel_id}")


@sio.on("leave_channel")
async def leave_channel_socket(sid, channel_id):
    await sio.leave_room(sid, f"channel:{channel_id}")


@sio.on("send_message")
async def send_message_socket(sid, data):
    payload = {
        "id": int(time.time() * 1000),
        "channel_id": int(data.get("channelId", 0)),
        "sender_id": data.get("senderId"),
        "sender": data.get("sender"),
        "content": data.get("content"),
        "is_deleted": False,
        "is_pinned": False,
        "created_at": now_iso(),
    }
    await sio.emit("new_message", payload, room=f"channel:{data.get('channelId')}")


@sio.on("typing")
async def typing_socket(sid, data):
    await sio.emit("user_typing", {"username": data.get("username")}, room=f"channel:{data.get('channelId')}", skip_sid=sid)


asgi_app = socketio.ASGIApp(sio, other_asgi_app=app, socketio_path="api/socket.io")
