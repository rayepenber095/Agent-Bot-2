# Python Backend

This directory contains a Python FastAPI + Socket.IO implementation of the `/api` backend.

## Run

```bash
cd <project-root>
python3 -m venv .venv
source .venv/bin/activate
pip install -r python-backend/requirements.txt
PORT=8080 BASE_PATH=/api uvicorn python-backend.main:asgi_app --host 0.0.0.0 --port 8080
```

The backend stores data in:

- `<project-root>/python-backend/vulnlab.db`

## Notes

- Demo users and starter data are seeded on first startup.
- Security mode toggle works via `/api/admin/security-mode`.
- Socket.IO endpoint is mounted at `/api/socket.io`.
