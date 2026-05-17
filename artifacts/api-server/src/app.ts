import express from "express";
import cors from "cors";
import { createServer } from "http";
import { Server as SocketIO } from "socket.io";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import { attachSecurityMode } from "./middleware/auth.js";
import { requestLogger } from "./middleware/requestLogger.js";
import authRouter from "./routes/auth.js";
import usersRouter from "./routes/users.js";
import productsRouter from "./routes/products.js";
import channelsRouter from "./routes/channels.js";
import messagesRouter from "./routes/messages.js";
import transactionsRouter from "./routes/transactions.js";
import socialRouter from "./routes/social.js";
import cartRouter from "./routes/cart.js";
import adminRouter from "./routes/admin.js";
import debugRouter from "./routes/debug.js";
import { getSecurityMode } from "./lib/security.js";
import { pool } from "./lib/db.js";

const app = express();
const httpServer = createServer(app);

app.use(
  cors({
    origin: true,
    credentials: true,
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization", "X-Admin-Override", "X-Requested-With"],
  })
);

app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true }));

// Security headers — strict only in hardened mode
app.use(async (req, res, next) => {
  const mode = await getSecurityMode();
  if (mode === "hardened") {
    helmet({
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          scriptSrc: ["'self'"],
          styleSrc: ["'self'", "'unsafe-inline'"],
          imgSrc: ["'self'", "data:", "https:", "http:"],
        },
      },
    })(req, res, next);
  } else {
    res.setHeader("X-Security-Mode", "vulnerable");
    next();
  }
});

// Rate limiting — only in hardened mode
app.use(async (req, res, next) => {
  const mode = await getSecurityMode();
  if (mode === "hardened") {
    return rateLimit({
      windowMs: 15 * 60 * 1000,
      max: 300,
      standardHeaders: true,
      legacyHeaders: false,
      message: { error: "Too many requests" },
    })(req, res, next);
  }
  next();
});

// Security mode + request logger
app.use(attachSecurityMode);
app.use(requestLogger);

const BASE = (process.env.BASE_PATH ?? "/api").replace(/\/$/, "");

// Health
app.get(`${BASE}/healthz`, (req, res) => {
  res.json({ status: "ok", mode: req.securityMode, timestamp: new Date().toISOString() });
});

// Auth
app.use(`${BASE}/auth`, authRouter);

// Users
app.use(`${BASE}/users`, usersRouter);

// Products
app.use(`${BASE}/products`, productsRouter);

// Channels + channel messages
app.use(`${BASE}/channels`, channelsRouter);

// Message search & DMs
app.use(`${BASE}/messages`, messagesRouter);
app.use(`${BASE}/dm`, (req, res, next) => {
  req.url = `/dm${req.url}`;
  messagesRouter(req, res, next);
});

// Transactions
app.use(`${BASE}/transactions`, transactionsRouter);

// Social feed & posts
app.use(`${BASE}/feed`, (req, res, next) => {
  req.url = `/feed${req.url === "/" ? "" : req.url}`;
  socialRouter(req, res, next);
});
app.use(`${BASE}/posts`, (req, res, next) => {
  req.url = `/posts${req.url}`;
  socialRouter(req, res, next);
});

// Cart & orders
app.use(`${BASE}/cart`, cartRouter);
app.use(`${BASE}/orders`, (req, res, next) => {
  req.url = `/orders${req.url}`;
  cartRouter(req, res, next);
});

// Admin
app.use(`${BASE}/admin`, adminRouter);

// Debug / vuln-only endpoints
app.use(`${BASE}/debug`, debugRouter);
app.get(`${BASE}/redirect`, (req, res, next) => {
  req.url = `/redirect`;
  debugRouter(req, res, next);
});
app.use(`${BASE}/files`, (req, res, next) => {
  req.url = `/files${req.url}`;
  debugRouter(req, res, next);
});
app.post(`${BASE}/webhooks/test`, (req, res, next) => {
  req.url = `/webhooks/test`;
  debugRouter(req, res, next);
});

// 404
app.use((req, res) => {
  res.status(404).json({ error: `Route not found: ${req.method} ${req.path}` });
});

// Error handler
app.use((err: Error, req: express.Request, res: express.Response, _next: express.NextFunction) => {
  const mode = req.securityMode ?? "vulnerable";
  if (mode === "vulnerable") {
    res.status(500).json({ error: err.message, stack: err.stack });
  } else {
    res.status(500).json({ error: "Internal server error" });
  }
});

// Socket.io for real-time chat
const io = new SocketIO(httpServer, {
  cors: { origin: true, credentials: true },
  path: `${BASE}/socket.io`,
});

io.on("connection", (socket) => {
  const { channelId } = socket.handshake.query as Record<string, string>;
  if (channelId) socket.join(`channel:${channelId}`);

  socket.on("join_channel", (cId: string) => socket.join(`channel:${cId}`));
  socket.on("leave_channel", (cId: string) => socket.leave(`channel:${cId}`));

  socket.on("send_message", (data: { channelId: string; content: string; senderId: number; sender: object }) => {
    io.to(`channel:${data.channelId}`).emit("new_message", {
      id: Date.now(),
      channel_id: parseInt(data.channelId, 10),
      sender_id: data.senderId,
      sender: data.sender,
      content: data.content,
      is_deleted: false,
      is_pinned: false,
      created_at: new Date().toISOString(),
    });
  });

  socket.on("typing", (data: { channelId: string; username: string }) => {
    socket.to(`channel:${data.channelId}`).emit("user_typing", { username: data.username });
  });
});

export { io, httpServer };

pool.query("SELECT 1")
  .then(() => console.log("DB connected"))
  .catch((e: Error) => console.error("DB connection error:", e.message));

export default app;
