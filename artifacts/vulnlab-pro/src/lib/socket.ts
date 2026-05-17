import { io, type Socket } from "socket.io-client";

const BASE_URL = import.meta.env.BASE_URL?.replace(/\/$/, "") ?? "";

let socket: Socket | null = null;

export function getSocket(): Socket {
  if (!socket) {
    socket = io(window.location.origin, {
      path: `${BASE_URL}/api/socket.io`,
      autoConnect: false,
      transports: ["websocket", "polling"],
    });
  }
  return socket;
}

export function connectSocket(token?: string) {
  const s = getSocket();
  if (token) {
    s.auth = { token };
  }
  if (!s.connected) s.connect();
  return s;
}

export function disconnectSocket() {
  socket?.disconnect();
  socket = null;
}
