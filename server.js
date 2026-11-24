const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const WebSocket = require("ws");

const PORT = Number(process.env.PORT || 3000);
const HOST = process.env.HOST || "0.0.0.0";
const accounts = JSON.parse(fs.readFileSync(path.join(__dirname, "accounts.json"), "utf8"));
const sessions = new Map();
const clients = new Map();
const world = { width: 2200, height: 1500 };
const publicDir = path.join(__dirname, "public");

function safeEqual(a, b) {
  const aa = Buffer.from(a);
  const bb = Buffer.from(b);
  return aa.length === bb.length && crypto.timingSafeEqual(aa, bb);
}
function verifyPassword(username, password) {
  const rec = accounts[username];
  if (!rec || typeof password !== "string" || password.length > 200) return false;
  const salt = Buffer.from(rec.salt, "base64");
  const expected = Buffer.from(rec.hash, "base64");
  const actual = crypto.scryptSync(password, salt, expected.length, { N: 2**14, r: 8, p: 1 });
  return safeEqual(actual, expected);
}
function sendJson(res, status, data) {
  res.writeHead(status, { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" });
  res.end(JSON.stringify(data));
}
const server = http.createServer((req, res) => {
  if (req.method === "POST" && req.url === "/api/login") {
    let body = "";
    req.on("data", chunk => { body += chunk; if (body.length > 5000) req.destroy(); });
    req.on("end", () => {
      try {
        const { username, password } = JSON.parse(body || "{}");
        const user = String(username || "").trim().toLowerCase();
        if (!verifyPassword(user, password)) return sendJson(res, 401, { error: "Identifiant ou mot de passe incorrect." });
        const token = crypto.randomBytes(32).toString("hex");
        sessions.set(token, { username: user, expires: Date.now() + 12 * 60 * 60 * 1000 });
        sendJson(res, 200, { token, username: user });
      } catch { sendJson(res, 400, { error: "Requête invalide." }); }
    });
    return;
  }
  if (req.method === "GET" && req.url === "/api/status") {
    return sendJson(res, 200, { private: true, accounts: Object.keys(accounts).length });
  }
  let pathname = decodeURIComponent((req.url || "/").split("?")[0]);
  if (pathname === "/") pathname = "/index.html";
  const file = path.normalize(path.join(publicDir, pathname));
  if (!file.startsWith(publicDir)) { res.writeHead(403); return res.end("Forbidden"); }
  fs.readFile(file, (err, data) => {
    if (err) { res.writeHead(404); return res.end("Not found"); }
    const ext = path.extname(file);
    const types = { ".html":"text/html; charset=utf-8", ".css":"text/css; charset=utf-8", ".js":"text/javascript; charset=utf-8" };
    res.writeHead(200, { "Content-Type": types[ext] || "application/octet-stream", "X-Content-Type-Options":"nosniff", "Referrer-Policy":"no-referrer" });
    res.end(data);
  });
});
const wss = new WebSocket.Server({ noServer: true });
server.on("upgrade", (req, socket, head) => {
  const url = new URL(req.url, "http://localhost");
  if (url.pathname !== "/world") return socket.destroy();
  const token = url.searchParams.get("token");
  const session = sessions.get(token);
  if (!session || session.expires < Date.now()) return socket.destroy();
  wss.handleUpgrade(req, socket, head, ws => {
    ws.username = session.username;
    wss.emit("connection", ws);
  });
});
function snapshot() {
  return [...clients.entries()].map(([name, p]) => ({ username: name, x: p.x, y: p.y, direction: p.direction }));
}
function broadcast(data) {
  const msg = JSON.stringify(data);
  for (const ws of wss.clients) if (ws.readyState === WebSocket.OPEN) ws.send(msg);
}
wss.on("connection", (ws) => {
  const name = ws.username;
  const old = clients.get(name);
  if (old && old.ws && old.ws.readyState === WebSocket.OPEN) old.ws.close(4001, "Nouvelle connexion");
  const player = { x: 280 + Math.random()*100, y: 260 + Math.random()*100, direction: "down", ws };
  clients.set(name, player);
  ws.send(JSON.stringify({ type: "welcome", username: name, world, players: snapshot() }));
  broadcast({ type: "players", players: snapshot() });
  ws.on("message", raw => {
    if (raw.length > 2000) return;
    let data;
    try { data = JSON.parse(raw.toString()); } catch { return; }
    if (data.type === "move") {
      const x = Number(data.x), y = Number(data.y);
      if (!Number.isFinite(x) || !Number.isFinite(y)) return;
      player.x = Math.max(24, Math.min(world.width - 24, x));
      player.y = Math.max(24, Math.min(world.height - 24, y));
      player.direction = ["up","down","left","right"].includes(data.direction) ? data.direction : "down";
      broadcast({ type: "players", players: snapshot() });
    } else if (data.type === "chat") {
      const message = String(data.message || "").trim().slice(0, 180);
      if (message) broadcast({ type: "chat", username: name, message, time: new Date().toISOString() });
    }
  });
  ws.on("close", () => {
    if (clients.get(name)?.ws === ws) {
      clients.delete(name);
      broadcast({ type: "players", players: snapshot() });
    }
  });
});
setInterval(() => {
  const now = Date.now();
  for (const [token, s] of sessions) if (s.expires < now) sessions.delete(token);
}, 60000).unref();
server.listen(PORT, HOST, () => console.log(`Monde privé lancé : http://localhost:${PORT}`));
