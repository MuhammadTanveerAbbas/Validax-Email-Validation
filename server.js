#!/usr/bin/env node
/**
 * Validax server
 *
 * What it does:
 *   - Serves the static site with strict security headers and a tight CSP.
 *   - Proxies POST /api/verify  -> emailvalidation.io (keeps the key server-side).
 *   - Exposes GET /api/health for simple uptime checks.
 *   - Blocks .env, server.js, and package.json from static serving.
 *
 * What it does NOT do:
 *   - No database, no sessions, no accounts. State is only in-memory rate limits.
 *   - It is not a full WAF. Put a reverse proxy (Caddy, nginx, Cloudflare) in
 *     front for TLS, global DDoS protection and persistent limits.
 */

"use strict";

const http = require("node:http");
const fs = require("node:fs/promises");
const path = require("node:path");
const crypto = require("node:crypto");
const { URL } = require("node:url");

const ROOT = __dirname;

// Load .env before reading configuration. Existing process env wins.
loadEnvFile(path.join(ROOT, ".env"));

function loadEnvFile(filePath) {
  let text;
  try {
    text = require("node:fs").readFileSync(filePath, "utf8");
  } catch (error) {
    return;
  }
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) continue;
    const eq = line.indexOf("=");
    if (eq <= 0) continue;
    const key = line.slice(0, eq).trim();
    if (!/^[A-Z0-9_]+$/i.test(key) || process.env[key] != null) continue;
    let value = line.slice(eq + 1).trim();
    if (
      (value.startsWith('"') && value.endsWith('"')) ||
      (value.startsWith("'") && value.endsWith("'"))
    ) {
      value = value.slice(1, -1);
    }
    process.env[key] = value;
  }
}

const PORT = toInt(process.env.PORT, 3000);
const EMAIL_KEY = clean(process.env.EMAIL_VALIDATION_API_KEY);
const DEEP_DAILY_CAP = toInt(process.env.DEEP_DAILY_CAP, 80);
const TRUST_PROXY = isOn(process.env.TRUST_PROXY);
const FORCE_HSTS = isOn(process.env.FORCE_HSTS);
const EMAIL_API = "https://api.emailvalidation.io/v1/info";

const BODY_LIMIT = 16 * 1024;
const UPSTREAM_TIMEOUT = 12000;
const REQUEST_TIMEOUT = 20000;

const ALLOWED_SERVICES = new Set(["website", "ecommerce", "portfolio", "blog", "custom"]);
const EMAIL_RE =
  /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$/;

const RATE_RULES = {
  verify: {
    perIpMinute: { max: 3, windowMs: 60 * 1000 },
    perIpHour: { max: 15, windowMs: 60 * 60 * 1000 },
    globalDay: { max: DEEP_DAILY_CAP, windowMs: 24 * 60 * 60 * 1000 }
  }
};

const MIME = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".webp": "image/webp",
  ".jpg": "image/jpeg",
  ".jpeg": "image/jpeg",
  ".png": "image/png",
  ".svg": "image/svg+xml",
  ".ico": "image/x-icon",
  ".txt": "text/plain; charset=utf-8",
  ".md": "text/plain; charset=utf-8"
};

const hits = new Map();

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

function clean(value) {
  return typeof value === "string" ? value.trim() : "";
}

function toInt(value, fallback) {
  const num = Number.parseInt(String(value == null ? "" : value), 10);
  return Number.isFinite(num) && num >= 0 ? num : fallback;
}

function isOn(value) {
  return /^(1|true|yes|on)$/i.test(clean(value));
}

function isEmail(value) {
  const email = clean(value).toLowerCase();
  return email.length >= 3 && email.length <= 254 && EMAIL_RE.test(email) ? email : null;
}

function clientIp(req) {
  if (TRUST_PROXY) {
    const forwarded = clean(req.headers["x-forwarded-for"]);
    if (forwarded) return forwarded.split(",")[0].trim().slice(0, 80);
  }
  const remote = req.socket && req.socket.remoteAddress ? req.socket.remoteAddress : "unknown";
  return remote.replace(/^::ffff:/, "");
}

function isSecureRequest(req) {
  if (req.socket && req.socket.encrypted) return true;
  if (!TRUST_PROXY) return false;
  const proto = clean(req.headers["x-forwarded-proto"]).toLowerCase();
  return proto === "https";
}

function sweep(now) {
  if (hits.size < 5000) return;
  for (const [key, state] of hits.entries()) {
    if (state.resetAt <= now) hits.delete(key);
  }
}

function consume(rule, key) {
  const now = Date.now();
  sweep(now);
  let state = hits.get(key);
  if (!state || state.resetAt <= now) {
    state = { count: 0, resetAt: now + rule.windowMs };
  }
  if (state.count >= rule.max) {
    hits.set(key, state);
    return { ok: false, retryAfter: Math.max(1, Math.ceil((state.resetAt - now) / 1000)) };
  }
  state.count += 1;
  hits.set(key, state);
  return { ok: true, remaining: rule.max - state.count };
}

function checkRules(group, ip) {
  const rules = RATE_RULES[group];
  if (!rules) return { ok: true };
  for (const [name, rule] of Object.entries(rules)) {
    const key = name === "globalDay" ? `${group}:${name}` : `${group}:${name}:${ip}`;
    const result = consume(rule, key);
    if (!result.ok) return { ok: false, retryAfter: result.retryAfter, scope: name };
  }
  return { ok: true };
}

function isSameOrigin(req) {
  // A strict same-origin check. For local files or unusual clients the Origin
  // header may be absent; POST endpoints still require JSON and are rate limited.
  const origin = clean(req.headers.origin);
  if (!origin) return true;
  const host = clean(req.headers.host);
  if (!host) return false;
  try {
    const parsed = new URL(origin);
    return parsed.host === host;
  } catch (error) {
    return false;
  }
}

// ---------------------------------------------------------------------------
// Security headers
// ---------------------------------------------------------------------------

function securityHeaders(req) {
  // 'unsafe-inline' in style-src is required by the small inline style blocks in
  // the pages and the CSP meta fallback in static hosting. Scripts stay strict.
  const csp = [
    "default-src 'self'",
    "base-uri 'none'",
    "object-src 'none'",
    "frame-ancestors 'none'",
    "form-action 'self'",
    "img-src 'self' data:",
    "script-src 'self'",
    "style-src 'self' 'unsafe-inline'",
    "connect-src 'self' https://dns.google https://cloudflare-dns.com https://disify.com https://api.usercheck.com https://api.mailcheck.ai https://open.kickbox.com",
    "upgrade-insecure-requests"
  ].join("; ");

  const headers = {
    "Content-Security-Policy": csp,
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "X-Frame-Options": "DENY"
  };

  if (FORCE_HSTS && isSecureRequest(req)) {
    headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains";
  }
  return headers;
}

function json(res, req, status, body, extra) {
  const payload = Buffer.from(JSON.stringify(body));
  res.writeHead(status, {
    ...securityHeaders(req),
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
    "Content-Length": String(payload.length),
    ...(extra || {})
  });
  res.end(payload);
}

function reject(res, req, status, message, extra) {
  json(res, req, status, { ok: false, error: message }, extra);
}

// ---------------------------------------------------------------------------
// Body parsing
// ---------------------------------------------------------------------------

async function readBody(req) {
  const length = Number.parseInt(clean(req.headers["content-length"]), 10);
  if (Number.isFinite(length) && length > BODY_LIMIT) {
    const error = new Error("Request body is too large.");
    error.status = 413;
    throw error;
  }

  const type = clean(req.headers["content-type"]).split(";")[0].toLowerCase();
  if (type !== "application/json") {
    const error = new Error("Use application/json.");
    error.status = 415;
    throw error;
  }

  const chunks = [];
  let total = 0;
  for await (const chunk of req) {
    total += chunk.length;
    if (total > BODY_LIMIT) {
      const error = new Error("Request body is too large.");
      error.status = 413;
      throw error;
    }
    chunks.push(chunk);
  }

  try {
    return JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}");
  } catch (error) {
    const bad = new Error("Invalid JSON body.");
    bad.status = 400;
    throw bad;
  }
}

// ---------------------------------------------------------------------------
// API handlers
// ---------------------------------------------------------------------------

async function handleVerify(req, res) {
  if (req.method !== "POST") return reject(res, req, 405, "Method not allowed.", { Allow: "POST" });
  if (!isSameOrigin(req)) return reject(res, req, 403, "Cross-origin requests are not allowed.");

  const ip = clientIp(req);
  const limited = checkRules("verify", ip);
  if (!limited.ok) {
    return reject(res, req, 429, "Too many deep checks. Try again later.", {
      "Retry-After": String(limited.retryAfter)
    });
  }

  if (!EMAIL_KEY) {
    return reject(res, req, 503, "Deep mailbox check is not configured on this server.");
  }

  const body = await readBody(req);
  const email = isEmail(body.email);
  if (!email) return reject(res, req, 400, "A valid email address is required.");

  const upstream = new URL(EMAIL_API);
  upstream.searchParams.set("apikey", EMAIL_KEY);
  upstream.searchParams.set("email", email);

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), UPSTREAM_TIMEOUT);
  try {
    const response = await fetch(upstream, {
      method: "GET",
      headers: { accept: "application/json" },
      signal: controller.signal
    });
    const data = await response.json().catch(() => ({}));

    if (!response.ok) {
      const status = response.status === 429 ? 429 : 502;
      return reject(res, req, status, "The mailbox service could not complete the check.");
    }

    // Return only the fields the client uses. Never echo the key or raw headers.
    json(res, req, 200, {
      ok: true,
      state: clean(data.state) || "unknown",
      smtp_check: data.smtp_check === true,
      format_valid: data.format_valid === true,
      mx_found: data.mx_found === true,
      catch_all: data.catch_all === true,
      disposable: data.disposable === true,
      role: data.role === true,
      score: typeof data.score === "number" ? data.score : null,
      reason: clean(data.reason) || null,
      sub_status: clean(data.sub_status) || null,
      explanation: clean(data.explanation) || null,
      did_you_mean: clean(data.did_you_mean) || null
    });
  } catch (error) {
    reject(res, req, 502, "The mailbox service timed out or is unavailable.");
  } finally {
    clearTimeout(timer);
  }
}

async function handleContact(req, res) {
  if (req.method !== "POST") return reject(res, req, 405, "Method not allowed.", { Allow: "POST" });
  if (!isSameOrigin(req)) return reject(res, req, 403, "Cross-origin requests are not allowed.");

  const ip = clientIp(req);
  const limited = checkRules("contact", ip);
  if (!limited.ok) {
    return reject(res, req, 429, "Too many messages. Try again later.", {
      "Retry-After": String(limited.retryAfter)
    });
  }

  if (!WEB3_KEY) {
    return reject(res, req, 503, "Contact delivery is not configured on this server.");
  }

  const body = await readBody(req);

  // Honeypot: bots that fill it get a silent "success".
  if (clean(body.website) || clean(body.botcheck)) {
    return json(res, req, 200, { ok: true, accepted: true });
  }

  const name = clean(body.name).slice(0, 80);
  const email = isEmail(body.email);
  const service = ALLOWED_SERVICES.has(clean(body.service).toLowerCase())
    ? clean(body.service).toLowerCase()
    : "website";
  const message = clean(body.message).slice(0, 2000);

  if (name.length < 2) return reject(res, req, 400, "A name is required.");
  if (!email) return reject(res, req, 400, "A valid email address is required.");
  if (message.length < 10) return reject(res, req, 400, "The message is too short.");

  const payload = {
    access_key: WEB3_KEY,
    from_name: "Validax contact form",
    subject: `Validax contact: ${service}`,
    name,
    email,
    replyto: email,
    service,
    message
  };

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), UPSTREAM_TIMEOUT);
  try {
    const response = await fetch(WEB3_API, {
      method: "POST",
      headers: { "content-type": "application/json", accept: "application/json" },
      body: JSON.stringify(payload),
      signal: controller.signal
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok || data.success === false) {
      return reject(res, req, 502, "The message could not be delivered.");
    }
    json(res, req, 200, { ok: true, delivered: true });
  } catch (error) {
    reject(res, req, 502, "The message service timed out or is unavailable.");
  } finally {
    clearTimeout(timer);
  }
}

function handleHealth(req, res) {
  if (req.method !== "GET") return reject(res, req, 405, "Method not allowed.", { Allow: "GET" });
  json(res, req, 200, {
    ok: true,
    service: "validax",
    deepCheckConfigured: Boolean(EMAIL_KEY),
    contactConfigured: Boolean(WEB3_KEY),
    deepDailyCap: DEEP_DAILY_CAP
  });
}

// ---------------------------------------------------------------------------
// Static file serving
// ---------------------------------------------------------------------------

function safeFilePath(urlPath) {
  let decoded;
  try {
    decoded = decodeURIComponent(urlPath);
  } catch (error) {
    return null;
  }
  if (decoded.includes("\0")) return null;

  let relative = decoded === "/" ? "/index.html" : decoded;
  // Hide sensitive/server files even if someone asks for them.
  const blocked = /(^|\/)(\.env|\.git|server\.js|package\.json|package-lock\.json|node_modules)(\/|$)/i;
  if (blocked.test(relative)) return null;

  const filePath = path.resolve(ROOT, "." + relative);
  const rootPrefix = ROOT.endsWith(path.sep) ? ROOT : ROOT + path.sep;
  if (filePath !== ROOT && !filePath.startsWith(rootPrefix)) return null;
  return filePath;
}

async function serveStatic(req, res, urlPath) {
  if (req.method !== "GET" && req.method !== "HEAD") {
    return reject(res, req, 405, "Method not allowed.", { Allow: "GET, HEAD" });
  }

  const filePath = safeFilePath(urlPath);
  if (!filePath) return reject(res, req, 404, "Not found.");

  let stat;
  try {
    stat = await fs.stat(filePath);
    if (stat.isDirectory()) {
      return serveStatic(req, res, path.posix.join(urlPath.replace(/\/$/, ""), "index.html"));
    }
  } catch (error) {
    if (urlPath === "/") return serveStatic(req, res, "/index.html");
    return reject(res, req, 404, "Not found.");
  }

  const ext = path.extname(filePath).toLowerCase();
  const type = MIME[ext] || "application/octet-stream";
  const isHtml = ext === ".html";

  const body = req.method === "HEAD" ? null : await fs.readFile(filePath);
  res.writeHead(200, {
    ...securityHeaders(req),
    "Content-Type": type,
    "Content-Length": String(stat.size),
    "Cache-Control": isHtml ? "no-cache" : "public, max-age=3600",
    "X-Content-Type-Options": "nosniff"
  });
  if (body) res.end(body);
  else res.end();
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

const server = http.createServer(async (req, res) => {
  req.setTimeout(REQUEST_TIMEOUT, () => {
    try {
      req.destroy();
    } catch (error) {
      /* ignore */
    }
  });

  const url = new URL(req.url || "/", `http://${req.headers.host || "localhost"}`);
  const pathname = url.pathname;

  try {
    if (pathname === "/api/verify") return await handleVerify(req, res);
    if (pathname === "/api/health") return handleHealth(req, res);
    if (pathname.startsWith("/api/")) return reject(res, req, 404, "Not found.");
    return await serveStatic(req, res, pathname);
  } catch (error) {
    const status = error && error.status ? error.status : 500;
    if (status >= 500) {
      // Keep internals out of the response.
      console.error(`[${new Date().toISOString()}] ${req.method} ${pathname} -> ${status}`, error.message);
    }
    reject(res, req, status, status >= 500 ? "Internal server error." : error.message);
  }
});

if (require.main === module) {
  server.listen(PORT, () => {
    console.log(`Validax listening on http://localhost:${PORT}`);
    console.log(`Deep check configured: ${EMAIL_KEY ? "yes" : "no"} (daily cap ${DEEP_DAILY_CAP})`);
  });
}

module.exports = { server, securityHeaders, safeFilePath, checkRules, consume, isEmail };
