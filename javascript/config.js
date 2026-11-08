/**
 * Public configuration for Validax email validation.
 *
 * This file holds the public API endpoints and client-side limits.
 * No secrets: the emailvalidation.io key lives server-side and /api/verify
 * is the proxy. DNS-over-HTTPS and reputation calls (Disify, UserCheck, etc.)
 * are direct-to-provider from the browser; they need no key and CORS allows it.
 *
 * See README.md for API descriptions and rate limits.
 */

const CONFIG = {
  // Same-origin API paths (proxied by server.js)
  API_PATHS: {
    verify: "/api/verify",
    health: "/api/health",
  },

  // DNS over HTTPS resolvers used for MX lookups. No key, CORS enabled.
  DNS_RESOLVERS: [
    { name: "Google DNS", url: "https://dns.google/resolve" },
    { name: "Cloudflare DNS", url: "https://cloudflare-dns.com/dns-query" }
  ],

  // Free reputation/enrichment APIs. No key, CORS enabled.
  LOOKUP_APIS: {
    disify: "https://disify.com/api/email/",
    usercheck: "https://api.usercheck.com/email/",
    mailcheck: "https://api.mailcheck.ai/email/"
  },

  // Client-side courtesy guards. The server enforces the real limits.
  RATE_LIMITS: {
    free: { max: 20, windowMs: 60 * 1000 },
    freeDaily: { max: 300, windowMs: 24 * 60 * 60 * 1000 },
    deep: { max: 3, windowMs: 60 * 1000 }
  },

  CACHE_TTL_MS: 24 * 60 * 60 * 1000,
  REQUEST_TIMEOUT_MS: 9000
};

// Classic scripts do not expose top-level const bindings on window, so publish
// the frozen config explicitly for the other modules.
window.CONFIG = CONFIG;
