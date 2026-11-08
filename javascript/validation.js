/**
 * Validax validation engine.
 *
 * Layers, fastest first:
 *   1. Local syntax, length, role, disposable list and typo detection (instant).
 *   2. MX lookup over DNS-over-HTTPS (Google, then Cloudflare). No key.
 *   3. Reputation enrichment via disify.com. No key.
 *   4. Optional deep mailbox probe via emailvalidation.io (uses credits).
 *
 * Rules around the network: every request has a timeout, all remote data is
 * treated as untrusted text, and results are cached for a day so repeated
 * checks cost nothing. Client side rate limits are courtesy guards only; they
 * do not replace limits on a server.
 */
(function (global) {
  "use strict";

  const CONFIG = global.CONFIG || {};
  const TIMEOUT = CONFIG.REQUEST_TIMEOUT_MS || 9000;
  const CACHE_KEY = "validax:cache:v1";
  const CACHE_MAX = 60;
  const RATE_PREFIX = "validax:rl:";

  const ROLE_ACCOUNTS = new Set([
    "admin", "administrator", "billing", "contact", "hello", "help", "hr",
    "info", "jobs", "marketing", "media", "no-reply", "noreply", "office",
    "postmaster", "press", "sales", "security", "support", "team", "webmaster",
    "abuse", "accounts", "careers", "legal", "orders", "privacy"
  ]);

  const FREE_PROVIDERS = new Set([
    "gmail.com", "googlemail.com", "yahoo.com", "yahoo.co.uk", "outlook.com",
    "hotmail.com", "live.com", "msn.com", "aol.com", "icloud.com", "me.com",
    "proton.me", "protonmail.com", "gmx.com", "gmx.net", "zoho.com", "yandex.com",
    "mail.com", "tutanota.com", "fastmail.com", "hey.com"
  ]);

  const DISPOSABLE_DOMAINS = new Set([
    "10minutemail.com", "1secmail.com", "1secmail.net", "1secmail.org",
    "burnermail.io", "discard.email", "dispostable.com", "emailfake.com",
    "emailondeck.com", "fakeinbox.com", "generator.email", "getairmail.com",
    "getnada.com", "guerrillamail.com", "harakirimail.com", "incognitomail.org",
    "instantemailaddress.com", "jetable.org", "mailcatch.com", "maildrop.cc",
    "mailforspam.com", "mailinator.com", "mailnesia.com", "mailsac.com",
    "mail.tm", "mintemail.com", "moakt.com", "mohmal.com", "mytemp.email",
    "sharklasers.com", "spam4.me", "spamgourmet.com", "tempinbox.com",
    "tempmail.com", "tempmailo.com", "temp-mail.org", "tempsky.com",
    "throwaway.email", "throwawaymail.com", "trashmail.com", "yopmail.com"
  ]);

  const COMMON_DOMAINS = [
    "gmail.com", "googlemail.com", "yahoo.com", "yahoo.co.uk", "outlook.com",
    "hotmail.com", "live.com", "msn.com", "icloud.com", "me.com", "aol.com",
    "proton.me", "protonmail.com", "zoho.com", "gmx.com", "gmx.net",
    "fastmail.com", "hey.com", "mail.com", "yandex.com", "tutanota.com"
  ];

  const TLD_FIXES = { con: "com", cmo: "com", ocm: "com", coom: "com", comm: "com", nte: "net", orgg: "org" };

  const EMAIL_RE =
    /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$/;

  // ---------------------------------------------------------------------
  // Storage helpers: private mode or a full quota must never break the page.
  // ---------------------------------------------------------------------

  function readStore(key, fallback) {
    try {
      const raw = localStorage.getItem(key);
      return raw ? JSON.parse(raw) : fallback;
    } catch (err) {
      return fallback;
    }
  }

  function writeStore(key, value) {
    try {
      localStorage.setItem(key, JSON.stringify(value));
    } catch (err) {
      /* storage unavailable, continue without it */
    }
  }

  // ---------------------------------------------------------------------
  // Client-side rate limiting (sliding window, per rule).
  // ---------------------------------------------------------------------

  function consume(rule, bucket) {
    if (!rule) return { ok: true, remaining: Infinity };
    const now = Date.now();
    const key = RATE_PREFIX + bucket;
    const state = readStore(key, { hits: [] });
    const hits = (Array.isArray(state.hits) ? state.hits : []).filter(
      (time) => typeof time === "number" && now - time < rule.windowMs
    );

    if (hits.length >= rule.max) {
      writeStore(key, { hits });
      return {
        ok: false,
        remaining: 0,
        retryAfterMs: Math.max(0, rule.windowMs - (now - hits[0]))
      };
    }

    hits.push(now);
    writeStore(key, { hits });
    return { ok: true, remaining: rule.max - hits.length };
  }

  function checkLimits() {
    const limits = CONFIG.RATE_LIMITS || {};
    const free = consume(limits.free, "free-minute");
    if (!free.ok) return { ok: false, retryAfterMs: free.retryAfterMs, scope: "minute" };
    const daily = consume(limits.freeDaily, "free-day");
    if (!daily.ok) return { ok: false, retryAfterMs: daily.retryAfterMs, scope: "day" };
    return { ok: true };
  }

  function checkDeepLimit() {
    return consume((CONFIG.RATE_LIMITS || {}).deep, "deep-minute");
  }

  // ---------------------------------------------------------------------
  // Cache and in-flight de-duplication.
  // ---------------------------------------------------------------------

  function cacheKey(email, deep) {
    return (deep ? "deep:" : "free:") + email;
  }

  function readCache(key) {
    const store = readStore(CACHE_KEY, {});
    const entry = store[key];
    if (!entry || typeof entry.t !== "number") return null;
    const ttl = CONFIG.CACHE_TTL_MS || 86400000;
    if (Date.now() - entry.t > ttl) {
      delete store[key];
      writeStore(CACHE_KEY, store);
      return null;
    }
    const report = entry.report;
    return report ? Object.assign({}, report, { cached: true, durationMs: 0 }) : null;
  }

  function writeCache(key, report) {
    const store = readStore(CACHE_KEY, {});
    store[key] = { t: Date.now(), report };
    const keys = Object.keys(store);
    if (keys.length > CACHE_MAX) {
      keys
        .sort((a, b) => (store[a].t || 0) - (store[b].t || 0))
        .slice(0, keys.length - CACHE_MAX)
        .forEach((old) => delete store[old]);
    }
    writeStore(CACHE_KEY, store);
  }

  const inFlight = new Map();

  // ---------------------------------------------------------------------
  // Network helper: hard timeout, no credentials, no referrer.
  // ---------------------------------------------------------------------

  async function fetchJson(url, options, timeoutMs) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs || TIMEOUT);
    try {
      const res = await fetch(url, {
        method: "GET",
        credentials: "omit",
        cache: "no-store",
        referrerPolicy: "no-referrer",
        headers: { accept: "application/json" },
        ...options,
        signal: controller.signal
      });
      if (!res.ok) {
        const error = new Error("Request failed with status " + res.status);
        error.status = res.status;
        throw error;
      }
      return await res.json();
    } finally {
      clearTimeout(timer);
    }
  }

  // ---------------------------------------------------------------------
  // Local checks
  // ---------------------------------------------------------------------

  function checkSyntax(input) {
    const email = String(input || "").trim();
    const base = { id: "syntax", label: "Syntax" };

    if (!email) return { ok: false, check: { ...base, status: "fail", detail: "Enter an email address." } };
    if (/\s/.test(email)) return { ok: false, check: { ...base, status: "fail", detail: "Spaces are not allowed." } };
    if (email.length > 254) return { ok: false, check: { ...base, status: "fail", detail: "Address is longer than 254 characters." } };

    const at = email.lastIndexOf("@");
    if (at <= 0 || at !== email.indexOf("@")) {
      return { ok: false, check: { ...base, status: "fail", detail: "Address must contain exactly one @ with a user and a domain." } };
    }

    const localPart = email.slice(0, at);
    const domain = email.slice(at + 1).toLowerCase();

    if (!EMAIL_RE.test(email)) {
      return { ok: false, check: { ...base, status: "fail", detail: "Characters or domain labels are not valid." } };
    }
    if (localPart.length > 64) {
      return { ok: false, check: { ...base, status: "fail", detail: "The part before @ is longer than 64 characters." } };
    }
    if (localPart.startsWith(".") || localPart.endsWith(".") || localPart.includes("..")) {
      return { ok: false, check: { ...base, status: "fail", detail: "Dots cannot lead, trail or repeat in the user name." } };
    }
    if (domain.length > 253 || domain.startsWith("-") || domain.endsWith("-") || domain.includes("..")) {
      return { ok: false, check: { ...base, status: "fail", detail: "The domain is malformed." } };
    }
    if (!domain.includes(".")) {
      return { ok: false, check: { ...base, status: "fail", detail: "The domain needs a dot and a top level domain." } };
    }

    return {
      ok: true,
      parts: { localPart, domain },
      check: { ...base, status: "pass", detail: "Well formed address." }
    };
  }

  function levenshtein(a, b) {
    if (a === b) return 0;
    const rows = a.length + 1;
    const cols = b.length + 1;
    let prev = new Array(cols);
    let curr = new Array(cols);
    for (let j = 0; j < cols; j += 1) prev[j] = j;
    for (let i = 1; i < rows; i += 1) {
      curr[0] = i;
      for (let j = 1; j < cols; j += 1) {
        const cost = a[i - 1] === b[j - 1] ? 0 : 1;
        curr[j] = Math.min(prev[j] + 1, curr[j - 1] + 1, prev[j - 1] + cost);
      }
      const swap = prev;
      prev = curr;
      curr = swap;
    }
    return prev[cols - 1];
  }

  function suggestDomain(domain) {
    if (!domain) return null;
    let best = null;
    for (const candidate of COMMON_DOMAINS) {
      if (candidate === domain) return null;
      const distance = levenshtein(domain, candidate);
      const allowed = domain.length >= 8 ? 2 : 1;
      if (distance > 0 && distance <= allowed && distance <= domain.length / 3) {
        if (!best || distance < best.distance) best = { candidate, distance };
      }
    }
    if (best) return best.candidate;

    const dot = domain.lastIndexOf(".");
    const tld = domain.slice(dot + 1);
    if (TLD_FIXES[tld]) return domain.slice(0, dot + 1) + TLD_FIXES[tld];
    return null;
  }

  function localChecks(parts) {
    const checks = [];
    const { localPart, domain } = parts;
    const normalizedLocal = localPart.toLowerCase();

    if (ROLE_ACCOUNTS.has(normalizedLocal) || /^(info|sales|admin|support)[+._-]/.test(normalizedLocal)) {
      checks.push({
        id: "role",
        label: "Role account",
        status: "warn",
        detail: "Shared address. Fine for contact pages, risky for signups."
      });
    } else {
      checks.push({ id: "role", label: "Role account", status: "pass", detail: "Personal-looking mailbox name." });
    }

    if (DISPOSABLE_DOMAINS.has(domain)) {
      checks.push({
        id: "disposable",
        label: "Disposable provider",
        status: "fail",
        detail: "Known throwaway domain. Addresses here usually expire."
      });
    } else {
      checks.push({
        id: "disposable",
        label: "Disposable provider",
        status: "pass",
        detail: "Not on the built-in throwaway list."
      });
    }

    if (FREE_PROVIDERS.has(domain)) {
      checks.push({
        id: "provider",
        label: "Provider type",
        status: "pass",
        detail: "Free mailbox provider (" + domain + ")."
      });
    }

    const suggestion = suggestDomain(domain);
    if (suggestion) {
      checks.push({
        id: "typo",
        label: "Typo check",
        status: "warn",
        detail: "Looks close to " + suggestion + "."
      });
    } else {
      checks.push({ id: "typo", label: "Typo check", status: "pass", detail: "No common domain typo found." });
    }

    return { checks, suggestion: suggestion ? normalizedLocal + "@" + suggestion : null };
  }

  // ---------------------------------------------------------------------
  // DNS over HTTPS: MX, with A record fallback.
  // ---------------------------------------------------------------------

  async function lookupMx(domain) {
    const resolvers = Array.isArray(CONFIG.DNS_RESOLVERS) ? CONFIG.DNS_RESOLVERS : [];
    let lastError = null;

    for (const resolver of resolvers) {
      try {
        const mxUrl =
          resolver.url + "?name=" + encodeURIComponent(domain) + "&type=MX";
        const mx = await fetchJson(mxUrl, { headers: { accept: "application/dns-json" } });

        if (mx.Status !== 0) {
          return {
            status: "fail",
            detail: "Domain does not resolve (DNS status " + mx.Status + ").",
            source: resolver.name
          };
        }

        const records = (Array.isArray(mx.Answer) ? mx.Answer : [])
          .filter((record) => record.type === 15)
          .map((record) => String(record.data || ""));

        if (records.length > 0) {
          return {
            status: "pass",
            detail: records.length + " mail server" + (records.length === 1 ? "" : "s") + ": " + records.slice(0, 3).join(", "),
            records,
            source: resolver.name
          };
        }

        const aUrl = resolver.url + "?name=" + encodeURIComponent(domain) + "&type=A";
        const a = await fetchJson(aUrl, { headers: { accept: "application/dns-json" } });
        if ((Array.isArray(a.Answer) ? a.Answer : []).some((record) => record.type === 1)) {
          return {
            status: "warn",
            detail: "No MX record. Domain has an A record and may still accept mail.",
            source: resolver.name
          };
        }
        return { status: "fail", detail: "No MX or A record for this domain.", source: resolver.name };
      } catch (error) {
        lastError = error;
      }
    }

    return {
      status: "unknown",
      detail: lastError && lastError.name === "AbortError" ? "DNS lookup timed out." : "DNS lookup unavailable right now."
    };
  }

  // ---------------------------------------------------------------------
  // Reputation enrichment (free, keyless).
  // ---------------------------------------------------------------------

  async function lookupReputation(email) {
    const apis = CONFIG.LOOKUP_APIS || {};

    if (apis.disify) {
      try {
        const data = await fetchJson(apis.disify + encodeURIComponent(email));
        if (data && typeof data === "object") {
          return {
            source: "disify.com",
            disposable: data.disposable === true,
            role: data.role === true,
            hasMx: typeof data.dns === "boolean" ? data.dns : null,
            suggestion:
              typeof data.typo_suggestion === "string" && data.typo_suggestion ? data.typo_suggestion : null
          };
        }
      } catch (error) {
        /* fall through to the next provider */
      }
    }

    if (apis.usercheck) {
      try {
        const data = await fetchJson(apis.usercheck + encodeURIComponent(email));
        if (data && typeof data === "object") {
          return {
            source: "api.usercheck.com",
            disposable: data.disposable === true,
            role: data.role === true,
            alias: data.alias === true,
            hasMx: typeof data.mx === "boolean" ? data.mx : null,
            domainAgeDays:
              typeof data.domain_age_in_days === "number" ? data.domain_age_in_days : null,
            suggestion:
              typeof data.did_you_mean === "string" && data.did_you_mean ? data.did_you_mean : null
          };
        }
      } catch (error) {
        /* no enrichment available */
      }
    }

    return null;
  }

  // ---------------------------------------------------------------------
  // Deep mailbox probe (emailvalidation.io, uses credits).
  // ---------------------------------------------------------------------

  async function deepProbe(email) {
    const paths = CONFIG.API_PATHS || {};
    const base = CONFIG.API_BASE || "";
    if (!paths.verify) {
      return { status: "unknown", detail: "Deep check is not configured." };
    }

    try {
      const data = await fetchJson(
        base + paths.verify,
        {
          method: "POST",
          headers: { "content-type": "application/json", accept: "application/json" },
          body: JSON.stringify({ email })
        },
        12000
      );
      const state = String(data.state || "unknown");
      const checks = [];

      if (data.smtp_check === true || state === "deliverable") {
        checks.push({
          id: "mailbox",
          label: "Mailbox (SMTP)",
          status: "pass",
          detail: "Mail server accepted the mailbox."
        });
      } else if (state === "risky") {
        checks.push({
          id: "mailbox",
          label: "Mailbox (SMTP)",
          status: "warn",
          detail: data.explanation || "Mailbox exists but looks risky."
        });
      } else if (state === "undeliverable") {
        checks.push({
          id: "mailbox",
          label: "Mailbox (SMTP)",
          status: "fail",
          detail: data.explanation || "Mailbox rejected by the mail server."
        });
      } else {
        checks.push({
          id: "mailbox",
          label: "Mailbox (SMTP)",
          status: "unknown",
          detail: "Mail server did not confirm the mailbox."
        });
      }

      if (data.catch_all === true) {
        checks.push({
          id: "catch_all",
          label: "Catch-all domain",
          status: "warn",
          detail: "This domain accepts mail for any address, so SMTP proof is weak."
        });
      }

      return {
        checks,
        suggestion: typeof data.did_you_mean === "string" && data.did_you_mean ? data.did_you_mean : null,
        source: "emailvalidation.io",
        remote: {
          state,
          score: typeof data.score === "number" ? data.score : null,
          reason: data.reason || null,
          subStatus: data.sub_status || null
        }
      };
    } catch (error) {
      const status = error && error.status;
      let detail = "Deep check unavailable. Free checks still apply.";
      if (status === 404 || status === 405 || status === 501) {
        detail = "Deep check needs the included server. Free checks still apply.";
      } else if (status === 503) {
        detail = "Deep check is not configured on this server.";
      } else if (status === 429) {
        detail = "Deep check limit reached. Try again later.";
      } else if (status === 502) {
        detail = "The mailbox service is unavailable right now.";
      } else if (status === 401 || status === 403) {
        detail = "The deep check proxy rejected the request.";
      }
      return { status: "unknown", detail, source: "emailvalidation.io" };
    }
  }

  // ---------------------------------------------------------------------
  // Scoring and report assembly
  // ---------------------------------------------------------------------

  const WEIGHTS = {
    syntax: 100,
    mx: 35,
    mailbox: 45,
    disposable: 40,
    role: 8,
    typo: 15,
    catch_all: 5
  };

  function finalize(report) {
    let score = 100;
    let invalid = false;
    let risky = false;
    let confirmed = false;

    for (const check of report.checks) {
      const weight = WEIGHTS[check.id] || 0;
      if (check.status === "fail") {
        score -= weight || 10;
        if (check.id === "syntax" || check.id === "mx" || check.id === "mailbox" || check.id === "disposable") {
          invalid = true;
        } else {
          risky = true;
        }
      } else if (check.status === "warn") {
        score -= Math.min(weight || 5, 6);
        risky = true;
      } else if (check.status === "unknown") {
        score -= 3;
      } else {
        confirmed = true;
      }
      if (check.id === "mx" && check.status === "pass") confirmed = true;
      if (check.id === "mailbox" && check.status === "pass") confirmed = true;
    }

    score = Math.max(0, Math.min(100, Math.round(score)));

    const mxCheck = report.checks.find((check) => check.id === "mx");
    if (mxCheck && mxCheck.status === "unknown") risky = true;

    let verdict = "valid";
    if (invalid) verdict = "invalid";
    else if (risky || score < 70 || !confirmed) verdict = "risky";

    report.score = score;
    report.verdict = verdict;
    report.durationMs = Math.round((Date.now() - report._startedAt) || 0);
    delete report._startedAt;
    return report;
  }

  function dedupeSources(sources) {
    return sources.filter((value, index) => value && sources.indexOf(value) === index);
  }

  // ---------------------------------------------------------------------
  // Public API
  // ---------------------------------------------------------------------

  async function validate(rawEmail, options) {
    const opts = options || {};
    const startedAt = Date.now();
    const email = String(rawEmail || "").trim().toLowerCase();
    const deep = opts.deep === true;
    const force = opts.force === true;
    const report = {
      email,
      checks: [],
      sources: [],
      suggestion: null,
      verdict: "invalid",
      score: 0,
      deep,
      cached: false,
      durationMs: 0,
      generatedAt: new Date().toISOString(),
      _startedAt: startedAt
    };

    const syntax = checkSyntax(email);
    report.checks.push(syntax.check);
    if (!syntax.ok) return finalize(report);

    const key = cacheKey(email, deep);
    if (!force) {
      const cached = readCache(key);
      if (cached) return cached;
    }

    const existing = inFlight.get(key);
    if (existing) return existing;

    const task = (async () => {
      const limits = checkLimits();
      if (!limits.ok) {
        const error = new Error(
          limits.scope === "day"
            ? "Daily free-check limit reached. Try again tomorrow."
            : "Too many checks. Wait " + Math.ceil(limits.retryAfterMs / 1000) + "s."
        );
        error.code = "rate_limited";
        error.retryAfterMs = limits.retryAfterMs;
        throw error;
      }

      const local = localChecks(syntax.parts);
      // Replace the local disposable result with a confirmed remote one later.
      report.checks.push(...local.checks);
      if (local.suggestion) report.suggestion = local.suggestion;

      const [mxResult, reputation] = await Promise.all([
        lookupMx(syntax.parts.domain),
        lookupReputation(email)
      ]);

      report.checks.push({
        id: "mx",
        label: "MX records",
        status: mxResult.status,
        detail: mxResult.detail
      });
      if (mxResult.source) report.sources.push(mxResult.source);

      if (reputation) {
        report.sources.push(reputation.source);

        if (mxResult.status === "unknown" && typeof reputation.hasMx === "boolean") {
          const mxCheck = report.checks.find((check) => check.id === "mx");
          if (mxCheck) {
            mxCheck.status = reputation.hasMx ? "warn" : "fail";
            mxCheck.detail = reputation.hasMx
              ? "DNS was unreachable; " + reputation.source + " reports a mail exchanger."
              : "DNS was unreachable; " + reputation.source + " reports no mail exchanger.";
          }
        }

        const disposableCheck = report.checks.find((check) => check.id === "disposable");
        if (disposableCheck && reputation.disposable) {
          disposableCheck.status = "fail";
          disposableCheck.detail = "Confirmed throwaway domain by " + reputation.source + ".";
        } else if (disposableCheck && disposableCheck.status !== "fail") {
          disposableCheck.status = "pass";
          disposableCheck.detail = "Not listed as a throwaway domain.";
        }

        if (reputation.role) {
          const roleCheck = report.checks.find((check) => check.id === "role");
          if (roleCheck) {
            roleCheck.status = "warn";
            roleCheck.detail = "The reputation database lists this as a shared role address.";
          }
        }

        if (reputation.alias === true) {
          report.checks.push({
            id: "alias",
            label: "Alias address",
            status: "warn",
            detail: "This mailbox forwards to another address, so identity is indirect."
          });
        }

        if (typeof reputation.domainAgeDays === "number") {
          const days = reputation.domainAgeDays;
          report.checks.push({
            id: "domain_age",
            label: "Domain age",
            status: days < 30 ? "warn" : "pass",
            detail:
              days < 1
                ? "Domain was registered today."
                : "Domain is " + days.toLocaleString() + " days old."
          });
        }

        if (reputation.suggestion && !report.suggestion) {
          const at = email.lastIndexOf("@");
          const localPart = at > 0 ? email.slice(0, at) : "";
          report.suggestion = reputation.suggestion.includes("@")
            ? reputation.suggestion
            : localPart + "@" + reputation.suggestion;
        }
      }

      if (deep) {
        const deepLimit = checkDeepLimit();
        if (!deepLimit.ok) {
          report.checks.push({
            id: "mailbox",
            label: "Mailbox (SMTP)",
            status: "unknown",
            detail: "Deep check limit reached. Wait " + Math.ceil(deepLimit.retryAfterMs / 1000) + "s."
          });
        } else {
          const probe = await deepProbe(email);
          if (Array.isArray(probe.checks)) report.checks.push(...probe.checks);
          else report.checks.push({ id: "mailbox", label: "Mailbox (SMTP)", status: probe.status, detail: probe.detail });
          if (probe.source) report.sources.push(probe.source);
          if (probe.suggestion) report.suggestion = probe.suggestion;
          if (probe.remote) report.remote = probe.remote;
        }
      }

      report.sources = dedupeSources(report.sources);
      if (mxResult.records) report.mxRecords = mxResult.records.slice(0, 5);

      const finished = finalize(report);
      finished.cached = false;
      writeCache(cacheKey(email, deep), finished);
      return finished;
    })();

    inFlight.set(key, task);
    try {
      return await task;
    } finally {
      inFlight.delete(key);
    }
  }

  function quickCheck(rawEmail) {
    const email = String(rawEmail || "").trim();
    const syntax = checkSyntax(email);
    if (!syntax.ok) return { ok: false, message: syntax.check.detail, suggestion: null };
    const parts = syntax.parts;
    const local = localChecks(parts);
    const disposable = local.checks.find((check) => check.id === "disposable");
    return {
      ok: true,
      disposable: Boolean(disposable && disposable.status === "fail"),
      suggestion: local.suggestion,
      provider: parts.domain
    };
  }

  global.Validax = Object.freeze({ validate, quickCheck, consumeLimit: consume });
})(window);
