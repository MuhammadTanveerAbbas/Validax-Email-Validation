/**
 * Validax page behaviour: navigation, copy helpers and the validator UI.
 * All text that comes from the network is inserted with textContent, never
 * innerHTML, so an API response cannot inject markup or script.
 */
(function () {
  "use strict";

  const $ = (id) => document.getElementById(id);
  const VERDICT_LABEL = { valid: "Valid", risky: "Risky", invalid: "Invalid", unknown: "Unknown" };
  const STATUS_ICON = { pass: "\u2713", warn: "!", fail: "\u2715", unknown: "?" };

  function prefersReducedMotion() {
    return window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  }

  function showToast(text) {
    const toast = $("toast");
    if (!toast) return;
    toast.textContent = text;
    toast.classList.add("show");
    clearTimeout(showToast.timer);
    showToast.timer = setTimeout(() => toast.classList.remove("show"), 2600);
  }

  async function copyText(text) {
    try {
      if (navigator.clipboard && window.isSecureContext) {
        await navigator.clipboard.writeText(text);
        return true;
      }
      throw new Error("clipboard API unavailable");
    } catch (error) {
      const input = document.createElement("textarea");
      input.value = text;
      input.setAttribute("readonly", "");
      input.style.position = "fixed";
      input.style.opacity = "0";
      document.body.appendChild(input);
      input.select();
      let ok = false;
      try {
        ok = document.execCommand("copy");
      } catch (err) {
        ok = false;
      }
      document.body.removeChild(input);
      return ok;
    }
  }

  // ---------------------------------------------------------------------
  // Shared chrome
  // ---------------------------------------------------------------------

  const year = $("year");
  if (year) year.textContent = String(new Date().getFullYear());

  const navToggle = $("navToggle");
  const navLinks = $("navLinks");
  if (navToggle && navLinks) {
    navToggle.addEventListener("click", () => {
      const open = navLinks.classList.toggle("is-open");
      navToggle.setAttribute("aria-expanded", String(open));
    });
    navLinks.addEventListener("click", (event) => {
      if (event.target.closest("a")) {
        navLinks.classList.remove("is-open");
        navToggle.setAttribute("aria-expanded", "false");
      }
    });
  }

  const copyButton = $("copyButton");
  if (copyButton) {
    const address = copyButton.dataset.email || "muhammadtanveerabbas.dev@gmail.com";
    const message = $("copyMessage");
    copyButton.addEventListener("click", async () => {
      const ok = await copyText(address);
      if (!ok) {
        showToast("Could not copy. Select the address manually.");
        return;
      }
      copyButton.textContent = "Copied!";
      if (message) message.classList.add("visible");
      showToast("Email copied to clipboard");
      setTimeout(() => {
        copyButton.textContent = "Copy email";
        if (message) message.classList.remove("visible");
      }, 2500);
    });
  }

  // ---------------------------------------------------------------------
  // Validator
  // ---------------------------------------------------------------------

  const form = $("emailForm");
  if (!form || !window.Validax) return;

  const emailInput = $("emailInput");
  const deepCheck = $("deepCheck");
  const validateBtn = $("validateBtn");
  const liveHint = $("liveHint");
  const statusLine = $("statusLine");
  const resultPanel = $("resultPanel");
  const verdictEl = $("verdict");
  const resultEmail = $("resultEmail");
  const scoreValue = $("scoreValue");
  const scoreBar = $("scoreBar");
  const scoreFill = $("scoreFill");
  const suggestionBox = $("suggestionBox");
  const suggestionText = $("suggestionText");
  const applySuggestion = $("applySuggestion");
  const checkList = $("checkList");
  const resultMeta = $("resultMeta");
  const jsonOut = $("jsonOut");
  const copyJsonBtn = $("copyJsonBtn");
  const recheckBtn = $("recheckBtn");
  const clearBtn = $("clearBtn");

  let lastReport = null;
  let hintTimer = null;
  let suggestion = null;

  function setStatus(message, tone) {
    if (!statusLine) return;
    statusLine.textContent = message || "";
    statusLine.classList.toggle("is-error", tone === "error");
    statusLine.classList.toggle("is-ok", tone === "ok");
  }

  function setLoading(message) {
    if (!statusLine) return;
    statusLine.textContent = "";
    statusLine.classList.remove("is-error", "is-ok");
    const loader = document.createElement("span");
    loader.className = "dot-loader";
    loader.setAttribute("aria-hidden", "true");
    loader.appendChild(document.createElement("span"));
    loader.appendChild(document.createElement("span"));
    loader.appendChild(document.createElement("span"));
    const label = document.createElement("span");
    label.textContent = message;
    statusLine.appendChild(loader);
    statusLine.appendChild(label);
  }

  function updateLiveHint() {
    if (!liveHint) return;
    const value = emailInput.value.trim();
    liveHint.classList.remove("is-error", "is-ok", "is-warn");
    suggestion = null;

    if (!value) {
      liveHint.textContent = "Local checks run instantly, then DNS and reputation lookups.";
      return;
    }

    const quick = window.Validax.quickCheck(value);
    if (!quick.ok) {
      liveHint.textContent = quick.message;
      liveHint.classList.add("is-error");
      return;
    }
    if (quick.disposable) {
      liveHint.textContent = "This domain is on the disposable list.";
      liveHint.classList.add("is-error");
      return;
    }
    if (quick.suggestion) {
      suggestion = quick.suggestion;
      liveHint.textContent = "Looks well formed. Did you mean " + quick.suggestion + "?";
      return;
    }
    liveHint.textContent = "Looks well formed. Run the check for DNS and reputation data.";
    liveHint.classList.add("is-ok");
  }

  emailInput.addEventListener("input", () => {
    clearTimeout(hintTimer);
    hintTimer = setTimeout(updateLiveHint, 250);
  });

  document.querySelectorAll("#examples .chip").forEach((chip) => {
    chip.addEventListener("click", () => {
      emailInput.value = chip.dataset.email || chip.textContent.trim();
      updateLiveHint();
      emailInput.focus();
    });
  });

  function renderChecks(checks) {
    checkList.textContent = "";
    checks.forEach((check) => {
      const status = STATUS_ICON[check.status] ? check.status : "unknown";
      const item = document.createElement("li");
      item.className = "check " + status;

      const icon = document.createElement("span");
      icon.className = "check-icon";
      icon.setAttribute("aria-hidden", "true");
      icon.textContent = STATUS_ICON[status];

      const body = document.createElement("span");
      body.className = "check-body";

      const label = document.createElement("span");
      label.className = "check-label";
      label.textContent = check.label;
      body.appendChild(label);

      const detail = document.createElement("span");
      detail.className = "check-detail";
      detail.textContent = String(check.detail || "").slice(0, 300);
      body.appendChild(detail);

      item.appendChild(icon);
      item.appendChild(body);
      checkList.appendChild(item);
    });
  }

  function renderMeta(report) {
    resultMeta.textContent = "";
    const parts = [
      report.cached ? "from local cache" : "checked in " + report.durationMs + " ms",
      report.deep ? "deep SMTP check" : "standard check",
      report.sources && report.sources.length ? "sources: " + report.sources.join(", ") : "local rules only"
    ];
    parts.forEach((text) => {
      const span = document.createElement("span");
      span.textContent = text;
      resultMeta.appendChild(span);
    });
    if (report.mxRecords && report.mxRecords.length) {
      const span = document.createElement("span");
      span.textContent = "MX: " + report.mxRecords.slice(0, 2).join(", ");
      resultMeta.appendChild(span);
    }
  }

  function render(report) {
    if (!report) return;
    lastReport = report;

    resultEmail.textContent = report.email;
    verdictEl.textContent = VERDICT_LABEL[report.verdict] || "Unknown";
    verdictEl.className = "verdict is-" + (VERDICT_LABEL[report.verdict] ? report.verdict : "unknown");

    scoreValue.textContent = report.score + " / 100";
    scoreBar.setAttribute("aria-valuenow", String(report.score));
    scoreFill.style.width = report.score + "%";
    scoreFill.className = "score-fill is-" + (VERDICT_LABEL[report.verdict] ? report.verdict : "unknown");

    suggestion = report.suggestion || null;
    if (suggestionBox && suggestionText) {
      suggestionBox.hidden = !suggestion;
      suggestionText.textContent = suggestion || "";
    }

    renderChecks(Array.isArray(report.checks) ? report.checks : []);
    renderMeta(report);

    if (jsonOut) {
      jsonOut.textContent = JSON.stringify(report, null, 2);
    }

    resultPanel.hidden = false;
    if (!prefersReducedMotion()) {
      resultPanel.scrollIntoView({ behavior: "smooth", block: "nearest" });
    }
  }

  async function runCheck(force) {
    const email = emailInput.value.trim();
    if (!email) {
      setStatus("Enter an email address first.", "error");
      emailInput.focus();
      return;
    }

    const deep = Boolean(deepCheck && deepCheck.checked);
    validateBtn.disabled = true;
    validateBtn.textContent = "Checking";
    setLoading(deep ? "Running deep mailbox check..." : "Checking syntax, DNS and reputation...");

    try {
      const report = await window.Validax.validate(email, { deep: deep, force: Boolean(force) });
      render(report);
      setStatus(
        report.cached
          ? "Loaded from the 24 hour cache. Use Re-check to refresh."
          : "Done in " + report.durationMs + " ms.",
        "ok"
      );
    } catch (error) {
      if (error && error.code === "rate_limited") {
        setStatus(error.message, "error");
      } else if (error && error.name === "AbortError") {
        setStatus("The check timed out. Try again.", "error");
      } else {
        setStatus("Check failed: " + (error && error.message ? error.message : "unknown error"), "error");
      }
    } finally {
      validateBtn.disabled = false;
      validateBtn.textContent = "Validate";
    }
  }

  form.addEventListener("submit", (event) => {
    event.preventDefault();
    runCheck(false);
  });

  if (applySuggestion) {
    applySuggestion.addEventListener("click", () => {
      if (!suggestion) return;
      emailInput.value = suggestion;
      updateLiveHint();
      form.requestSubmit();
    });
  }

  if (copyJsonBtn) {
    copyJsonBtn.addEventListener("click", async () => {
      if (!lastReport) return;
      const ok = await copyText(JSON.stringify(lastReport, null, 2));
      showToast(ok ? "JSON copied" : "Could not copy the JSON");
    });
  }

  if (recheckBtn) {
    recheckBtn.addEventListener("click", () => runCheck(true));
  }

  if (clearBtn) {
    clearBtn.addEventListener("click", () => {
      lastReport = null;
      resultPanel.hidden = true;
      emailInput.value = "";
      updateLiveHint();
      setStatus("");
      emailInput.focus();
    });
  }
})();
