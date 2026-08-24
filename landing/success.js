(function () {
  "use strict";
  const status = document.getElementById("session-status");
  const panel = document.getElementById("license-panel");
  const licenseValue = document.getElementById("license-value");
  const copyButton = document.getElementById("copy-license");
  const activationHelp = document.getElementById("activation-help");
  const sessionId = new URLSearchParams(window.location.search).get("session_id") || "";
  const apiBase = normalizeApiBase(window.EXTGUARD_CONFIG?.apiBaseUrl);
  if (!status || !panel || !licenseValue || !copyButton || !activationHelp) return;
  if (!apiBase) { fail("Activation service is not configured. Contact support with your Stripe receipt."); return; }
  if (!/^cs_(?:test_|live_)?[A-Za-z0-9]+$/.test(sessionId)) { fail("This activation link is incomplete. Open the success link from your Stripe receipt."); return; }
  loadLicense();
  async function loadLicense() {
    try {
      const endpoint = new URL("/api/v1/checkout/session", `${apiBase}/`);
      endpoint.searchParams.set("session_id", sessionId);
      const response = await fetch(endpoint, { method: "GET", headers: { Accept: "application/json" }, cache: "no-store", credentials: "omit", referrerPolicy: "no-referrer" });
      const payload = await readJson(response);
      if (response.status === 202) throw new Error("The subscription is still processing. Refresh this page shortly.");
      if (!response.ok) throw new Error(publicMessage(payload, "The subscription could not be confirmed."));
      if (typeof payload.licenseKey !== "string" || payload.licenseKey.length < 20) throw new Error("The activation service returned an invalid license key.");
      licenseValue.textContent = payload.licenseKey;
      panel.classList.add("visible");
      activationHelp.hidden = false;
      status.textContent = "Payment confirmed. Your Team license is ready.";
      document.title = "ExtGuard Team license ready";
    } catch (error) { fail(error instanceof Error ? error.message : "The subscription could not be confirmed."); }
  }
  copyButton.addEventListener("click", async () => {
    const value = licenseValue.textContent || "";
    try { await navigator.clipboard.writeText(value); copyButton.textContent = "Copied"; }
    catch {
      const selection = window.getSelection();
      const range = document.createRange();
      range.selectNodeContents(licenseValue);
      selection?.removeAllRanges();
      selection?.addRange(range);
      copyButton.textContent = "Selected for copying";
    }
  });
  function fail(message) { status.textContent = message; status.classList.add("form-status", "error"); document.title = "ExtGuard activation needs attention"; }
  function normalizeApiBase(value) {
    if (typeof value !== "string" || value.trim() === "") return "";
    try {
      const url = new URL(value.trim());
      const local = url.hostname === "localhost" || url.hostname === "127.0.0.1";
      if (url.protocol !== "https:" && !(local && url.protocol === "http:")) return "";
      return url.href.replace(/\/$/, "");
    } catch { return ""; }
  }
  async function readJson(response) {
    const contentType = response.headers.get("content-type") || "";
    if (!contentType.includes("application/json")) return {};
    try { return await response.json(); } catch { return {}; }
  }
  function publicMessage(payload, fallback) {
    const value = typeof payload?.error === "string" ? payload.error : payload?.error?.message;
    return typeof value === "string" && value.length <= 180 ? value : fallback;
  }
})();
