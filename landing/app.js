(function () {
  "use strict";
  const form = document.getElementById("checkout-form");
  const button = document.getElementById("checkout-button");
  const emailInput = document.getElementById("checkout-email");
  const seatsInput = document.getElementById("checkout-seats");
  const status = document.getElementById("checkout-status");
  if (!form || !button || !emailInput || !seatsInput || !status) return;
  const apiBase = normalizeApiBase(window.EXTGUARD_CONFIG?.apiBaseUrl);
  if (!apiBase) {
    button.disabled = true;
    button.textContent = "Team checkout is not open yet";
    setStatus("The free extension remains available without a time limit.");
    return;
  }
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    setStatus("");
    if (!form.reportValidity()) return;
    const email = String(emailInput.value).trim();
    const seats = Number.parseInt(String(seatsInput.value), 10);
    if (!Number.isInteger(seats) || seats < 1 || seats > 100) {
      setStatus("Choose between 1 and 100 seats.", true);
      return;
    }
    setLoading(true);
    try {
      const response = await fetch(`${apiBase}/api/v1/checkout`, {
        method: "POST",
        headers: { Accept: "application/json", "Content-Type": "application/json" },
        body: JSON.stringify({ email, seats }),
        credentials: "omit",
        referrerPolicy: "no-referrer",
      });
      const payload = await readJson(response);
      if (!response.ok) throw new Error(publicMessage(payload, "Checkout could not be started."));
      const checkoutUrl = parseStripeCheckoutUrl(payload.url);
      if (!checkoutUrl) throw new Error("The checkout service returned an invalid destination.");
      window.location.assign(checkoutUrl.href);
    } catch (error) {
      setStatus(error instanceof Error ? error.message : "Checkout could not be started.", true);
      setLoading(false);
    }
  });
  function setLoading(loading) {
    button.disabled = loading;
    emailInput.disabled = loading;
    seatsInput.disabled = loading;
    button.textContent = loading ? "Opening Stripe checkout..." : "Continue to secure checkout";
  }
  function setStatus(message, isError) {
    status.textContent = message;
    status.classList.toggle("error", Boolean(isError));
  }
  function normalizeApiBase(value) {
    if (typeof value !== "string" || value.trim() === "") return "";
    try {
      const url = new URL(value.trim());
      const local = url.hostname === "localhost" || url.hostname === "127.0.0.1";
      if (url.protocol !== "https:" && !(local && url.protocol === "http:")) return "";
      return url.href.replace(/\/$/, "");
    } catch { return ""; }
  }
  function parseStripeCheckoutUrl(value) {
    if (typeof value !== "string") return null;
    try {
      const url = new URL(value);
      return url.protocol === "https:" && url.hostname === "checkout.stripe.com" ? url : null;
    } catch { return null; }
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
