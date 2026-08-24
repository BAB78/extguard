window.EXTGUARD_CONFIG = Object.freeze({
  apiBaseUrl: "https://extguard-api.nivroo.workers.dev",

  // Purchasing stays closed until the Stripe account finishes live-mode review. The API above
  // is still needed while closed: the success page uses it to hand a licence key to anyone who
  // already bought. Sending a real visitor to a checkout page stamped "Sandbox" would look
  // broken and could take a card that was never going to be charged.
  checkoutOpen: false,
});
