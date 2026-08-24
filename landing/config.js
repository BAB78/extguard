window.EXTGUARD_CONFIG = Object.freeze({
  apiBaseUrl: "https://extguard-api.nivroo.workers.dev",

  // Open: the Stripe account is live-approved and the API runs on live credentials. Set this
  // back to false to stop taking new subscriptions without taking the site down; the success
  // page still needs apiBaseUrl so existing customers can retrieve their licence key.
  checkoutOpen: true,
});
