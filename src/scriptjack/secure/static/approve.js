// The portal's own approve action.
//
// It reads the page-embedded API token and POSTs the approve request — exactly
// what injected script would do in the vulnerable application. Here it runs only
// when the reviewer clicks an Approve button, and only because the nonce-based
// CSP authorises this file. It is included to make the legitimate path and the
// (later) hijacked path structurally identical.
(function () {
  "use strict";

  function apiToken() {
    var meta = document.querySelector('meta[name="scriptjack-api-token"]');
    return meta ? meta.getAttribute("content") : "";
  }

  document.addEventListener("click", function (event) {
    var target = event.target;
    if (!target || !target.classList || !target.classList.contains("approve")) {
      return;
    }
    var vendor = target.getAttribute("data-vendor");
    if (!vendor) {
      return;
    }
    fetch("/vendors/" + encodeURIComponent(vendor) + "/approve", {
      method: "POST",
      headers: { "X-Api-Token": apiToken() },
    })
      .then(function (response) {
        return response.json();
      })
      .then(function (data) {
        var row = document.querySelector('tr[data-vendor="' + vendor + '"]');
        if (row) {
          var statusCell = row.querySelector(".status");
          if (statusCell && data.status) {
            statusCell.textContent = data.status;
          }
        }
        if (data.status === "approved") {
          target.remove();
        }
      })
      .catch(function () {
        /* demo: ignore transport errors */
      });
  });
})();
