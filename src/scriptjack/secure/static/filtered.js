// Secure DOM sink.
//
// The active-filter label comes from the URL fragment (never sent to the server).
// It is written with `textContent`, so any markup in the fragment is shown as
// inert text and is never parsed as HTML or script. The vulnerable application
// (a later slice) assigns the same value with `innerHTML` — that is the whole
// contrast. There is no `innerHTML`, `document.write`, or `eval` here.
(function () {
  "use strict";

  function currentFilter() {
    var raw = window.location.hash.replace(/^#/, "");
    try {
      return decodeURIComponent(raw);
    } catch (err) {
      return raw;
    }
  }

  function apply() {
    var raw = currentFilter();
    var label = document.getElementById("active-filter");
    if (label) {
      label.textContent = raw ? raw : "(all)"; // data stays data
    }

    var wanted = null;
    var match = /(?:^|;)\s*status=([a-z]+)/.exec(raw);
    if (match) {
      wanted = match[1];
    }

    var rows = document.querySelectorAll("#vendor-table tbody tr");
    rows.forEach(function (row) {
      var statusCell = row.children.length > 1 ? row.children[1] : null;
      var status = statusCell ? statusCell.textContent.trim() : "";
      row.hidden = wanted !== null && status !== wanted;
    });
  }

  window.addEventListener("hashchange", apply);
  apply();
})();
