// VULNERABLE DOM sink.
//
// The active-filter label comes from the URL fragment (never sent to the server)
// and is written into `innerHTML`, so markup in the fragment is parsed as HTML and
// event-handler / element-loading script executes. A crafted `/filtered#...` deep
// link therefore runs attacker script that appears in no server-side request record.
// Contrast the secure app's `textContent` assignment.
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
      label.innerHTML = raw ? raw : "(all)"; // data crosses into a markup context
    }
  }

  window.addEventListener("hashchange", apply);
  apply();
})();
