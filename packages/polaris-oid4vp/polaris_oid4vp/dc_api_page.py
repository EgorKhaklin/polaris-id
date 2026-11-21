# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""dc_api_page.py -- the page `serve(dc_api_origin=...)` answers at /dc-api/, and its script.

The page asks the browser for an mdoc over the Digital Credentials API: the script fetches a
signed request from /dc-api/request, hands it to `navigator.credentials.get` when the button is
pressed, and posts what the wallet answers to /dc-api/response. It runs under
`default-src 'none'; script-src 'self'; connect-src 'self'`: no inline script, no event handler
attribute, no style, and no other origin. It shows one status line and never a claim value.

The feature test is the one the Digital Credentials draft gives (W3C Working Draft, section 2.2
and section 7.7: "static boolean userAgentAllowsProtocol(DOMString protocol)"): without a
`DigitalCredential` interface, or with one whose `userAgentAllowsProtocol` says no to
`openid4vp-v1-signed`, the page says the browser cannot present here and fetches nothing. The
request is fetched before the button is pressed, so `get()` is called inside the press, in the
user activation the API asks for.
"""

PAGE = b"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Present a credential</title>
<script src="/dc-api/app.js" defer></script>
</head>
<body>
<main>
<h1>Present a credential</h1>
<p>This page asks your wallet for a credential through your browser.</p>
<p><button id="present" type="button" disabled>Present a credential</button></p>
<p id="status" role="status" aria-live="polite">Preparing a request.</p>
</main>
</body>
</html>
"""

SCRIPT = b"""\"use strict\";
(function () {
  var PROTOCOL = "openid4vp-v1-signed";
  var button = document.getElementById("present");
  var status = document.getElementById("status");
  var member = null;

  function say(text) {
    status.textContent = text;
  }

  function offered() {
    if (typeof DigitalCredential === "undefined") {
      return false;
    }
    if (typeof DigitalCredential.userAgentAllowsProtocol !== "function") {
      return true;
    }
    try {
      return DigitalCredential.userAgentAllowsProtocol(PROTOCOL) !== false;
    } catch (e) {
      return false;
    }
  }

  async function fetchRequest(announce) {
    member = null;
    button.disabled = true;
    try {
      var answer = await fetch("/dc-api/request", {method: "POST", cache: "no-store", credentials: "omit"});
      if (!answer.ok) {
        say(answer.status === 503 ? "The verifier is busy. Reload the page in a few minutes."
                                  : "The verifier made no request. Reload the page to try again.");
        return;
      }
      member = await answer.json();
      button.disabled = false;
      if (announce) {
        say("Ready.");
      }
    } catch (e) {
      say("The verifier could not be reached. Reload the page to try again.");
    }
  }

  async function present() {
    if (member === null) {
      return;
    }
    var request = member;
    member = null;
    button.disabled = true;
    var credential = null;
    try {
      credential = await navigator.credentials.get({mediation: "required", digital: {requests: [request]}});
    } catch (e) {
      credential = null;
    }
    if (!credential || typeof credential.protocol !== "string") {
      say("No credential was presented.");
      await fetchRequest(false);
      return;
    }
    try {
      var answer = await fetch("/dc-api/response", {
        method: "POST", cache: "no-store", credentials: "omit",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({protocol: credential.protocol, data: credential.data})
      });
      say(answer.ok ? "Sent. The verifier has answered." : "The verifier refused the presentation.");
    } catch (e) {
      say("The answer could not be sent to the verifier.");
    }
    await fetchRequest(false);
  }

  if (!offered()) {
    say("This browser does not offer the Digital Credentials API, so it cannot present a credential here.");
    return;
  }
  button.addEventListener("click", function () {
    present();
  });
  fetchRequest(true);
})();
"""
