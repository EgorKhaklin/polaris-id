# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""age_page.py -- the page `serve(age_origin=...)` answers at /age/, and its script.

The page asks a wallet, through the browser's Digital Credentials API, for one fact: whether the
credential says its holder is N or over. The script fetches a signed request from /age/request,
hands it to `navigator.credentials.get` when the button is pressed, posts what the wallet answers
to /age/response, and shows the answer that comes back: "The credential says: N or over.", "The
credential says: under N." or "Could not check." Every other outcome (a browser without the API
or without `openid4vp-v1-signed`, a declined request, a failed fetch) shows "Could not check.",
and only the listener's answer shows anything else.

It runs under `default-src 'none'; script-src 'self'; connect-src 'self'`, as the /dc-api/ page
does: no inline script, no event handler attribute, no style and no other origin. Its fetches are
POSTs, which no cache answers, and the listener marks every answer `no-store`.
"""

import html

from .age import COULD_NOT_CHECK, answer_over, answer_under

_PAGE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Does the credential say {over}?</title>
<script src="/age/app.js" defer></script>
</head>
<body>
<main>
<h1>Does the credential say {over}?</h1>
<p>This page asks your wallet for one fact from a credential: whether it says its holder is {over}.
It shows one of three answers: &quot;The credential says: {over}.&quot;, &quot;The credential says: {under}.&quot;
or &quot;Could not check.&quot;</p>
<p>It reads credentials issued under these roots:</p>
<ul>
{roots}
</ul>
<p><button id="ask" type="button" disabled>Ask the wallet</button></p>
<p id="status" role="status" aria-live="polite">Preparing a request.</p>
</main>
</body>
</html>
"""


def page(age, labels):
    """The page for `age`, listing the roots it trusts by `labels`, escaped."""
    return _PAGE.format(over=answer_over(age), under=answer_under(age),
                        roots="\n".join("<li>%s</li>" % html.escape(label) for label in labels)).encode("utf-8")


SCRIPT = ("""\"use strict\";
(function () {
  var PROTOCOL = "openid4vp-v1-signed";
  var COULD_NOT_CHECK = "Could not check.";
  var NO_ANSWER = "%s";
  var button = document.getElementById("ask");
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
    return DigitalCredential.userAgentAllowsProtocol(PROTOCOL) !== false;
  }

  async function fetchRequest(announce) {
    member = null;
    button.disabled = true;
    try {
      var answer = await fetch("/age/request", {method: "POST", credentials: "omit"});
      if (!answer.ok) {
        say(COULD_NOT_CHECK);
        return;
      }
      member = await answer.json();
      button.disabled = false;
      if (announce) {
        say("Ready.");
      }
    } catch (e) {
      say(COULD_NOT_CHECK);
    }
  }

  async function ask() {
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
      say(COULD_NOT_CHECK);
      await fetchRequest(false);
      return;
    }
    if (!credential || typeof credential.protocol !== "string") {
      say(COULD_NOT_CHECK);
      await fetchRequest(false);
      return;
    }
    try {
      var answer = await fetch("/age/response", {
        method: "POST", credentials: "omit",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({protocol: credential.protocol, data: credential.data})
      });
      var said = answer.ok ? (await answer.json()).answer : null;
      if (typeof said !== "string" || said === NO_ANSWER) {
        say(COULD_NOT_CHECK);
      } else {
        say("The credential says: " + said + ".");
      }
    } catch (e) {
      say(COULD_NOT_CHECK);
    }
    await fetchRequest(false);
  }

  try {
    if (!offered()) {
      say(COULD_NOT_CHECK);
      return;
    }
  } catch (e) {
    say(COULD_NOT_CHECK);
    return;
  }
  button.addEventListener("click", function () {
    ask();
  });
  fetchRequest(true);
})();
""" % COULD_NOT_CHECK).encode("utf-8")
