#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""lab/interop/negative-vectors/quotes.py: every quoted clause in vectors.json and mdoc-vectors.json
is found, word for word, in the section of the document it cites.

    python3 quotes.py --fetch DIR   # each document in MANIFEST into DIR, its SHA-256 checked
    python3 quotes.py --check DIR   # each quote in its cited section of the fetched documents

MANIFEST pins each cited document to an immutable source (the RFC Editor's text, the IETF
archive's text of the cited draft revision, the OpenID Foundation's final page) and its SHA-256.
A changed document fails --fetch, naming the URL: a person reads the change and re-pins it. A quote
missing from its section fails --check, naming the vector and the clause. A document that is not
there fails too. test_vectors.py checks offline that MANIFEST covers every cited reference.

A section is the cited one with its subsections: in the text form, from its heading at the left
margin to the next heading outside it, page breaks removed; in the HTML form, its <section>
element. Whitespace is collapsed and a line-end hyphen is tried joined both ways; a quote's
`...`-separated pieces must appear in order. ISO clauses are not quoted, so not checked.
"""
import hashlib
import html
import json
import os
import re
import ssl
import sys
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
FILES = ("vectors.json", "mdoc-vectors.json")
# ref prefix: (URL, SHA-256 of the bytes served, 2026-11-03)
MANIFEST = {
    "RFC 5280": ("https://www.rfc-editor.org/rfc/rfc5280.txt", "a2f2628c0a83b873fc4786abd921f9b2c02395954b655d190bf16b831633345d"),
    "RFC 7515": ("https://www.rfc-editor.org/rfc/rfc7515.txt", "ecbf84674118e62526511c1237e1deaa86aada86d25b247623a2a7e04ae62e40"),
    "RFC 7518": ("https://www.rfc-editor.org/rfc/rfc7518.txt", "9a9ae524b09ea700ad3f189bac115df95ba69af84b26ffdbe3cdfb8d2152b1fc"),
    "RFC 7519": ("https://www.rfc-editor.org/rfc/rfc7519.txt", "fecd930e9ccf2276b95c0017c6c4ff5d09352e4bc3c7629946447894e0f97248"),
    "RFC 8259": ("https://www.rfc-editor.org/rfc/rfc8259.txt", "61a5378f4255c720beb2a4b4a63b29540147c140f36988bf086291989b4cd2d7"),
    "RFC 8725": ("https://www.rfc-editor.org/rfc/rfc8725.txt", "737b7013a2495dcfd5481cf4c57c87e2455d537c4cec1140c9096a71fcef0812"),
    "RFC 9052": ("https://www.rfc-editor.org/rfc/rfc9052.txt", "01eecd7f646537600e7aad665b1fa581ce6ec33dae4ef4add0997aaf38cd0a45"),
    "RFC 9053": ("https://www.rfc-editor.org/rfc/rfc9053.txt", "3d470615875620375f8453ba25b8dce7e4d0271e76b0b79a46df34ccb2d56ab0"),
    "RFC 9360": ("https://www.rfc-editor.org/rfc/rfc9360.txt", "3dbe546adf08e309b429c8e71b2ee8384292fb8767338d3eb17d1c4e5adefc23"),
    "RFC 9864": ("https://www.rfc-editor.org/rfc/rfc9864.txt", "0f9b6dd26b3285fd9fe7f7e0a82e684d06512dee642703d51c6f88a7b0edaa2b"),
    "RFC 9901": ("https://www.rfc-editor.org/rfc/rfc9901.txt", "fd4cb79184162fa7ef95f4f63abab8ee6d03c9a04c19b8f83758946464b284eb"),
    "SD-JWT VC draft-19": ("https://www.ietf.org/archive/id/draft-ietf-oauth-sd-jwt-vc-19.txt",
                           "394c4640c581c301adaf24d1d356238e2c290b5c9e8b130141ca0e28732144fb"),
    "draft-ietf-oauth-status-list-21": ("https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-21.txt",
                                        "21e4867a01f73cee2ebc1408d150c87f77898c3d1549ebc25c80fa352221f846"),
    "OpenID4VP 1.0": ("https://openid.net/specs/openid-4-verifiable-presentations-1_0-final.html",
                      "08e635ea3563b192309c627382c281c81de176e94cdb5ffb11b13ac624f7e12e"),
    "HAIP 1.0": ("https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0-final.html",
                 "3996e0479d06b72d6d68668b8ae3cd39fddfc29ae9220c0c3fead7dc060ec4fb"),
}
_SECTION = re.compile(r"^s?([A-Z](?:\.\d+)+|\d+(?:\.\d+)*)\b")


def locate(ref):
    """(manifest key, section number) for a clause reference, or None when MANIFEST has no row."""
    for key in sorted(MANIFEST, key=len, reverse=True):
        if ref.startswith(key + " "):
            m = _SECTION.match(ref[len(key) + 1:])
            return (key, m.group(1)) if m else None
    return None


def file_name(key):
    return MANIFEST[key][0].rsplit("/", 1)[1]


def cited(docs):
    """[(vector id, ref, text)] for every quoted clause: the ISO ones are not quoted."""
    return [(v["id"], c["ref"], c["text"]) for doc in docs for v in doc["vectors"] for c in v.get("clauses", [])
            if not c["text"].startswith("not quoted:")]


def _collapse(text):
    return re.sub(r"\s+", " ", text).strip()


def text_section(raw, number):
    """The section `number` with its subsections from an RFC-style text document, page breaks
    removed; None when no heading at the left margin names it."""
    raw = raw.replace("\f", "\n")
    lines = [line for line in raw.splitlines()
             if not re.search(r"\[Page \d+\]\s*$", line) and not re.match(r"^(RFC \d+|Internet-Draft)\s{2,}", line)]
    heading = re.compile(r"^(?:Appendix )?([A-Z](?:\.\d+)*|\d+(?:\.\d+)*)\.\s+\S")
    start = None
    for k, line in enumerate(lines):
        m = heading.match(line)
        if not m:
            continue
        if start is None and m.group(1) == number:
            start = k
        elif start is not None and not (m.group(1) + ".").startswith(number + "."):
            return "\n".join(lines[start:k])
    return "\n".join(lines[start:]) if start is not None else None


def html_section(raw, number):
    """The <section> element for `number` (section-N or appendix-X), tags stripped; None if absent."""
    m = re.search(r'<section id="(?:section|appendix)-%s">' % re.escape(number), raw)
    if not m:
        return None
    depth, pos = 1, m.end()
    for tag in re.finditer(r"<(/?)section\b", raw[pos:]):
        depth += -1 if tag.group(1) else 1
        if depth == 0:
            body = raw[pos:pos + tag.start()]
            body = re.sub(r"(?is)<(script|style).*?</\1>", " ", body)
            return html.unescape(re.sub(r"(?s)<[^>]+>", " ", body)).replace("¶", " ")
    return None


def section(raw, number, is_html):
    return html_section(raw, number) if is_html else text_section(raw, number)


def found_in(quote, body):
    """Each `...`-separated piece of the quote in order in the section, whitespace collapsed, a
    line-end hyphen joined with and without it, backticks ignored."""
    joined = [_collapse(re.sub(r"(\w)-\s*\n\s*(\w)", r"\1-\2", body)),
              _collapse(re.sub(r"(\w)-\s*\n\s*(\w)", r"\1\2", body))]
    pieces = [p.strip() for p in _collapse(quote.replace("`", "")).split("...") if p.strip()]
    if not pieces:
        return False
    for text in joined:
        text = re.sub(r" ([,.;:)\]])", r"\1", re.sub(r"([(\[]) ", r"\1", text))
        at, ok = 0, True
        for piece in pieces:
            i = text.find(piece, at)
            if i < 0:
                ok = False
                break
            at = i + len(piece)
        if ok:
            return True
    return False


def quote_problems(docs, directory):
    """Every quote not found in its cited section, every reference MANIFEST cannot place, every
    section or document that is not there."""
    problems, cache = [], {}
    quotes = cited(docs)
    if not quotes:
        return ["no quoted clause in the files"]
    for vid, ref, text in quotes:
        place = locate(ref)
        if place is None:
            problems.append("%s: %s has no row in MANIFEST" % (vid, ref))
            continue
        key, number = place
        path = os.path.join(directory, file_name(key))
        if key not in cache:
            try:
                with open(path, encoding="utf-8") as fh:
                    cache[key] = fh.read()
            except OSError as e:
                cache[key] = None
                problems.append("%s: %s is not there (%s)" % (key, path, e.strerror))
        if cache[key] is None:
            continue
        body = section(cache[key], number, path.endswith(".html"))
        if body is None:
            problems.append("%s: %s: section %s is not in %s" % (vid, ref, number, file_name(key)))
        elif not found_in(text, body):
            problems.append("%s: %s: the quote is not in section %s: %r" % (vid, ref, number, text[:90]))
    return problems


def fetch(directory):
    """Each MANIFEST document into directory; [problems]: a hash that differs names the URL."""
    os.makedirs(directory, exist_ok=True)
    problems, context = [], ssl.create_default_context()
    for key, (url, digest) in sorted(MANIFEST.items()):
        data, errors = None, []
        # A slow server is retried, twice; a changed document is not: its hash decides at once.
        for attempt in range(3):
            try:
                with urllib.request.urlopen(url, timeout=90, context=context) as r:
                    data = r.read()
                break
            except OSError as e:
                errors.append(str(e))
                time.sleep(5 * (attempt + 1))
        if data is None:
            problems.append("%s: %s could not be fetched (%s)" % (key, url, "; ".join(errors)))
            continue
        got = hashlib.sha256(data).hexdigest()
        if got != digest:
            problems.append("%s: %s changed: SHA-256 %s, pinned %s; read the change, then re-pin" % (key, url, got, digest))
            continue
        with open(os.path.join(directory, file_name(key)), "wb") as fh:
            fh.write(data)
    return problems


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 2 or argv[0] not in ("--fetch", "--check"):
        print(__doc__, file=sys.stderr)
        return 2
    if argv[0] == "--fetch":
        problems = fetch(argv[1])
        done = "%d documents fetched, each SHA-256 as pinned" % len(MANIFEST)
    else:
        docs = []
        for name in FILES:
            with open(os.path.join(HERE, name)) as fh:
                docs.append(json.load(fh))
        problems = quote_problems(docs, argv[1])
        done = "%d quoted clauses, each in the section it cites" % len(cited(docs))
    for p in problems:
        print(p, file=sys.stderr)
    if problems:
        return 1
    print(done)
    return 0


if __name__ == "__main__":
    sys.exit(main())
