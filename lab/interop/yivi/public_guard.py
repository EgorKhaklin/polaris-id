# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""What may not appear in the walk's PUBLIC files: anything that carries the holder's data.

A Yivi presentation carries the presenter's email address as a salted digest, its disclosures,
a key binding JWT and the holder's public key. Those stay in polaris-private. The public files
get the request, the verdicts (the disclosed domain withheld), the x5c shape and the refusals.

`problems(path, withheld=())` lists why a file may not be public, and is empty when it may be.
It reads the text, every JSON value in it, and every base64 or base64url token of 16 characters
or more, decoded and read again, gzip unpacked wherever its magic appears, up to MAX_DEPTH
decodings; content still text or gzip past that bound is refused rather than passed, and so is
any gzip at all, and gzip that does not unpack within MAX_GUNZIP bytes. It refuses:
  - an SD-JWT (an issuer JWT followed by `~`), or a disclosure (a base64url JSON array of salt,
    name and value);
  - a key binding JWT (`typ` kb+jwt) or an issuer-signed credential (`typ` dc+sd-jwt or
    vc+sd-jwt);
  - a `cnf` member (the holder key), an `_sd` digest list, or an `email` member, whatever its
    value;
  - an email address;
  - any of the `withheld` values (such as the disclosed domain, read from the private capture
    by the caller at check time and never written into the tree), in any case.
Binary that is not text or gzip is read for an email address and the withheld values only,
and a file that is not UTF-8 text is refused. Also opened: base64 wrapped onto lines (each run
of base64-only lines is joined), percent-encoding (the text is read again unquoted), a token
shifted off the base64 grid by a prefix (for the email and withheld checks), and a withheld
value split across a JSON document's strings. Also refused: a JWE, an `sd_hash` member (a key
binding JWT without a `typ`), and an email address at an IP literal.
OUT OF SCOPE, and not written by walk.py: an @ written as the JSON escape \\u0040 in a file that
is not JSON, a `typ` such as application/dc+sd-jwt, hex encodings, and a bare JWK that is not
under `cnf` (the verifier's request object carries its own encryption JWK).
The verifier's own request object passes: its `client_metadata.jwks` key is the verifier's
per-request encryption key, not the holder's.
"""
import base64
import binascii
import json
import pathlib
import re
import urllib.parse
import zlib

_COMPACT = re.compile(r"[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")
_SDJWT = re.compile(r"[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+~")
_TOKEN = re.compile(r"[A-Za-z0-9+/_-]{16,}={0,2}")
_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@(?:[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}"
                    r"|\[[0-9A-Fa-f:.]+\])")
_JWE = re.compile(r"[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{8,}")
_B64_LINE = re.compile(r"[A-Za-z0-9+/]{4,}={0,2}")
_EMAIL_MEMBER = re.compile(r"""["']email["']\s*:""")
_FORBIDDEN_TYP = {"kb+jwt", "dc+sd-jwt", "vc+sd-jwt"}
_FORBIDDEN_KEYS = {"cnf": "a cnf member (the holder key)", "_sd": "an _sd digest list",
                   "...": "an array digest member", "email": "an email member",
                   "sd_hash": "an sd_hash member (a key binding JWT's)"}
MAX_DEPTH = 4
MAX_GUNZIP = 1 << 20
GZIP_MAGIC = b"\x1f\x8b"


def _decode(token):
    """The bytes a base64 or base64url token decodes to, or None."""
    text = token.rstrip("=").replace("-", "+").replace("_", "/")
    try:
        return base64.b64decode(text + "=" * (-len(text) % 4), validate=True)
    except (binascii.Error, ValueError):
        return None


def _json(raw):
    try:
        return json.loads(raw)
    except (ValueError, UnicodeDecodeError, RecursionError):
        return None


def _is_disclosure(value, min_salt=16):
    """[salt, name, value] or, for an array element, [salt, value]: the salt a base64url string,
    of 16 characters or more inside a JSON document (SD-JWT section 4.2.1 has it 128 bits or
    more), which a list of algorithm names such as ["A128GCM", "A256GCM"] is not. A token that
    decodes to exactly such an array is a disclosure whatever its salt (min_salt=1)."""
    return (isinstance(value, list) and len(value) in (2, 3) and isinstance(value[0], str)
            and len(value[0]) >= min_salt
            and re.fullmatch(r"[A-Za-z0-9_-]+", value[0]) is not None
            and (len(value) == 2 or isinstance(value[1], str)))


def _strings(value):
    """Every string value in a JSON document, in document order."""
    if isinstance(value, dict):
        for item in value.values():
            yield from _strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from _strings(item)
    elif isinstance(value, str):
        yield value


def _base64_line_runs(text):
    """Each run of two or more lines that are base64 and nothing else, joined: what
    base64.encodebytes and MIME write, 76 characters to a line."""
    run = []
    for line in text.splitlines() + [""]:
        if _B64_LINE.fullmatch(line.strip()):
            run.append(line.strip())
            continue
        if len(run) >= 2:
            yield "".join(run)
        run = []


class _Scan:
    def __init__(self, withheld):
        self.withheld = [w.lower() for w in withheld if w]
        self.found = set()

    def add(self, where, what):
        self.found.add("%s: %s" % (where, what))

    def values(self, text, where):
        """The two checks that also apply to bytes that are not text."""
        if _EMAIL.search(text):
            self.add(where, "an email address")
        low = text.lower()
        if any(w in low for w in self.withheld):
            self.add(where, "a withheld value")

    def walk(self, value, where, depth):
        if isinstance(value, dict):
            for key, item in value.items():
                if key in _FORBIDDEN_KEYS:
                    self.add(where, _FORBIDDEN_KEYS[key])
                self.text(str(key), where, depth)
                self.walk(item, "%s.%s" % (where, key), depth)
        elif isinstance(value, list):
            if _is_disclosure(value) and depth > 0:
                self.add(where, "a disclosure (a base64url [salt, name, value] array)")
            for i, item in enumerate(value):
                self.walk(item, "%s[%d]" % (where, i), depth)
        elif isinstance(value, str):
            self.text(value, where, depth)

    def text(self, text, where, depth):
        self.values(text, where)
        if _EMAIL_MEMBER.search(text):
            self.add(where, "an email member")
        if _SDJWT.search(text):
            self.add(where, "an SD-JWT (an issuer JWT followed by ~)")
        for match in _COMPACT.finditer(text):
            header = _json(_decode(match.group(0).split(".", 1)[0]) or b"")
            if isinstance(header, dict) and str(header.get("typ", "")).lower() in _FORBIDDEN_TYP:
                self.add(where, "a JWT of typ %s" % header.get("typ"))
        for match in _JWE.finditer(text):
            header = _json(_decode(match.group(0).split(".", 1)[0]) or b"")
            if isinstance(header, dict) and "enc" in header:
                self.add(where, "a JWE (an encrypted response)")
        for match in _TOKEN.finditer(text):
            token = match.group(0)
            raw = _decode(token)
            if raw:
                self.data(raw, where + "<decoded>", depth + 1)
            # The same token read from its second, third and fourth character, for a value
            # encoded after a prefix that shifts it off the 4-character grid; read for an email
            # address and the withheld values only.
            for skip in (1, 2, 3):
                shifted = _decode(token[skip:])
                if shifted:
                    self.values(shifted.decode("latin-1"), where + "<decoded+%d>" % skip)
        for joined in _base64_line_runs(text):
            raw = _decode(joined)
            if raw:
                self.data(raw, where + "<joined lines>", depth + 1)
        if "%" in text:
            unquoted = urllib.parse.unquote(text)
            if unquoted != text:
                if depth >= MAX_DEPTH:
                    self.add(where, "content encoded deeper than the decode bound (%d)" % MAX_DEPTH)
                else:
                    self.text(unquoted, where + "<unquoted>", depth + 1)

    def data(self, raw, where, depth):
        """Bytes a token decoded to, or a file's: gunzipped when gzip, read again when text, and
        refused when they are still text or gzip past the decode bound."""
        is_gzip = raw[:2] == GZIP_MAGIC
        if depth > MAX_DEPTH:
            if is_gzip or _utf8(raw) is not None:
                self.add(where, "content encoded deeper than the decode bound (%d)" % MAX_DEPTH)
            else:
                self.values(raw.decode("latin-1"), where)
            return
        if is_gzip:
            self.add(where, "gzip-compressed content")
            unpacked = _gunzip(raw)
            if unpacked is None:
                self.add(where, "gzip that does not decompress within %d bytes" % MAX_GUNZIP)
                return
            self.data(unpacked, where + "<gunzipped>", depth + 1)
            return
        decoded = _utf8(raw)
        if decoded is None:
            self.values(raw.decode("latin-1"), where)
            return
        doc = _json(decoded)
        if _is_disclosure(doc, min_salt=1 if depth > 0 else 16):
            self.add(where, "a disclosure (a base64url [salt, name, value] array)")
        if doc is not None:
            self.walk(doc, where, depth)
            # A withheld value split across strings ({"a": "secretdom", "b": "ain.nl"}).
            joined = "".join(_strings(doc)).lower()
            if any(w in joined for w in self.withheld):
                self.add(where, "a withheld value (across its strings)")
        self.text(decoded, where, depth)


def _utf8(raw):
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _gunzip(raw):
    """The decompressed bytes, or None when they do not decompress, or not within MAX_GUNZIP."""
    try:
        inflater = zlib.decompressobj(16 + zlib.MAX_WBITS)
        out = inflater.decompress(raw, MAX_GUNZIP)
    except zlib.error:
        return None
    if inflater.unconsumed_tail or not inflater.eof:
        return None
    return out


def problems(path, withheld=()):
    """Why the file at `path` may not be public; empty when it may be."""
    path = pathlib.Path(path)
    raw = path.read_bytes()
    scan = _Scan(withheld)
    if _utf8(raw) is None:
        scan.add(path.name, "not UTF-8 text, so it is not read as public")
    scan.data(raw, path.name, 0)
    return sorted(scan.found)


def check_dir(directory, withheld=()):
    """Every problem in every file under `directory`. A directory that does not exist, or holds no
    file, is a problem too: a check that read nothing must not read as a pass."""
    directory = pathlib.Path(directory)
    if not directory.is_dir():
        return ["%s: the directory does not exist, so nothing was checked" % directory]
    files = [p for p in sorted(directory.rglob("*"))
             if p.is_file() and "__pycache__" not in p.parts]
    if not files:
        return ["%s: the directory holds no file, so nothing was checked" % directory]
    out = []
    for path in files:
        out.extend(problems(path, withheld))
    return out
