# The wallet protocol surface (P8.6)

**Reader:** an engineer building a holder client, or an assessor asking what a Polaris wallet
must be able to say to a verifier and what Polaris deliberately does not build.

**Status:** shipped v9.327. `polaris-presentation/1` with stapled status, `polaris-qr/1`
framing, the wallet's `present --qr`, and the detached verifier's `--presentation` /
`--qr-frames`.

## The decision, restated

The wallet is a PROTOCOL, not a product. `scripts/polaris-wallet.py` is the reference holder
agent -- it holds a credential, presents it, proves membership in zero knowledge, signs a
document on the holder's behalf (P8.5) and logs in to a relying party (P8.4) -- and every
message it emits is specified so that any client can emit the same. Native mobile and
desktop clients, card and NFC middleware, and a WebAuthn browser bridge are product
engineering a reference implementation does not attempt; they follow this protocol when
someone builds them, and never lead it.

## The presentation

`polaris-presentation/1` is the unsigned wrapper a holder hands a verifier: the issuer-signed
credential, an optional stapled issuer-signed status assertion (fetched when connected, so
authorization is decidable with no connectivity at all), an optional ZK membership proof,
the context and disclosure level presented under, and an opaque presentation code. Its
authenticity lives entirely in the signed objects inside it. `verify_presentation` decides it
offline: credential authentic and (with anchors) issuer trusted; assertion authentic, fresh,
ACTIVE and **bound** to this credential -- the same token value and the same signing key, so
a stranger's or another credential's assertion buys nothing; the expected context, if any.
`usable_offline` is the conjunction. The presentation code is reported present or absent
and never interpreted: a duress presentation is indistinguishable at the verifier by design,
because the code is matched only by the issuer, out of sight.

## Transfer: QR and NFC

A credential is a post-quantum signature plus a key, about ten kilobytes as JSON, several
times what one QR symbol holds. `polaris-qr/1` compresses the canonical presentation,
base64url-encodes it, and splits it into frames `PLRS1/<total>/<index>/<digest>/<chunk>`,
each under a byte budget (1800 by default) and each naming the SHA3-256 of the whole
payload. A receiver takes frames in any order, tolerates duplicates, and refuses -- before it
parses anything -- frames naming different digests, a missing index, a conflicting
duplicate, or a reassembled payload whose digest does not match. The framing is transport
integrity only; it adds no authenticity, which is the point: nothing in the transfer layer
needs a key.

## What is out of scope, and why

- **A WebAuthn browser bridge.** Binding a presentation to a platform authenticator needs a
  holder key registered against the credential at enrollment. Polaris's model is
  issuer-centric on purpose -- the holder holds a credential, not a key pair, which is why
  document signing is notarial (P8.5) and login is by possession (P8.4). A holder-key binding
  is a future credential extension, not a wallet feature; the bridge waits on it.
- **Native clients and card middleware.** Product engineering, not a research problem, and
  not what a reference implementation on notional data should carry. The protocol above is
  what they would implement.

## What runs

`scripts/polaris-presentation-drill.py` (the `pqc-real` CI job) builds a real presentation
under real ML-DSA-65 keys and drives: usable offline; several frames under budget,
reassembled in any order; a missing frame, a mixed-in frame from another transfer, and an
altered chunk refused; an unbound, expired, revoked, and stranger-signed assertion refused;
no assertion not decidable; a wrong context refused; a presentation code present and never
interpreted; the wallet round trip (`enroll`, `present --qr --status-assertion`, decide with
`--qr-frames --issuer-anchor`); hostile input. The fuzzer holds `verify_presentation` and the
frame decoder total. `check_wallet_presentation` pins the surface, the duress opacity, the
wallet and CLI flags, the spec (section 3.14), the drill, and that this document records the
boundaries above -- with a detection test.

## Resource bounds (v9.335)

A decoder that is total on hostile input must also be resource-bounded, since a
compressible payload can expand a thousandfold. `decode_presentation_frames` bounds the
frame count (the format's 9,999), the compressed payload (512 KiB) and the inflated payload
(2 MiB), each checked before the work it guards, and inflates under an output limit so a
decompression bomb is refused at the limit rather than decompressed. The presentation drill
refuses a real bomb (64 MiB of zeros in some forty frames), an incompressible oversized
payload and a flood of frames, each in well under a second. The bounds are normative in the
wire spec.
