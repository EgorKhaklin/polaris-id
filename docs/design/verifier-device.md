# The verifier device

**Reader:** an engineer building the thing at the counter, or an assessor asking what a
"verified" light actually means. **Job:** what a device reads, what it decides, and what it
learns about the holder while doing it.

The reference implementation is
[`polaris_card/verifier_device.py`](../../polaris_card/verifier_device.py), and
[`scripts/polaris-verifier-device-drill.py`](../../scripts/polaris-verifier-device-drill.py)
runs it through the accept/reject matrix under real signatures on every push.

---

## 1. Three facts, kept apart

A device that reports only "accepted" teaches its operator nothing about what a refusal meant.
So a verdict carries three separate findings, and all three are required to accept:

| | What it establishes | What it does not |
|---|---|---|
| **Possession** | The card signed *this device's* challenge just now. | Nothing about whether the card is genuine or still valid. |
| **Authenticity** | The issuing authority signed this card object. | Nothing about whether the credential still stands. |
| **Authorization** | The credential is ACTIVE at an instant inside a window this device accepts. | Nothing about who is holding the card. |

**Possession alone is not acceptance.** A card that was revoked this morning still signs. The
device says so in as many words rather than returning a bare refusal.

## 2. What a signature cannot refuse

The reader's challenge and scope are both inside the card's signature, so a captured response
**relayed to a different device** fails on the scope and one **replayed later with a fresh
challenge** fails on the challenge.

Neither helps against a response **replayed to the same device**. The signature over that
challenge is perfectly valid the second time; nothing about the bytes says they have been seen
before. Only the device remembering its own outstanding challenges refuses that, so it does:
each challenge is answered exactly once, and a second attempt is refused with the reason.

A presentation refused for the *wrong scope* does not consume the challenge. Otherwise an
attacker could burn the challenges an honest holder is about to use, which is a denial of
service against the exchange rather than an attack on it.

## 3. The tension this row found

**A P3.6 status assertion signs the `token_value` in the clear**, because that is what binds it
to a credential. So a device that checks authorization offline **learns the stable credential
identifier**, and two such devices can tell they saw the same person.

The card's key mode gives a per-verifier pairwise handle and gives up nothing. But nothing
binds that handle to a status assertion, so a device using key mode alone cannot check
authorization offline at all.

That is a property of the protocol, not of any device, and pretending otherwise would let
"offline verification" quietly also mean "and everyone who does it can link you". So every
verdict carries `linkability`:

| Value | Meaning |
|---|---|
| `pairwise` | The device learned a handle scoped to itself and nothing more. |
| `credential-linkable` | The device learned a stable credential identifier. |
| `unknown` | Nothing was established. |

**It is recorded before the assertion is verified, and that ordering is the point.** The device
read the token value the moment it held the assertion. A failed verification does not
un-disclose an identifier, so reporting linkability only on success would be accounting for
what the device accepted rather than for what it learned.

**Closing it** means a status assertion keyed to something other than the token value. The
card's `credential_ref` would stop a device learning the value the API accepts, but it is still
stable across devices, so it buys confidentiality rather than unlinkability. Genuine offline
unlinkability is the epoch membership proof (P9.3), and no fielded secure element computes one:
that path needs the holder's phone.

## 4. The transports, and the QR ceiling

**NFC** is the card's own APDU interface (P4.2). The device drives SELECT, the holder enters a
PIN at a pinpad, and the device asks for a signed challenge and, if it wants authenticity, the
card object.

**QR** is the holder's phone, because a card has no screen. The device displays
`PCQ1:<scope>:<challenge>`; the phone drives the card and displays
`PCR1:<challenge>:<handle>:<signature>[:<card object>]` back.

Measured, in characters of base64url:

| Payload | Characters | Fits a QR code |
|---|---|---|
| Presentation only | 179 | yes, comfortably |
| ...with a classical-only card object | 495 | yes |
| ...with a dual-signature card object | **7,519** | **no, at any version** |

A version-40 QR code holds 4,296 alphanumeric characters at the lowest error correction, which
is already past what a phone screen renders and a handheld scanner reads in one go; the
practical ceiling is nearer 1,800.

**So the QR path cannot carry a post-quantum card object.** A device that needs post-quantum
authenticity needs NFC. A QR-only device can establish possession, and authenticity only for a
classical-only card. That is a hard constraint with a number behind it, not a preference.

## 5. What the device does not do

- **It does not interpret a PIN.** Both correct PINs answer `9000` and the device cannot tell
  them apart, which is the design ([card-profile.md](card-profile.md) §4). The duress signal is
  raised by the authority, which holds both slot public keys, on the online path only.
- **It does not re-implement verification.** The card object goes to the profile's own verifier
  and the status assertion to the detached one. A second implementation of a decision that
  already has one is two answers to a question with nothing saying which is right.
- **It does not choose its own freshness.** `max_window_seconds` is the operator's, and an
  assertion whose window is wider than the device accepts is refused even when it is valid.

## Proven by

`polaris_card/test_verifier_device.py` (27 tests) and
`scripts/polaris-verifier-device-drill.py` on every push: the accepting case under a real
ML-DSA status assertion, a replay to the same device, a relay to another, a revoked credential,
an expired window, an over-wide window, a tampered card object, possession without
authorization, the reported linkability of every mode, two devices failing to correlate one
card, the QR round trip, and the capacity numbers above. `check_verifier_device` pins them.
