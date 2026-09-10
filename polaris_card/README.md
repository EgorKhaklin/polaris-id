# polaris_card

The physical layer: the on-card data model as a normative encoding, its reference codec, and
published test vectors.

| File | What it is |
|---|---|
| [`card_profile.py`](card_profile.py) | The normative encoder, decoder and offline verifier for the card object. Dependency-free: a card profile has to be implementable inside a secure element's toolchain and inside the detached verifier, so nothing here imports a crypto library and signature verification is passed in. |
| [`emulator.py`](emulator.py) | A software token: ISO 7816-4 APDUs with real status words, two PIN slots, a retry counter and a PUK. Everything downstream develops against this rather than against silicon that does not exist yet, which is why the interface is the one real silicon presents. |
| [`vectors/`](vectors/) | Published test vectors: `card-objects.json` (the encoding) and `apdu-exchanges.json` (the command bytes and the status-word protocol). An implementation that reproduces these agrees with this one; one that does not, does not. |
| [`make_vectors.py`](make_vectors.py) | Regenerates both vector files from the code, so they cannot drift from it. |
| [`test_card_profile.py`](test_card_profile.py) | The profile's own suite (27 tests). |
| [`test_emulator.py`](test_emulator.py) | The card's behaviour (33 tests), including a walk of the published APDU session against a real token. |

The specification and the reasoning are [docs/design/card-profile.md](../docs/design/card-profile.md).

Named `card_profile.py` rather than `profile.py` on purpose: `profile` is a standard-library
module, and a file with that name shadows it for any process that puts this directory on
`sys.path`.

The card emits a **fixed-length raw `r||s` signature**, never DER. That is what a secure
element returns, and it is what makes "a duress presentation is indistinguishable" an exact
statement rather than one you can only sample for: a DER signature's length varies per
signature, a fixed-length one does not vary at all. Readers wrap to DER on their own side
(`emulator.der_from_raw`).
