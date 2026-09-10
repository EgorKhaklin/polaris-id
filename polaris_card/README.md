# polaris_card

The physical layer: the on-card data model as a normative encoding, its reference codec, and
published test vectors.

| File | What it is |
|---|---|
| [`card_profile.py`](card_profile.py) | The normative encoder, decoder and offline verifier for the card object. Dependency-free: a card profile has to be implementable inside a secure element's toolchain and inside the detached verifier, so nothing here imports a crypto library and signature verification is passed in. |
| [`vectors/`](vectors/) | Published test vectors. An implementation that reproduces these bytes agrees with this one; one that does not, does not. |
| [`test_card_profile.py`](test_card_profile.py) | The profile's own suite. |

The specification and the reasoning are [docs/design/card-profile.md](../docs/design/card-profile.md).

Named `card_profile.py` rather than `profile.py` on purpose: `profile` is a standard-library
module, and a file with that name shadows it for any process that puts this directory on
`sys.path`.
