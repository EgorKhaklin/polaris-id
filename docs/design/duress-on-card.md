# Duress on the card

**Reader:** an engineer implementing a card applet or a pinpad, and a reviewer asking what
happens to the person holding the card. **Job:** how duress is entered, everything that must
look the same when it is, and an honest account of what this protects against and what it does
not.

The vocation above C1 to C10 says no person can be compelled to surrender their identity
against their will. [duress-codes.md](duress-codes.md) is that mechanism in the application.
This is the same mechanism at the physical layer, where the coercer is standing next to the
holder rather than reading a log.

---

## 1. The entry method

**A second PIN, of the same length as the first, entered at the same pinpad in the same way.**

Both PINs unlock the card. The normal PIN unlocks the normal key slot; the duress PIN unlocks
the duress slot. The card object carries only the normal slot's public key; the authority holds
both, and a presentation signed by the duress slot verifies against the authority's record and
raises a `DuressEvent`. The reader sees a well-formed, successful presentation either way.

**The two PINs must be the same length**, enforced at personalization. The PIN travels in the
data field of a `VERIFY` command, so its length is on the wire: a six-digit duress PIN beside a
four-digit normal one announces which class was entered to anyone watching the exchange,
without their needing to see the keypad at all.

**The two PINs must differ.** A card whose duress PIN equalled its normal one would produce a
presentation the *authority* could not tell apart either, and the authority is the one party
that has to.

### What was considered and not chosen

| Method | Why not |
|---|---|
| A prefix or suffix on the normal PIN (`1234` vs `1234#`) | The length changes, and length is on the wire. |
| A distinct finger for biometric capture | Capture quality varies per finger, so a duress presentation would have a different retry profile. The system also binds a biometric *type*, never a template. |
| A special sequence before entry (a long press, a double tap) | It happens at the pinpad, in front of the coercer, and takes visibly longer. |
| A silent timeout (enter nothing) | Indistinguishable from hesitation, so it fires by accident, and a coercer who knows the scheme reads any pause as a signal. |

A second PIN is the only one of these that costs the holder nothing observable.

## 2. Everything that must look the same

Indistinguishability is not one property, it is every observable. Each row is asserted
somewhere that runs.

| Observable | Kept identical by | Proven by |
|---|---|---|
| Status word | Both correct PINs answer `9000` | `polaris-card-emulator-drill.py` |
| Response shape and length | Fixed-length raw `r||s`, never DER | `test_emulator.py`, exact rather than sampled |
| Command sequence | The reader drives the same commands either way | `polaris-card-emulator-drill.py`, transcript compared position by position |
| Retry counter | Both correct PINs reset it identically | `test_emulator.py` |
| Blocking | A blocked card refuses *both* correct PINs alike | `test_emulator.py` |
| What is readable off the card | Only the normal slot's public key is in the card object | `polaris-card-profile-drill.py` |
| Whether a duress PIN is *enrolled* | The card always holds a duress comparand and always compares against it | `polaris-duress-timing-drill.py` |
| Time | Measured, both for the PIN check and for a whole presentation | `polaris-duress-timing-drill.py` |

### The one that was a defect

The card originally skipped the duress comparison when the holder had not enrolled a duress
PIN. That made **enrollment itself observable**: a coercer who could tell that a card has no
duress PIN would know that the PIN they had just watched was the real one.

Note the shape of that harm. It does not endanger the holder who skipped enrollment; it
endangers the ones who *did* enroll, by splitting the population into two classes a coercer can
distinguish. So a card now always holds a duress comparand: when no duress PIN is enrolled it
is an unguessable value of the same length beginning with a NUL, which a keypad cannot produce,
so the comparison always runs, always costs the same, and never matches.

This is the physical-layer twin of the rule in [card-profile.md](card-profile.md) §4 that every
card carries a duress *slot* whether or not a PIN is enrolled. Both exist so that the mechanism
says nothing about the individual.

## 3. What the timing drill claims, and what it will not

`scripts/polaris-duress-timing-drill.py` measures four pairs and reports each gap with the
resolution the run achieved. It judges them against **10 microseconds**, which is what a
coercer could plausibly observe through a reader: an NFC exchange runs in milliseconds and the
field's own jitter is tens of microseconds. Gaps of a few tens of *nanoseconds* are Python
object layout, and a drill that failed on those would be measuring the emulator rather than the
design.

**A right PIN and a wrong one do differ**, by around a hundred nanoseconds, and that is
measured and reported rather than asserted away. It is not a leak: the status word already
announces the difference, and it has to, because a holder who mistyped needs to be told.

**An emulator cannot establish that a real secure element is constant-time**, resists fault
injection, or keeps a key non-extractable. Those are properties of a certified part (P4.6). The
structural half is what carries over to an applet: both comparisons always run, and a comparand
always exists. Those are checked as properties rather than as text, because the first version
of that check pinned the exact wording of the original defect and duly missed a
differently-worded reintroduction of it.

## 4. Safety review

The mechanism signals. It does not prevent, and treating it as prevention is how it gets people
hurt.

**A coercer who knows the scheme exists.** They can demand a second presentation, or demand the
holder name their duress PIN, or simply not believe them. No card behaviour defeats this. What
the card buys is that the *first* presentation already reached the authority, and that nothing
about it looked unusual at the time.

**Recall under stress.** A duress PIN is used once, possibly years after it was chosen, under
the worst conditions a person will ever face. That argues for a memorable value and against a
long one, and it is why the length is the holder's normal PIN length rather than something
longer "for security". A holder who cannot recall it is in the position they would have been in
with no mechanism at all.

**Blocking under coercion.** Three wrong attempts block the card. Under coercion that reads as
defiance, which is precisely the danger. A duress PIN that unlocks *normally* is what avoids
it: the holder complies, visibly, and the card behaves.

**Offline, nothing is signalled.** There is nobody to signal to. The card must therefore behave
identically offline under either PIN and must not, for instance, decline to respond: a card
that behaved differently offline would tell the coercer which PIN was entered, which is worse
than having no mechanism. Stated also in [card-profile.md](card-profile.md) §4.

**A rare signal is a loud one.** If few holders enroll, a `DuressEvent` is unusual enough that
the *response* to it may itself expose the holder. That is an operational matter rather than a
card property, and it belongs in the authority's response procedure: the value of the mechanism
rises with adoption, and an authority that treats duress alerts as rare emergencies rather than
as a standing procedure will handle the first one badly.

**The holder cannot be told whether it worked.** By construction: any confirmation channel a
holder could check is a channel a coercer can watch them check.

## Proven by

`scripts/polaris-duress-timing-drill.py` and `scripts/polaris-card-emulator-drill.py` on every
push, `polaris_card/test_emulator.py` (the retry counter, the blocking, the exact response
length, the refusals at construction), and `check_duress_on_card`, which pins the entry-method
rules, the always-compare property as a property rather than as text, and this document's
statement of the limits.
