"""polaris_web/proofing.py - identity proofing and the assurance it supports (roadmap P4.4).

Polaris could issue a credential and had no way to say how the person was proven to be who
they claimed. `EnrollmentStatusEvent` recorded that enrollment happened; nothing recorded what
it rested on. That gap is why an assurance level could not be asserted honestly, and it is what
the NIST 800-63-4 mapping (P6.2) was blocked on.

TWO RULES SHAPE THIS MODULE.

THE LEVEL IS DERIVED, NEVER ASSERTED. An enrollment does not get to claim IAL2 because someone
typed IAL2. `derive_ial` takes the evidence actually recorded and returns the level that
evidence supports; recording a level above it is refused. An assurance level an operator can
type in is not an assurance level, it is a label, and every relying party downstream would be
trusting the label.

THE RECORD SAYS WHAT WAS ESTABLISHED, NEVER WHAT WAS PRESENTED. A row says that a piece of
STRONG evidence of type PASSPORT was validated by one method and bound to the applicant by
another. It does not carry the document number, a scan, an expiry date, or a biometric
template. That is enough to justify a level and not enough to reconstruct a person's documents,
and the difference is the whole reason an enrollment archive is not a second identity database
sitting behind the first. Forbidden fields are refused BY NAME, as everywhere else in this
tree, because a vocabulary that happens not to include a field stops excluding it the day
somebody adds one.

The strength and combination rules implement the published NIST SP 800-63A evidence table. They
are a reading of a public standard rather than an authority's policy: an authority may require
more, never less, and the full control-by-control mapping is P6.2. Where 800-63A speaks of
"identity evidence", this module records only its classification.

See docs/design/identity-proofing.md.
"""
from __future__ import annotations

# The evidence strengths 800-63A defines, weakest first. UNACCEPTABLE is recorded rather than
# dropped: an authority that looked at something and rejected it has made a finding, and a
# record that silently omits rejected evidence cannot be audited for what was considered.
STRENGTHS = ("UNACCEPTABLE", "WEAK", "FAIR", "STRONG", "SUPERIOR")
_RANK = {s: i for i, s in enumerate(STRENGTHS)}

# How a piece of evidence was checked to be genuine, and how it was bound to the person in
# front of you. Two different questions: a genuine passport belonging to somebody else passes
# the first and fails the second.
VALIDATION_METHODS = ("NONE", "VISUAL_INSPECTION", "PHYSICAL_SECURITY_FEATURES",
                      "DIGITAL_SIGNATURE_CHECK", "ISSUING_SOURCE_CONFIRMATION")
VERIFICATION_METHODS = ("NONE", "PHYSICAL_COMPARISON", "BIOMETRIC_COMPARISON",
                        "ENROLLMENT_CODE", "KNOWLEDGE_BASED")

#: THE CEILING EACH VERIFICATION METHOD PUTS ON THE EVIDENCE IT VERIFIED (v9.395).
#:
#: Validation asks whether a document is genuine. Verification asks whether it is THIS
#: person's, and the methods are not interchangeable at that job. Until v9.395 they were:
#: any method that was not NONE let evidence contribute its full nominal strength, so a
#: passport "verified" by posting a code to the address on it counted exactly as much as
#: one verified against the face of the person holding it. One SUPERIOR is IAL2, so that
#: single record produced an IAL2 enrollment.
#:
#: ENROLLMENT_CODE proves somebody at that address received a letter. It is real evidence
#: -- an attacker needs physical control of a channel -- and it is not evidence that the
#: applicant is the document's holder. Worse, the address is exactly what a controlling
#: household, a care setting or a monitored shelter takes from somebody, which is the same
#: population the trusted-referee path exists for.
#:
#: KNOWLEDGE_BASED is weaker still: the answers live in credit files and breach dumps, so
#: the barrier is a database rather than a mailbox.
#:
#: Methods absent from this mapping have no ceiling. A biometric compared to the person in
#: front of you is the binding the whole step is for.
VERIFICATION_CEILING = {
    "ENROLLMENT_CODE": "FAIR",
    "KNOWLEDGE_BASED": "WEAK",
}

# Where the applicant was when this happened. IAL3 requires in-person or a supervised remote
# session; the distinction is not a formality, because an unsupervised remote session is one an
# attacker can run against a coerced or absent applicant.
PRESENCE = ("REMOTE_UNSUPERVISED", "REMOTE_SUPERVISED", "IN_PERSON")

IAL_LEVELS = ("IAL1", "IAL2", "IAL3")

# Refused by name. See the module docstring.
FORBIDDEN_EVIDENCE_FIELDS = frozenset({
    "document_number", "passport_number", "license_number", "ssn", "national_id_number",
    "scan", "image", "photo", "portrait", "document_image",
    "biometric_template", "template", "minutiae", "face_embedding", "iris_code",
    "date_of_birth", "dob", "address", "mothers_maiden_name", "security_answers",
})

EVIDENCE_FIELDS = ("evidence_type", "strength", "validation_method", "verification_method",
                   "issuing_authority_name", "validated", "verified")


class ProofingRefused(ValueError):
    """The evidence or the claimed level would put something untrue into the record."""


def _rank(strength):
    if strength not in _RANK:
        raise ProofingRefused("unknown evidence strength: %r (accepted: %s)"
                              % (strength, ", ".join(STRENGTHS)))
    return _RANK[strength]


def check_evidence(evidence: dict) -> dict:
    """Validate one piece of evidence for recording. Returns it, or refuses.

    The forbidden-field check runs FIRST and stands on its own. If it ran after the vocabulary
    check, a document number would be refused merely for being unknown, and the guard would
    vanish the day somebody widened the vocabulary."""
    forbidden = sorted(set(evidence) & FORBIDDEN_EVIDENCE_FIELDS)
    if forbidden:
        raise ProofingRefused(
            "refusing to record %s on an enrollment: the record says what was ESTABLISHED, "
            "never what was presented. Keeping the document itself would make the enrollment "
            "archive a second identity database behind the first" % ", ".join(forbidden))
    unknown = sorted(set(evidence) - set(EVIDENCE_FIELDS))
    if unknown:
        raise ProofingRefused("unknown evidence fields: %s (the vocabulary is closed)"
                              % ", ".join(unknown))
    for field in ("evidence_type", "strength", "validation_method", "verification_method"):
        if not evidence.get(field):
            raise ProofingRefused("a piece of evidence needs %s" % field)
    _rank(evidence["strength"])
    if evidence["validation_method"] not in VALIDATION_METHODS:
        raise ProofingRefused("unknown validation method: %r" % evidence["validation_method"])
    if evidence["verification_method"] not in VERIFICATION_METHODS:
        raise ProofingRefused("unknown verification method: %r"
                              % evidence["verification_method"])
    return evidence


def effective_strength(evidence: dict) -> str:
    """The strength a piece of evidence ACTUALLY contributes.

    Evidence that was not validated contributes nothing: a passport nobody checked is a
    claim, not evidence. Evidence that was validated but not verified to the applicant also
    contributes nothing, because a genuine document belonging to somebody else is exactly the
    attack that step exists to stop. Recording the nominal strength and quietly counting it
    anyway is how an IAL2 enrollment ends up resting on a photocopy.

    AND HOW IT WAS VERIFIED CAPS IT. The methods are not interchangeable: a posted code
    proves somebody at an address opened a letter, knowledge-based answers prove access to
    a credit file, and a biometric comparison proves the document belongs to the person in
    the room. Counting all three at the document's nominal strength is the same error one
    level down -- see VERIFICATION_CEILING."""
    check_evidence(evidence)
    if not evidence.get("validated") or not evidence.get("verified"):
        return "UNACCEPTABLE"
    if evidence["validation_method"] == "NONE" or evidence["verification_method"] == "NONE":
        return "UNACCEPTABLE"
    # A weak binding to the applicant caps what the evidence contributes, however strong
    # the document itself is. A genuine passport verified by a posted code is a genuine
    # passport and an unproven claim that it is this person's.
    ceiling = VERIFICATION_CEILING.get(evidence["verification_method"])
    if ceiling is not None and _rank(evidence["strength"]) > _rank(ceiling):
        return ceiling
    return evidence["strength"]


def derive_ial(evidence_list, *, presence="REMOTE_UNSUPERVISED", biometric_collected=False):
    """The identity assurance level the recorded evidence supports. Never what was claimed.

    The combinations are 800-63A's: IAL2 wants one SUPERIOR, or two STRONG, or one STRONG with
    two FAIR; IAL3 wants two SUPERIOR, or one SUPERIOR with one STRONG, or two STRONG with one
    FAIR, AND an in-person or supervised-remote session, AND a biometric collected.

    IAL1 is the floor and means self-asserted: it is what a person gets when the evidence does
    not support more, and it is not a failure. Returning IAL1 rather than raising matters,
    because an authority that must record SOMETHING will otherwise record the level it wanted."""
    if presence not in PRESENCE:
        raise ProofingRefused("unknown presence: %r (accepted: %s)"
                              % (presence, ", ".join(PRESENCE)))
    counts = dict.fromkeys(STRENGTHS, 0)
    for evidence in evidence_list:
        counts[effective_strength(evidence)] += 1
    superior, strong, fair = counts["SUPERIOR"], counts["STRONG"], counts["FAIR"]

    supervised = presence in ("IN_PERSON", "REMOTE_SUPERVISED")
    ial3_evidence = (superior >= 2
                     or (superior >= 1 and strong >= 1)
                     or (strong >= 2 and fair >= 1))
    if ial3_evidence and supervised and biometric_collected:
        return "IAL3"
    if (superior >= 1 or strong >= 2 or (strong >= 1 and fair >= 2)):
        return "IAL2"
    return "IAL1"


def why_not_higher(evidence_list, *, presence="REMOTE_UNSUPERVISED",
                   biometric_collected=False) -> str:
    """One sentence an operator can act on, for why the level is not higher.

    An enrollment that lands at IAL1 with no explanation is one the operator will re-run
    blindly. This says what is missing rather than what is wrong."""
    level = derive_ial(evidence_list, presence=presence, biometric_collected=biometric_collected)
    if level == "IAL3":
        return "the evidence, the session and the biometric all support IAL3"
    counts = dict.fromkeys(STRENGTHS, 0)
    nominal = dict.fromkeys(STRENGTHS, 0)
    for evidence in evidence_list:
        counts[effective_strength(evidence)] += 1
        nominal[evidence["strength"]] += 1
    discounted = sum(nominal[s] for s in ("SUPERIOR", "STRONG", "FAIR")) - sum(
        counts[s] for s in ("SUPERIOR", "STRONG", "FAIR"))
    if level == "IAL2":
        missing = []
        if not (counts["SUPERIOR"] >= 2 or (counts["SUPERIOR"] >= 1 and counts["STRONG"] >= 1)
                or (counts["STRONG"] >= 2 and counts["FAIR"] >= 1)):
            missing.append("stronger evidence")
        if presence not in ("IN_PERSON", "REMOTE_SUPERVISED"):
            missing.append("an in-person or supervised session")
        if not biometric_collected:
            missing.append("a biometric")
        return "IAL3 would need " + ", ".join(missing)
    parts = ["IAL2 would need one SUPERIOR piece, or two STRONG, or one STRONG and two FAIR"]
    if discounted:
        parts.append("%d piece(s) contributed nothing because they were not validated AND "
                     "verified to the applicant" % discounted)
    return "; ".join(parts)


def check_claimed_ial(claimed, evidence_list, *, presence="REMOTE_UNSUPERVISED",
                      biometric_collected=False) -> str:
    """Refuse a claimed level the evidence does not support. Returns the supported level.

    A level BELOW what the evidence supports is allowed: an authority may hold itself to less
    than it could claim, and refusing that would push operators to overstate in order to record
    anything at all."""
    if claimed not in IAL_LEVELS:
        raise ProofingRefused("unknown assurance level: %r" % claimed)
    supported = derive_ial(evidence_list, presence=presence,
                           biometric_collected=biometric_collected)
    if IAL_LEVELS.index(claimed) > IAL_LEVELS.index(supported):
        raise ProofingRefused(
            "this enrollment claims %s and its evidence supports %s. %s. An assurance level an "
            "operator can type in is a label, and every relying party downstream would be "
            "trusting the label rather than the proofing"
            % (claimed, supported,
               why_not_higher(evidence_list, presence=presence,
                              biometric_collected=biometric_collected)))
    return supported


# ---------------------------------------------------------------------------
# Biometric capture: an abstraction over vendors, and a wall against templates
# ---------------------------------------------------------------------------
BIOMETRIC_MODALITIES = ("FINGERPRINT", "FACE", "IRIS")


class BiometricCapture:
    """What a capture device is allowed to hand back: a modality, a quality score, a liveness
    result. Never a template, and there is no field for one.

    Vendor-neutral by construction rather than by intention: this class is the only shape the
    enrollment path accepts, so a vendor SDK is adapted to it at the edge and its own types
    never reach the record. The alternative, letting each vendor's blob through and promising
    not to store it, is a promise rather than a boundary.

    An authority that needs to MATCH a biometric later needs a template, and that is a
    different system with different retention, a different threat model and a different legal
    posture. Polaris binds a credential to a modality and records that a live capture met a
    quality bar; it does not become a biometric database in order to do it."""

    __slots__ = ("modality", "quality", "liveness_passed", "vendor")

    def __init__(self, modality, quality, liveness_passed, vendor=None):
        if modality not in BIOMETRIC_MODALITIES:
            raise ProofingRefused("unknown biometric modality: %r (accepted: %s)"
                                  % (modality, ", ".join(BIOMETRIC_MODALITIES)))
        if not isinstance(quality, (int, float)) or not 0 <= quality <= 100:
            raise ProofingRefused("quality must be a score from 0 to 100, got %r" % (quality,))
        self.modality = modality
        self.quality = float(quality)
        self.liveness_passed = bool(liveness_passed)
        self.vendor = str(vendor) if vendor else None

    def acceptable(self, minimum_quality=60.0) -> bool:
        """A capture counts toward IAL3 only if it is live and meets the bar.

        Liveness is not optional: a photograph of a face and a lifted fingerprint both produce
        excellent quality scores, and a capture pipeline that scored them without checking
        liveness would raise the recorded assurance of exactly the enrollments an attacker
        controls."""
        return self.liveness_passed and self.quality >= minimum_quality

    def as_record(self) -> dict:
        """What may be written down. Note what is not here."""
        return {"biometric_modality": self.modality,
                "biometric_quality": self.quality,
                "biometric_liveness_passed": self.liveness_passed}


# ---------------------------------------------------------------------------
# Recording, which is where the derivation stops being advice
# ---------------------------------------------------------------------------
def record_proofing(conn, individual_id, agency_id, evidence_list, *,
                    presence="REMOTE_UNSUPERVISED", capture=None, claimed_ial=None):
    """Write one proofing event and its evidence, in one transaction.

    The level written is the level the evidence supports. `claimed_ial` is what the operator
    believes it to be, and passing one that the evidence does not support is REFUSED rather
    than silently downgraded: an operator who thinks an enrollment reached IAL2 and is quietly
    recorded at IAL1 has been told nothing, and will make the same mistake on the next
    applicant.

    A capture that fails liveness or the quality bar does not count toward IAL3. It is still
    RECORDED, because an authority that attempted a capture and got a poor one has made a
    finding, and a record that omits it cannot be audited for what was tried."""
    for evidence in evidence_list:
        check_evidence(evidence)
    biometric_ok = bool(capture and capture.acceptable())
    supported = derive_ial(evidence_list, presence=presence,
                           biometric_collected=biometric_ok)
    if claimed_ial is not None:
        check_claimed_ial(claimed_ial, evidence_list, presence=presence,
                          biometric_collected=biometric_ok)

    with conn.cursor() as cur:
        cur.execute(
            "INSERT INTO EnrollmentProofing (individual_id, recorded_by_agency_id, presence, "
            "biometric_modality, biometric_quality, biometric_liveness_passed, derived_ial) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s) RETURNING proofing_id, recorded_at",
            (individual_id, agency_id, presence,
             capture.modality if capture else None,
             capture.quality if capture else None,
             capture.liveness_passed if capture else None,
             supported))
        row = cur.fetchone()
        proofing_id = row["proofing_id"] if hasattr(row, "keys") else row[0]
        if evidence_list:
            from psycopg2.extras import execute_values
            execute_values(
                cur,
                "INSERT INTO EnrollmentEvidence (proofing_id, evidence_type, strength, "
                "validation_method, verification_method, issuing_authority_name, validated, "
                "verified) VALUES %s",
                [(proofing_id, e["evidence_type"], e["strength"], e["validation_method"],
                  e["verification_method"], e.get("issuing_authority_name"),
                  bool(e.get("validated")), bool(e.get("verified")))
                 for e in evidence_list])
    conn.commit()
    return {"proofing_id": proofing_id, "derived_ial": supported,
            "biometric_counted": biometric_ok,
            "why_not_higher": why_not_higher(evidence_list, presence=presence,
                                             biometric_collected=biometric_ok)}


def current_ial(conn, individual_id):
    """The level the most recent proofing event supports, or None if never proofed.

    Deliberately the LATEST rather than the highest ever reached. An authority that re-proofs
    someone and finds less than it found before has learned something, and a record that kept
    the old high-water mark would be reporting a level nothing currently supports."""
    with conn.cursor() as cur:
        cur.execute("SELECT derived_ial FROM EnrollmentProofing WHERE individual_id = %s "
                    "ORDER BY recorded_at DESC, proofing_id DESC LIMIT 1", (individual_id,))
        row = cur.fetchone()
    if row is None:
        return None
    return row["derived_ial"] if hasattr(row, "keys") else row[0]


def evidence_for(conn, proofing_id):
    with conn.cursor() as cur:
        cur.execute("SELECT evidence_type, strength, validation_method, verification_method, "
                    "issuing_authority_name, validated, verified FROM EnrollmentEvidence "
                    "WHERE proofing_id = %s ORDER BY evidence_id", (proofing_id,))
        return cur.fetchall()
