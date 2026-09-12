-- ============================================================================
-- 2026-09-11-018-relying-party-events.down.sql
--
-- Reverses v9.425: relying-party decisions go back to being unrecorded.
--
-- LOSSY, and loud about it. Dropping RelyingPartyEvent discards the record of who
-- registered which outside organisation, who turned off the zero-knowledge step-up
-- its holders had to clear, and the reasons they gave. There is nowhere else that
-- information lives, because before v9.425 it was not written down at all.
--
-- Running this also removes the rule that a change weakening a relying party's
-- policy must state a reason. After it, `rp-policy --no-require-zk` succeeds
-- silently again.
-- ============================================================================

DROP TRIGGER IF EXISTS trg_relying_party_audited ON RelyingParty;
DROP TRIGGER IF EXISTS trg_rp_event_append_only ON RelyingPartyEvent;
DROP FUNCTION IF EXISTS record_relying_party_change();
DROP FUNCTION IF EXISTS _rp_weakens(TEXT, RelyingParty, RelyingParty);

-- The append-only guard is gone, so the table can be dropped. This is the loss.
DROP TABLE IF EXISTS RelyingPartyEvent;
