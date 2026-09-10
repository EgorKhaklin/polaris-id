-- Down for 013. Dropping an audit-of-record table destroys the record of which cards were
-- personalized and under which keys, so this exists for a failed forward migration on an
-- empty table and not for routine use.
SET LOCAL lock_timeout = '3s';
SET LOCAL statement_timeout = '60s';

DROP TRIGGER IF EXISTS trg_card_personalization_append_only ON CardPersonalization;
DROP TABLE IF EXISTS CardPersonalization;
