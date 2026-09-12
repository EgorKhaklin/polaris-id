-- ============================================================================
-- 2026-09-12-003-app-user-events.down.sql
--
-- Reverses v9.443: the operator-account table goes back to having no trigger on it.
--
-- LOSSY, and loud about it. Dropping AppUserEvent discards the record of who was
-- given an account, who was promoted to admin, who was reactivated after being
-- disabled, who was moved between authorities, and whose hardware-key deadline was
-- pushed further away, along with the reasons given. AuthAuditLog holds none of that:
-- it records what the APPLICATION chose to write, so an UPDATE made in psql leaves it
-- empty.
--
-- Running this also removes the rule that those five changes must state a reason.
-- After it, promoting an auditor to admin succeeds silently again.
-- ============================================================================

DROP TRIGGER IF EXISTS trg_app_user_audited ON AppUser;
DROP TRIGGER IF EXISTS trg_app_user_guarded ON AppUser;
DROP TRIGGER IF EXISTS trg_app_user_event_append_only ON AppUserEvent;
DROP FUNCTION IF EXISTS record_app_user_change();
DROP FUNCTION IF EXISTS guard_app_user_change();
DROP FUNCTION IF EXISTS _app_user_widens(TEXT, AppUser, AppUser);
DROP FUNCTION IF EXISTS _app_user_rescopes(TEXT, AppUser, AppUser);
DROP FUNCTION IF EXISTS _app_user_role_rank(TEXT);

-- The append-only guard is gone, so the table can be dropped. This is the loss.
DROP TABLE IF EXISTS AppUserEvent;
