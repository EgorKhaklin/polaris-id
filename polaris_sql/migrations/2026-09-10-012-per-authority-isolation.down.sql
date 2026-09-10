-- Revert 012. The column is kept rather than dropped: an operator binding an administrator
-- recorded is a fact about that deployment, and dropping it silently unscopes every operator.
DROP POLICY IF EXISTS token_authority_isolation ON IdentityToken;
ALTER TABLE IdentityToken DISABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS verification_authority_isolation ON VerificationEvent;
ALTER TABLE VerificationEvent DISABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS lifecycle_authority_isolation ON TokenLifecycleEvent;
ALTER TABLE TokenLifecycleEvent DISABLE ROW LEVEL SECURITY;
