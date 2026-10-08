-- Reverts 2026-10-04-001. Dropping the table discards the instance's record of its chain
-- anchors; each anchor stays in its Bitcoin block, and its proof with whoever kept a copy.

DROP TABLE IF EXISTS ChainAnchor;
