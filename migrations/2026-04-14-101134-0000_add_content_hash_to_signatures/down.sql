-- Remove content_hash column and its index
DROP INDEX IF EXISTS idx_signature_content_hash;
ALTER TABLE contract_signatures DROP COLUMN content_hash;
