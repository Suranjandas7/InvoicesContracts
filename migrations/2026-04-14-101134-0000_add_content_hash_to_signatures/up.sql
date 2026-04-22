-- Add content_hash column to store the SHA-256 hash of contract content at signing time
-- This prevents undetected tampering of contract content after signing
ALTER TABLE contract_signatures ADD COLUMN content_hash TEXT NOT NULL DEFAULT '';

-- Create index for faster lookups (optional but good practice)
CREATE INDEX IF NOT EXISTS idx_signature_content_hash ON contract_signatures(content_hash);
