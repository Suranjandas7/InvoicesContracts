use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};

/// Generate a new Ed25519 keypair
/// Returns (public_key_hex, private_key_hex)
pub fn generate_keypair() -> (String, String) {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();

    let private_key_hex = hex::encode(signing_key.to_bytes());
    let public_key_hex = hex::encode(verifying_key.to_bytes());

    (public_key_hex, private_key_hex)
}

/// Sign contract data with a private key
/// Returns hex-encoded signature
pub fn sign_contract(
    private_key_hex: &str,
    contract_id: &str,
    content_hash: &str,
    timestamp: &str,
) -> Result<String, String> {
    // Decode private key
    let private_key_bytes =
        hex::decode(private_key_hex).map_err(|e| format!("Invalid private key hex: {}", e))?;

    if private_key_bytes.len() != 32 {
        return Err("Private key must be 32 bytes".to_string());
    }

    let mut key_array = [0u8; 32];
    key_array.copy_from_slice(&private_key_bytes);

    let signing_key = SigningKey::from_bytes(&key_array);

    // Create message to sign
    let message = format!("{}:{}:{}", contract_id, content_hash, timestamp);

    // Sign the message
    let signature = signing_key.sign(message.as_bytes());

    Ok(hex::encode(signature.to_bytes()))
}

/// Verify a signature
pub fn verify_signature(
    public_key_hex: &str,
    signature_hex: &str,
    contract_id: &str,
    content_hash: &str,
    timestamp: &str,
) -> bool {
    // Decode public key
    let public_key_bytes = match hex::decode(public_key_hex) {
        Ok(bytes) => bytes,
        Err(_) => return false,
    };

    if public_key_bytes.len() != 32 {
        return false;
    }

    let mut key_array = [0u8; 32];
    key_array.copy_from_slice(&public_key_bytes);

    let verifying_key = match VerifyingKey::from_bytes(&key_array) {
        Ok(key) => key,
        Err(_) => return false,
    };

    // Decode signature
    let signature_bytes = match hex::decode(signature_hex) {
        Ok(bytes) => bytes,
        Err(_) => return false,
    };

    if signature_bytes.len() != 64 {
        return false;
    }

    let mut sig_array = [0u8; 64];
    sig_array.copy_from_slice(&signature_bytes);

    let signature = Signature::from_bytes(&sig_array);

    // Reconstruct message
    let message = format!("{}:{}:{}", contract_id, content_hash, timestamp);

    // Verify
    verifying_key.verify(message.as_bytes(), &signature).is_ok()
}

/// Generate a random 12-character verification code (format: AAAA-BBBB-CCCC)
pub fn generate_verification_code() -> String {
    use rand::Rng;
    const CHARSET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789"; // Removed ambiguous chars (0,O,I,1) for readability
    let mut rng = rand::thread_rng();

    let code: String = (0..12)
        .map(|_| {
            let idx = rng.gen_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect();

    // Format as AAAA-BBBB-CCCC
    format!("{}-{}-{}", &code[0..4], &code[4..8], &code[8..12])
}

/// Hash content using SHA-256, returns hex-encoded hash
pub fn hash_content(content: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(content.as_bytes());
    let result = hasher.finalize();
    hex::encode(result)
}

/// Generate final combined hash of all signatures
/// This is created when the last signature is added
/// Combines: contract content + all signature hashes + timestamps
pub fn generate_final_hash(
    contract_content: &str,
    signature_hashes: &[String],
    signed_at_timestamps: &[String],
    content_hashes: &[String],
) -> String {
    let mut combined = String::new();
    combined.push_str(contract_content);
    
    // Combine all signature data in order
    for i in 0..signature_hashes.len() {
        combined.push_str(&signature_hashes[i]);
        combined.push_str(&signed_at_timestamps[i]);
        combined.push_str(&content_hashes[i]);
    }
    
    hash_content(&combined)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let (public_key, private_key) = generate_keypair();
        assert_eq!(public_key.len(), 64); // 32 bytes = 64 hex chars
        assert_eq!(private_key.len(), 64);
    }

    #[test]
    fn test_sign_and_verify() {
        let (public_key, private_key) = generate_keypair();
        let contract_id = "test-contract-123";
        let content_hash = hash_content("Sample contract content");
        let timestamp = "2026-04-12T10:30:00Z";

        let signature = sign_contract(&private_key, contract_id, &content_hash, timestamp)
            .expect("Signing should succeed");

        assert!(verify_signature(
            &public_key,
            &signature,
            contract_id,
            &content_hash,
            timestamp
        ));
    }

    #[test]
    fn test_verify_fails_with_wrong_data() {
        let (public_key, private_key) = generate_keypair();
        let contract_id = "test-contract-123";
        let content_hash = hash_content("Sample contract content");
        let timestamp = "2026-04-12T10:30:00Z";

        let signature = sign_contract(&private_key, contract_id, &content_hash, timestamp)
            .expect("Signing should succeed");

        // Verify with different content should fail
        let wrong_hash = hash_content("Different content");
        assert!(!verify_signature(
            &public_key,
            &signature,
            contract_id,
            &wrong_hash,
            timestamp
        ));
    }

    #[test]
    fn test_verification_code_format() {
        let code = generate_verification_code();
        assert_eq!(code.len(), 14); // 12 chars + 2 dashes (format: AAAA-BBBB-CCCC)
        assert!(code.contains('-'));
        let parts: Vec<&str> = code.split('-').collect();
        assert_eq!(parts.len(), 3);
        assert_eq!(parts[0].len(), 4);
        assert_eq!(parts[1].len(), 4);
        assert_eq!(parts[2].len(), 4);
    }

    #[test]
    fn test_hash_content() {
        let content = "Test contract";
        let hash = hash_content(content);
        assert_eq!(hash.len(), 64); // SHA-256 produces 32 bytes = 64 hex chars

        // Same content should produce same hash
        let hash2 = hash_content(content);
        assert_eq!(hash, hash2);
    }

    #[test]
    fn test_generate_final_hash() {
        let contract_content = "Test contract content";
        let sig_hash1 = "signature_hash_1";
        let sig_hash2 = "signature_hash_2";
        let timestamp1 = "2026-05-01T10:00:00Z";
        let timestamp2 = "2026-05-01T11:00:00Z";
        let content_hash1 = "content_hash_1";
        let content_hash2 = "content_hash_2";

        let final_hash = generate_final_hash(
            contract_content,
            &[sig_hash1.to_string(), sig_hash2.to_string()],
            &[timestamp1.to_string(), timestamp2.to_string()],
            &[content_hash1.to_string(), content_hash2.to_string()],
        );

        // Should produce a valid SHA-256 hash
        assert_eq!(final_hash.len(), 64);

        // Same inputs should produce same hash
        let final_hash2 = generate_final_hash(
            contract_content,
            &[sig_hash1.to_string(), sig_hash2.to_string()],
            &[timestamp1.to_string(), timestamp2.to_string()],
            &[content_hash1.to_string(), content_hash2.to_string()],
        );
        assert_eq!(final_hash, final_hash2);

        // Different order should produce different hash (intentional for security)
        let final_hash_different_order = generate_final_hash(
            contract_content,
            &[sig_hash2.to_string(), sig_hash1.to_string()],
            &[timestamp2.to_string(), timestamp1.to_string()],
            &[content_hash2.to_string(), content_hash1.to_string()],
        );
        assert_ne!(final_hash, final_hash_different_order);
    }
}
