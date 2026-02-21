use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ring::rand::SystemRandom;
use ring::signature::{self, EcdsaKeyPair, KeyPair};
use serde_json::{json, Value};
use std::fs;
use std::path::Path;

/// Manages an ECDSA P-256 key pair for ACME JWS signing.
pub struct AcmeKey {
    key_pair: EcdsaKeyPair,
    rng: SystemRandom,
}

impl AcmeKey {
    /// Load a key pair from a PKCS#8 DER file, or generate and save one if it doesn't exist.
    pub fn load_or_generate(path: &Path) -> Result<Self, String> {
        let rng = SystemRandom::new();
        if path.exists() {
            let pkcs8_bytes =
                fs::read(path).map_err(|e| format!("Failed to read key file: {}", e))?;
            let key_pair = EcdsaKeyPair::from_pkcs8(
                &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
                &pkcs8_bytes,
                &rng,
            )
            .map_err(|e| format!("Failed to parse key file: {}", e))?;
            Ok(Self { key_pair, rng })
        } else {
            let pkcs8 = EcdsaKeyPair::generate_pkcs8(
                &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
                &rng,
            )
            .map_err(|e| format!("Failed to generate key pair: {}", e))?;
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)
                    .map_err(|e| format!("Failed to create key directory: {}", e))?;
            }
            fs::write(path, pkcs8.as_ref())
                .map_err(|e| format!("Failed to write key file: {}", e))?;
            let key_pair = EcdsaKeyPair::from_pkcs8(
                &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
                pkcs8.as_ref(),
                &rng,
            )
            .map_err(|e| format!("Failed to parse generated key: {}", e))?;
            Ok(Self { key_pair, rng })
        }
    }

    /// Returns the JWK (JSON Web Key) representation of the public key.
    pub fn jwk(&self) -> Value {
        let public_key = self.key_pair.public_key().as_ref();
        // P-256 uncompressed point: 0x04 || x (32 bytes) || y (32 bytes)
        assert_eq!(public_key.len(), 65);
        assert_eq!(public_key[0], 0x04);
        let x = URL_SAFE_NO_PAD.encode(&public_key[1..33]);
        let y = URL_SAFE_NO_PAD.encode(&public_key[33..65]);
        json!({
            "crv": "P-256",
            "kty": "EC",
            "x": x,
            "y": y,
        })
    }

    /// Computes the JWK thumbprint (SHA-256) per RFC 7638.
    /// Used for key authorization: token.thumbprint
    pub fn thumbprint(&self) -> String {
        let jwk = self.jwk();
        // RFC 7638: lexicographic order of required members for EC: crv, kty, x, y
        let canonical = format!(
            r#"{{"crv":"{}","kty":"{}","x":"{}","y":"{}"}}"#,
            jwk["crv"].as_str().unwrap(),
            jwk["kty"].as_str().unwrap(),
            jwk["x"].as_str().unwrap(),
            jwk["y"].as_str().unwrap(),
        );
        let digest = ring::digest::digest(&ring::digest::SHA256, canonical.as_bytes());
        URL_SAFE_NO_PAD.encode(digest.as_ref())
    }

    /// Sign a JWS request body with the "jwk" header (used for newAccount).
    pub fn sign_jwk(&self, url: &str, nonce: &str, payload: &Value) -> Result<Value, String> {
        let protected = json!({
            "alg": "ES256",
            "jwk": self.jwk(),
            "nonce": nonce,
            "url": url,
        });
        self.sign_inner(&protected, payload)
    }

    /// Sign a JWS request body with the "kid" header (used for all authenticated requests).
    pub fn sign_kid(
        &self,
        url: &str,
        nonce: &str,
        kid: &str,
        payload: &Value,
    ) -> Result<Value, String> {
        let protected = json!({
            "alg": "ES256",
            "kid": kid,
            "nonce": nonce,
            "url": url,
        });
        self.sign_inner(&protected, payload)
    }

    /// Sign a POST-as-GET request (empty payload string, not "{}").
    pub fn sign_post_as_get(
        &self,
        url: &str,
        nonce: &str,
        kid: &str,
    ) -> Result<Value, String> {
        let protected = json!({
            "alg": "ES256",
            "kid": kid,
            "nonce": nonce,
            "url": url,
        });
        let protected_b64 = URL_SAFE_NO_PAD.encode(protected.to_string().as_bytes());
        // POST-as-GET: payload is empty string, not base64 of "{}"
        let payload_b64 = "";
        let signing_input = format!("{}.{}", protected_b64, payload_b64);
        let sig = self
            .key_pair
            .sign(&self.rng, signing_input.as_bytes())
            .map_err(|e| format!("Signing failed: {}", e))?;
        let sig_b64 = URL_SAFE_NO_PAD.encode(sig.as_ref());
        Ok(json!({
            "protected": protected_b64,
            "payload": payload_b64,
            "signature": sig_b64,
        }))
    }

    fn sign_inner(&self, protected: &Value, payload: &Value) -> Result<Value, String> {
        let protected_b64 = URL_SAFE_NO_PAD.encode(protected.to_string().as_bytes());
        let payload_b64 = URL_SAFE_NO_PAD.encode(payload.to_string().as_bytes());
        let signing_input = format!("{}.{}", protected_b64, payload_b64);
        let sig = self
            .key_pair
            .sign(&self.rng, signing_input.as_bytes())
            .map_err(|e| format!("Signing failed: {}", e))?;
        let sig_b64 = URL_SAFE_NO_PAD.encode(sig.as_ref());
        Ok(json!({
            "protected": protected_b64,
            "payload": payload_b64,
            "signature": sig_b64,
        }))
    }
}
