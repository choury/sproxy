use crate::acme_client::{AccountCredentials, AcmeClient};
use crate::acme_jws::AcmeKey;
use once_cell::sync::Lazy;
use parking_lot::{Mutex, RwLock};
use rcgen::{CertificateParams, KeyPair, SanType};
use std::collections::HashMap;
use std::env;
use std::fs;
use std::io::Write;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

static HTTP_CHALLENGES: Lazy<RwLock<HashMap<String, String>>> =
    Lazy::new(|| RwLock::new(HashMap::new()));
static ACME_LOCK: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

pub fn get_http_challenge(token: &str) -> Option<String> {
    HTTP_CHALLENGES.read().get(token).cloned()
}

fn store_http_challenge(token: &str, payload: &str) {
    HTTP_CHALLENGES
        .write()
        .insert(token.to_string(), payload.to_string());
}

fn clear_http_challenge(token: &str) {
    HTTP_CHALLENGES.write().remove(token);
}

fn normalize_contacts(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(|item| item.trim())
        .filter(|item| !item.is_empty())
        .map(|item| {
            if item.starts_with("mailto:") {
                item.to_string()
            } else {
                format!("mailto:{}", item)
            }
        })
        .collect()
}

fn resolve_directory_url() -> String {
    if let Ok(value) = env::var("SPROXY_ACME_DIRECTORY") {
        let normalized = value.trim().to_lowercase();
        match normalized.as_str() {
            "staging" => "https://acme-staging-v02.api.letsencrypt.org/directory".to_string(),
            "prod" | "production" => {
                "https://acme-v02.api.letsencrypt.org/directory".to_string()
            }
            custom if !custom.is_empty() => value,
            _ => "https://acme-v02.api.letsencrypt.org/directory".to_string(),
        }
    } else {
        "https://acme-v02.api.letsencrypt.org/directory".to_string()
    }
}

fn prepare_state_dir() -> Result<PathBuf, String> {
    let path = match env::var("SPROXY_ACME_STATE") {
        Ok(value) if !value.trim().is_empty() => PathBuf::from(value.trim()),
        _ => PathBuf::from(".acme"),
    };
    fs::create_dir_all(&path)
        .map_err(|e| format!("Failed to create ACME state directory {:?}: {}", path, e))?;
    Ok(path)
}

fn resolve_env_path(key: &str) -> Option<String> {
    match env::var(key) {
        Ok(value) if !value.trim().is_empty() => Some(value),
        _ => None,
    }
}

fn ensure_parent(path: &Path) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("Failed to create parent directory {:?}: {}", parent, e))?;
    }
    Ok(())
}

fn write_file(path: Option<&str>, data: &[u8], mode: Option<u32>) -> Result<(), String> {
    if let Some(target) = path {
        let path = PathBuf::from(target);
        ensure_parent(&path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
            let mut options = fs::OpenOptions::new();
            options.write(true).create(true).truncate(true);
            if let Some(bits) = mode {
                options.mode(bits);
            }
            let mut file = options
                .open(&path)
                .map_err(|e| format!("Failed to open {} for write: {}", target, e))?;
            if let Some(bits) = mode {
                let perms = fs::Permissions::from_mode(bits);
                fs::set_permissions(&path, perms)
                    .map_err(|e| format!("Failed to set permissions for {}: {}", target, e))?;
            }
            file.write_all(data)
                .map_err(|e| format!("Failed to write {}: {}", target, e))?;
        }
        #[cfg(not(unix))]
        {
            let _ = mode;
            let mut file = fs::File::create(&path)
                .map_err(|e| format!("Failed to open {} for write: {}", target, e))?;
            file.write_all(data)
                .map_err(|e| format!("Failed to write {}: {}", target, e))?;
        }
    }
    Ok(())
}

fn load_or_create_account(
    client: &mut AcmeClient,
    state_dir: &Path,
    contacts: Option<Vec<String>>,
) -> Result<(), String> {
    let creds_path = state_dir.join("account.json");
    if creds_path.exists() {
        let data = fs::read_to_string(&creds_path)
            .map_err(|e| format!("Failed to read account credentials: {}", e))?;
        let creds: AccountCredentials = serde_json::from_str(&data)
            .map_err(|e| format!("Failed to parse account credentials: {}", e))?;
        client.set_kid(creds.kid);
        Ok(())
    } else {
        let kid = client.new_account(contacts)?;
        let creds = AccountCredentials {
            kid,
            key_pkcs8_b64: String::new(), // key is stored separately
        };
        let data = serde_json::to_string_pretty(&creds)
            .map_err(|e| format!("Failed to serialize account credentials: {}", e))?;
        fs::write(&creds_path, data.as_bytes())
            .map_err(|e| format!("Failed to write account credentials: {}", e))?;
        Ok(())
    }
}

pub fn request_certificate(domain: &str, contacts_raw: Option<&str>) -> Result<(), String> {
    if domain.is_empty() {
        return Err("domain must not be empty".into());
    }

    // Strip brackets from IPv6 addresses (e.g. "[::1]" -> "::1")
    let domain = domain.trim_start_matches('[').trim_end_matches(']');

    let _guard = ACME_LOCK.lock();
    eprintln!("[acme] requesting certificate for: {}", domain);

    let certfile = resolve_env_path("SPROXY_ACME_CERT");
    let keyfile = resolve_env_path("SPROXY_ACME_KEY");

    let state_dir = prepare_state_dir()?;
    let dir_url = resolve_directory_url();
    eprintln!("[acme] directory: {}", dir_url);

    // Load or generate the ACME account key
    let account_key_path = state_dir.join("account_key.der");
    let acme_key = AcmeKey::load_or_generate(&account_key_path)?;
    eprintln!("[acme] account key loaded");

    // Create client and register/load account
    eprintln!("[acme] fetching ACME directory...");
    let mut client = AcmeClient::new(&dir_url, acme_key)?;
    eprintln!("[acme] directory fetched");

    let contacts = contacts_raw
        .map(|list| normalize_contacts(list))
        .and_then(|list| if list.is_empty() { None } else { Some(list) });
    eprintln!("[acme] registering/loading account...");
    load_or_create_account(&mut client, &state_dir, contacts)?;
    eprintln!("[acme] account ready");

    // Create new order
    eprintln!("[acme] creating order for: {}", domain);
    let (order_url, order_state) = client.new_order(&[domain])?;
    eprintln!("[acme] order created: {}, status: {}", order_url, order_state.status);

    // Process authorizations
    if let Some(auth_urls) = &order_state.authorizations {
        for auth_url in auth_urls {
            eprintln!("[acme] fetching authorization: {}", auth_url);
            let auth = client.get_authorization(auth_url)?;
            eprintln!("[acme] authorization status: {}", auth.status);
            if auth.status == "valid" {
                eprintln!("[acme] authorization already valid, skipping");
                continue;
            }

            // Find HTTP-01 challenge
            eprintln!("[acme] available challenges: {:?}", auth.challenges.iter().map(|c| &c.challenge_type).collect::<Vec<_>>());
            let challenge = auth
                .challenges
                .iter()
                .find(|c| c.challenge_type == "http-01")
                .ok_or("No HTTP-01 challenge found")?;

            let token = challenge
                .token
                .as_deref()
                .ok_or("Challenge has no token")?;
            let key_auth = client.key_authorization(token);
            eprintln!("[acme] storing HTTP-01 challenge: token={}", token);

            // Store challenge response for the HTTP server
            store_http_challenge(token, &key_auth);

            // Notify server that challenge is ready
            let challenge_url = challenge.url.clone();
            eprintln!("[acme] notifying server challenge is ready: {}", challenge_url);
            let result = client.set_challenge_ready(&challenge_url);

            if let Err(e) = result {
                clear_http_challenge(token);
                return Err(format!("Challenge validation failed: {}", e));
            }
            eprintln!("[acme] challenge notification sent");
        }
    }

    // Poll until order is ready
    eprintln!("[acme] polling order status...");
    let order_state = client.poll_order_ready(&order_url, 30)?;
    eprintln!("[acme] order ready, status: {}", order_state.status);

    // Clear any remaining challenges
    if let Some(auth_urls) = &order_state.authorizations {
        for auth_url in auth_urls {
            if let Ok(auth) = client.get_authorization(auth_url) {
                for ch in &auth.challenges {
                    if let Some(token) = &ch.token {
                        clear_http_challenge(token);
                    }
                }
            }
        }
    }

    // Build CSR params with appropriate SAN type (IP or DNS)
    let make_csr = |key_pair: &KeyPair| -> Result<Vec<u8>, String> {
        let mut params = CertificateParams::default();
        params.distinguished_name = rcgen::DistinguishedName::new();
        if let Ok(ip) = domain.parse::<IpAddr>() {
            params.subject_alt_names = vec![SanType::IpAddress(ip)];
        } else {
            params.subject_alt_names = vec![SanType::DnsName(domain.try_into()
                .map_err(|e| format!("Invalid domain name: {}", e))?)];
        }
        let csr = params
            .serialize_request(key_pair)
            .map_err(|e| format!("Failed to generate CSR: {}", e))?;
        Ok(csr.der().to_vec())
    };

    // Load existing key or generate a new one
    let (cert_key_pem, csr_der) = if let Some(ref key_path) = keyfile {
        match fs::read_to_string(key_path) {
            Ok(pem) => {
                let key_pair = KeyPair::from_pem(&pem)
                    .map_err(|e| format!("Failed to parse existing key: {}", e))?;
                let der = make_csr(&key_pair)?;
                (pem, der)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let key_pair = KeyPair::generate()
                    .map_err(|e| format!("Failed to generate key: {}", e))?;
                let pem = key_pair.serialize_pem();
                let der = make_csr(&key_pair)?;
                write_file(Some(key_path), pem.as_bytes(), Some(0o600))?;
                (pem, der)
            }
            Err(e) => return Err(format!("Failed to read key file {}: {}", key_path, e)),
        }
    } else {
        let key_pair =
            KeyPair::generate().map_err(|e| format!("Failed to generate key: {}", e))?;
        let pem = key_pair.serialize_pem();
        let der = make_csr(&key_pair)?;
        (pem, der)
    };

    // Finalize order
    let finalize_url = order_state
        .finalize
        .ok_or("Order has no finalize URL")?;
    eprintln!("[acme] finalizing order: {}", finalize_url);
    client.finalize(&finalize_url, &csr_der)?;
    eprintln!("[acme] order finalized");

    // Poll until certificate is available
    eprintln!("[acme] polling for certificate...");
    let final_state = client.poll_order_ready(&order_url, 30)?;
    let cert_url = final_state
        .certificate
        .ok_or("Order has no certificate URL")?;
    eprintln!("[acme] certificate ready: {}", cert_url);

    // Download certificate
    eprintln!("[acme] downloading certificate...");
    let cert_pem = client.download_certificate(&cert_url)?;
    eprintln!("[acme] certificate downloaded ({} bytes)", cert_pem.len());

    // Save certificate
    write_file(certfile.as_deref(), cert_pem.as_bytes(), None)?;
    eprintln!("[acme] certificate saved");

    // Save key if it wasn't already present
    let _ = cert_key_pem; // key was already written above if needed

    eprintln!("[acme] certificate request completed successfully");
    Ok(())
}
