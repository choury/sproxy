use acme_lib::persist::FilePersist;
use acme_lib::{create_p384_key, Directory, DirectoryUrl};
use once_cell::sync::Lazy;
use parking_lot::{Mutex, RwLock};
use std::collections::HashMap;
use std::env;
use std::fs;
use std::io::ErrorKind;
use std::io::Write;
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
    raw
        .split(',')
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

fn leak_string(s: String) -> &'static str {
    Box::leak(s.into_boxed_str())
}

fn resolve_directory_url() -> Result<DirectoryUrl<'static>, String> {
    if let Ok(value) = env::var("SPROXY_ACME_DIRECTORY") {
        let normalized = value.trim().to_lowercase();
        match normalized.as_str() {
            "staging" => Ok(DirectoryUrl::LetsEncryptStaging),
            "prod" | "production" => Ok(DirectoryUrl::LetsEncrypt),
            custom if !custom.is_empty() => Ok(DirectoryUrl::Other(leak_string(value))),
            _ => Ok(DirectoryUrl::LetsEncrypt),
        }
    } else {
        Ok(DirectoryUrl::LetsEncrypt)
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

fn prepare_persist_dir(state_dir: Option<&str>) -> Result<PathBuf, String> {
    let path = state_dir
        .and_then(|value| {
            let trimmed = value.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(PathBuf::from(trimmed))
            }
        })
        .unwrap_or_else(|| PathBuf::from(".acme"));
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

pub fn request_certificate(
    domain: &str,
    contacts_raw: Option<&str>,
) -> Result<(), String> {
    if domain.is_empty() {
        return Err("domain must not be empty".into());
    }

    let _guard = ACME_LOCK.lock();

    let certfile = resolve_env_path("SPROXY_ACME_CERT");
    let keyfile = resolve_env_path("SPROXY_ACME_KEY");

    let state_dir = resolve_env_path("SPROXY_ACME_STATE");
    let persist_path = prepare_persist_dir(state_dir.as_deref())?;
    let persist = FilePersist::new(&persist_path);
    let dir_url = resolve_directory_url()?;
    let directory = Directory::from_url(persist, dir_url)
        .map_err(|e| format!("ACME directory error: {}", e))?;

    let contacts = contacts_raw
        .map(|list| normalize_contacts(list))
        .and_then(|list| if list.is_empty() { None } else { Some(list) });
    let account = directory
        .account_with_realm(domain, contacts)
        .map_err(|e| format!("ACME account error: {}", e))?;

    let mut ord_new = account
        .new_order(domain, &[])
        .map_err(|e| format!("ACME new order failed: {}", e))?;

    let mut existing_key_pem = None;
    let mut key_was_present = false;
    if let Some(path) = keyfile.as_deref() {
        match fs::read_to_string(path) {
            Ok(pem) => {
                key_was_present = true;
                existing_key_pem = Some(pem);
            }
            Err(err) if err.kind() == ErrorKind::NotFound => {}
            Err(err) => return Err(format!("Failed to read key file {}: {}", path, err)),
        }
    }

    let ord_csr = loop {
        if let Some(ord_csr) = ord_new.confirm_validations() {
            break ord_csr;
        }

        let auths = ord_new
            .authorizations()
            .map_err(|e| format!("fetch authorizations failed: {}", e))?;

        for auth in auths {
            let challenge = auth.http_challenge();
            if !challenge.need_validate() {
                continue;
            }
            let token = challenge.http_token().to_string();
            let proof = challenge.http_proof();
            store_http_challenge(&token, &proof);
            let result = challenge.validate(5000);
            clear_http_challenge(&token);
            result.map_err(|e| format!("challenge validation failed: {}", e))?;
        }

        ord_new
            .refresh()
            .map_err(|e| format!("order refresh failed: {}", e))?;
    };

    let cert_order = if let Some(ref pem) = existing_key_pem {
        ord_csr
            .finalize(pem, 5000)
            .map_err(|e| format!("finalize order failed: {}", e))?
    } else {
        let pkey = create_p384_key();
        ord_csr
            .finalize_pkey(pkey, 5000)
            .map_err(|e| format!("finalize order failed: {}", e))?
    };
    let cert = cert_order
        .download_and_save_cert()
        .map_err(|e| format!("certificate download failed: {}", e))?;

    if let Some(path) = keyfile.as_deref() {
        if !key_was_present {
            write_file(Some(path), cert.private_key().as_bytes(), Some(0o600))?;
        }
    }
    write_file(certfile.as_deref(), cert.certificate().as_bytes(), None)?;

    Ok(())
}
