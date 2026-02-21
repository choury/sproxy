use crate::acme_jws::AcmeKey;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::thread;
use std::time::Duration;

/// ACME directory URLs.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Directory {
    new_nonce: String,
    new_account: String,
    new_order: String,
}

/// ACME order state.
#[derive(Deserialize, Debug)]
pub struct OrderState {
    pub status: String,
    pub authorizations: Option<Vec<String>>,
    pub finalize: Option<String>,
    pub certificate: Option<String>,
}

/// ACME authorization.
#[derive(Deserialize, Debug)]
pub struct Authorization {
    pub status: String,
    pub challenges: Vec<Challenge>,
}

/// ACME challenge.
#[derive(Deserialize, Debug, Clone)]
#[allow(dead_code)]
pub struct Challenge {
    #[serde(rename = "type")]
    pub challenge_type: String,
    pub url: String,
    pub token: Option<String>,
    pub status: String,
}

/// Serializable account credentials for persistence.
#[derive(Serialize, Deserialize)]
pub struct AccountCredentials {
    pub kid: String,
    pub key_pkcs8_b64: String,
}

/// Result from an ACME POST request.
struct AcmeResponse {
    location: Option<String>,
    body: Value,
}

/// Synchronous ACME client.
pub struct AcmeClient {
    agent: ureq::Agent,
    dir: Directory,
    nonce: Option<String>,
    key: AcmeKey,
    kid: Option<String>,
}

impl AcmeClient {
    /// Create a new client by fetching the ACME directory.
    pub fn new(directory_url: &str, key: AcmeKey) -> Result<Self, String> {
        let agent = ureq::Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(30)))
            .http_status_as_error(false)
            .build()
            .new_agent();
        let mut response = agent
            .get(directory_url)
            .call()
            .map_err(|e| format!("Failed to fetch ACME directory: {}", e))?;
        let dir: Directory = response
            .body_mut()
            .read_json()
            .map_err(|e| format!("Failed to parse ACME directory: {}", e))?;
        Ok(Self {
            agent,
            dir,
            nonce: None,
            key,
            kid: None,
        })
    }

    /// Fetch a fresh nonce from the ACME server.
    fn fetch_nonce(&mut self) -> Result<String, String> {
        let response = self.agent
            .head(&self.dir.new_nonce)
            .call()
            .map_err(|e| format!("Failed to fetch nonce: {}", e))?;
        response
            .headers()
            .get("Replay-Nonce")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
            .ok_or_else(|| "No Replay-Nonce header in response".to_string())
    }

    /// Get a nonce, using cached one if available.
    fn get_nonce(&mut self) -> Result<String, String> {
        if let Some(nonce) = self.nonce.take() {
            Ok(nonce)
        } else {
            self.fetch_nonce()
        }
    }

    /// Send a signed POST request with JWK header (for newAccount).
    fn post_jwk(&mut self, url: &str, payload: &Value) -> Result<AcmeResponse, String> {
        let nonce = self.get_nonce()?;
        let body = self.key.sign_jwk(url, &nonce, payload)?;
        self.do_post(url, &body)
    }

    /// Send a signed POST request with KID header.
    fn post_kid(&mut self, url: &str, payload: &Value) -> Result<AcmeResponse, String> {
        let kid = self
            .kid
            .as_ref()
            .ok_or("Account not registered yet")?
            .clone();
        let nonce = self.get_nonce()?;
        let body = self.key.sign_kid(url, &nonce, &kid, payload)?;
        self.do_post(url, &body)
    }

    /// Send a POST-as-GET request (empty payload).
    fn post_as_get(&mut self, url: &str) -> Result<AcmeResponse, String> {
        let kid = self
            .kid
            .as_ref()
            .ok_or("Account not registered yet")?
            .clone();
        let nonce = self.get_nonce()?;
        let body = self.key.sign_post_as_get(url, &nonce, &kid)?;
        self.do_post(url, &body)
    }

    /// Execute the POST and handle nonce updates.
    fn do_post(&mut self, url: &str, body: &Value) -> Result<AcmeResponse, String> {
        let mut response = self.agent
            .post(url)
            .header("Content-Type", "application/jose+json")
            .send_json(body)
            .map_err(|e| format!("ACME POST to {} failed: {}", url, e))?;

        // Save nonce for next request
        if let Some(nonce) = response
            .headers()
            .get("Replay-Nonce")
            .and_then(|v| v.to_str().ok())
        {
            self.nonce = Some(nonce.to_string());
        }

        // Extract Location header before consuming body
        let location = response
            .headers()
            .get("Location")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        let status = response.status().as_u16();
        let resp_body: Value = response
            .body_mut()
            .read_json()
            .unwrap_or_else(|_| json!({}));

        if status >= 400 {
            return Err(format!(
                "ACME error (HTTP {}): {}",
                status,
                resp_body
                    .get("detail")
                    .and_then(|v| v.as_str())
                    .unwrap_or(&resp_body.to_string())
            ));
        }

        Ok(AcmeResponse {
            location,
            body: resp_body,
        })
    }

    /// Register a new account or find an existing one.
    pub fn new_account(
        &mut self,
        contacts: Option<Vec<String>>,
    ) -> Result<String, String> {
        let mut payload = json!({
            "termsOfServiceAgreed": true,
        });
        if let Some(contacts) = contacts {
            payload["contact"] = Value::Array(
                contacts
                    .into_iter()
                    .map(Value::String)
                    .collect(),
            );
        }
        let url = self.dir.new_account.clone();
        let resp = self.post_jwk(&url, &payload)?;
        let kid = resp
            .location
            .ok_or("No Location header in newAccount response")?;
        self.kid = Some(kid.clone());
        Ok(kid)
    }

    /// Set the account URL (KID) for an existing account.
    pub fn set_kid(&mut self, kid: String) {
        self.kid = Some(kid);
    }

    /// Create a new certificate order.
    /// Automatically detects IP addresses vs domain names for the identifier type.
    pub fn new_order(&mut self, domains: &[&str]) -> Result<(String, OrderState), String> {
        let mut has_ip = false;
        let identifiers: Vec<Value> = domains
            .iter()
            .map(|d| {
                let is_ip = d.parse::<std::net::IpAddr>().is_ok();
                if is_ip {
                    has_ip = true;
                }
                json!({
                    "type": if is_ip { "ip" } else { "dns" },
                    "value": d,
                })
            })
            .collect();
        let mut payload = json!({ "identifiers": identifiers });
        // IP certificates require the "shortlived" profile (Let's Encrypt policy)
        if has_ip {
            payload["profile"] = json!("shortlived");
        }
        let url = self.dir.new_order.clone();
        let resp = self.post_kid(&url, &payload)?;
        let order_url = resp
            .location
            .ok_or("No Location header in newOrder response")?;
        let state: OrderState = serde_json::from_value(resp.body)
            .map_err(|e| format!("Failed to parse order: {}", e))?;
        Ok((order_url, state))
    }

    /// Fetch the authorizations for an order.
    pub fn get_authorization(&mut self, auth_url: &str) -> Result<Authorization, String> {
        let resp = self.post_as_get(auth_url)?;
        serde_json::from_value(resp.body)
            .map_err(|e| format!("Failed to parse authorization: {}", e))
    }

    /// Compute the key authorization value: token.thumbprint
    pub fn key_authorization(&self, token: &str) -> String {
        format!("{}.{}", token, self.key.thumbprint())
    }

    /// Notify the server that a challenge is ready.
    pub fn set_challenge_ready(&mut self, challenge_url: &str) -> Result<(), String> {
        let payload = json!({});
        let _ = self.post_kid(challenge_url, &payload)?;
        Ok(())
    }

    /// Poll the order state until it is ready or invalid.
    pub fn poll_order_ready(
        &mut self,
        order_url: &str,
        max_attempts: u32,
    ) -> Result<OrderState, String> {
        for attempt in 0..max_attempts {
            let resp = self.post_as_get(order_url)?;
            let state: OrderState = serde_json::from_value(resp.body)
                .map_err(|e| format!("Failed to parse order state: {}", e))?;
            eprintln!("[acme] poll attempt {}/{}: status={}", attempt + 1, max_attempts, state.status);
            match state.status.as_str() {
                "ready" | "valid" => return Ok(state),
                "invalid" => return Err("Order became invalid".to_string()),
                "pending" | "processing" => {
                    thread::sleep(Duration::from_secs(2));
                }
                other => return Err(format!("Unexpected order status: {}", other)),
            }
        }
        Err("Order did not become ready in time".to_string())
    }

    /// Finalize the order by submitting a CSR.
    pub fn finalize(&mut self, finalize_url: &str, csr_der: &[u8]) -> Result<(), String> {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
        let csr_b64 = URL_SAFE_NO_PAD.encode(csr_der);
        let payload = json!({ "csr": csr_b64 });
        let _ = self.post_kid(finalize_url, &payload)?;
        Ok(())
    }

    /// Download the certificate chain.
    pub fn download_certificate(&mut self, cert_url: &str) -> Result<String, String> {
        let kid = self
            .kid
            .as_ref()
            .ok_or("Account not registered yet")?
            .clone();
        let nonce = self.get_nonce()?;
        let body = self.key.sign_post_as_get(cert_url, &nonce, &kid)?;
        let mut response = self.agent
            .post(cert_url)
            .header("Content-Type", "application/jose+json")
            .header("Accept", "application/pem-certificate-chain")
            .send_json(&body)
            .map_err(|e| format!("Failed to download certificate: {}", e))?;

        if let Some(nonce) = response
            .headers()
            .get("Replay-Nonce")
            .and_then(|v| v.to_str().ok())
        {
            self.nonce = Some(nonce.to_string());
        }

        let status = response.status().as_u16();
        if status >= 400 {
            return Err(format!("Certificate download failed (HTTP {})", status));
        }
        response
            .body_mut()
            .read_to_string()
            .map_err(|e| format!("Failed to read certificate body: {}", e))
    }
}
