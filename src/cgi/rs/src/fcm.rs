use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::env;
use std::fs::File;
use std::io::Read;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Deserialize)]
struct ServiceAccountKey {
    client_email: String,
    private_key: String,
}

#[derive(Serialize, Deserialize)]
struct JwtClaim {
    iss: String,
    scope: String,
    aud: String,
    exp: u64,
    iat: u64,
}

fn read_service_account() -> Result<ServiceAccountKey, String> {
    let json_path = env::var("GOOGLE_AUTH_JSON")
        .map_err(|e| format!("Failed to get GOOGLE_AUTH_JSON environment variable: {}", e))?;

    let mut file = File::open(&json_path)
        .map_err(|e| format!("Failed to open JSON key file {}: {}", json_path, e))?;
    let mut json_string = String::new();
    file.read_to_string(&mut json_string)
        .map_err(|e| format!("Failed to read JSON key file {}: {}", json_path, e))?;

    serde_json::from_str(&json_string)
        .map_err(|e| format!("Failed to parse JSON key file {}: {}", json_path, e))
}

fn build_jwt(key: &ServiceAccountKey, scope: &str, token_uri: &str) -> Result<String, String> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| format!("System time error: {}", e))?
        .as_secs();
    let claim = JwtClaim {
        iss: key.client_email.clone(),
        scope: scope.to_string(),
        aud: token_uri.to_string(),
        exp: now + 3600,
        iat: now,
    };

    let encoding_key =
        EncodingKey::from_rsa_pem(key.private_key.as_bytes()).map_err(|e| e.to_string())?;
    encode(&Header::new(Algorithm::RS256), &claim, &encoding_key).map_err(|e| e.to_string())
}

fn fetch_access_token(token_uri: &str, jwt: &str) -> Result<String, String> {
    let mut response = ureq::post(token_uri)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .send_form([
            ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
            ("assertion", jwt),
        ])
        .map_err(|e| format!("Failed to send POST request for access token: {}", e))?;

    let value: serde_json::Value = response
        .body_mut()
        .read_json()
        .map_err(|e| format!("Failed to parse access token response: {}", e))?;

    value["access_token"]
        .as_str()
        .ok_or_else(|| "access_token not found in response".to_string())
        .map(|s| s.to_string())
}

fn send_message(access_token: &str, title: &str, body: &str, token: &str) -> Result<(), String> {
    let msg = json!({
        "message": {
            "notification": {
                "title": title,
                "body": body
            },
            "data": {
                "title": title,
                "body": body
            },
            "android": {
                "priority": "HIGH"
            },
            "token": token
        }
    });

    let mut response =
        ureq::post("https://fcm.googleapis.com/v1/projects/choury-dev/messages:send")
            .header("Content-Type", "application/json")
            .header("Authorization", &format!("Bearer {}", access_token))
            .send_json(&msg)
            .map_err(|e| format!("Failed to send FCM message: {}", e))?;

    let value: serde_json::Value = response
        .body_mut()
        .read_json()
        .map_err(|e| format!("Failed to parse FCM response: {}", e))?;

    if value["name"].as_str().is_some() {
        Ok(())
    } else {
        Err("Name not found in FCM response".to_string())
    }
}

pub fn send_push_message(title: &str, body: &str, token: &str) -> Result<(), String> {
    let service_key = read_service_account()?;
    let scope = "https://www.googleapis.com/auth/firebase.messaging";
    let token_uri = "https://oauth2.googleapis.com/token";
    let jwt = build_jwt(&service_key, scope, token_uri)?;
    let access_token = fetch_access_token(token_uri, &jwt)?;
    send_message(&access_token, title, body, token)
}
