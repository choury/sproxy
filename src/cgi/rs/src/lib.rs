use std::env;
use std::fs::File;
use std::io::Read;
use std::os::raw::c_char;
use std::ffi::CStr;
use std::time::{SystemTime, UNIX_EPOCH};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use serde_json::json;

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

#[no_mangle]
pub extern "C" fn sendFcm(title: *const c_char, body: *const c_char, token: *const c_char) -> i32 {
    let title = unsafe { CStr::from_ptr(title).to_str().unwrap() };
    let body = unsafe { CStr::from_ptr(body).to_str().unwrap() };
    let token = unsafe { CStr::from_ptr(token).to_str().unwrap() };

    let scope = "https://www.googleapis.com/auth/firebase.messaging";
    let token_uri = "https://oauth2.googleapis.com/token";
    let json_path = match env::var("GOOGLE_AUTH_JSON") {
        Ok(path) => path,
        Err(e) => {
            eprintln!("Failed to get GOOGLE_AUTH_JSON environment variable: {}", e);
            return 1;
        }
    };

    // 读取服务账号的 JSON 密钥文件
    let mut file = match File::open(json_path) {
        Ok(file) => file,
        Err(e) => {
            eprintln!("Failed to open JSON key file: {}", e);
            return 1;
        }
    };
    let mut json_string = String::new();
    if let Err(e) = file.read_to_string(&mut json_string) {
        eprintln!("Failed to read JSON key file: {}", e);
        return 1;
    }

    // 解析 JSON 数据
    let json_value: serde_json::Value = match serde_json::from_str(&json_string) {
        Ok(value) => value,
        Err(e) => {
            eprintln!("Failed to parse JSON key file: {}", e);
            return 1;
        }
    };
    let service_account_key = ServiceAccountKey {
        client_email: json_value["client_email"].as_str().unwrap().to_string(),
        private_key: json_value["private_key"].as_str().unwrap().to_string(),
    };

    // 准备 JWT 声明
    let jwt_claim = JwtClaim {
        iss: service_account_key.client_email,
        scope: scope.to_string(),
        aud: token_uri.to_string(),
        exp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() + 3600,
        iat: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
    };

    // 创建 JWT
    let encoding_key = match EncodingKey::from_rsa_pem(service_account_key.private_key.as_bytes()) {
        Ok(key) => key,
        Err(e) => {
            eprintln!("Failed to create encoding key: {}", e);
            return 1;
        }
    };
    let header = Header::new(Algorithm::RS256);
    let jwt = match encode(&header, &jwt_claim, &encoding_key) {
        Ok(jwt) => jwt,
        Err(e) => {
            eprintln!("Failed to encode JWT: {}", e);
            return 1;
        }
    };

    // 发送 POST 请求以获取访问令牌
    let token_response = match ureq::post(token_uri)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .send(&format!("grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion={}", jwt)) {
        Ok(response) => response,
        Err(e) => {
            eprintln!("Failed to send POST request: {}", e);
            return 1;
        }
    };

    // 解析 JSON 响应以获取访问令牌
    let token_response_json: serde_json::Value = match serde_json::from_str(&token_response.into_body().read_to_string().unwrap()) {
        Ok(value) => value,
        Err(e) => {
            eprintln!("Failed to parse JSON response: {}", e);
            return 1;
        }
    };
    let access_token = token_response_json["access_token"].as_str().unwrap().to_string();

    // 定义 FCM 消息
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

    // 发送 FCM 消息
    let url = "https://fcm.googleapis.com/v1/projects/choury-dev/messages:send";
    let response = match ureq::post(url)
        .header("Content-Type", "application/json")
        .header("Authorization", &format!("Bearer {}", access_token))
        .send(&msg.to_string()) {
        Ok(response) => response,
        Err(e) => {
            eprintln!("Failed to send FCM message: {}", e);
            return 1;
        }
    };

    let response_json: serde_json::Value = match serde_json::from_str(&response.into_body().read_to_string().unwrap()) {
        Ok(value) => value,
        Err(e) => {
            eprintln!("Failed to parse FCM response: {}", e);
            return 1;
        }
    };

    match response_json["name"].as_str() {
        Some(name) => {
            println!("{}", name);
            0
        }
        None => {
            eprintln!("Name not found in FCM response");
            1
        }
    }
}