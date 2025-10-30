use std::ffi::CStr;
use std::os::raw::c_char;
use std::slice;

mod acme;
mod fcm;

fn cstr_to_str<'a>(ptr: *const c_char) -> Result<&'a str, String> {
    if ptr.is_null() {
        Err("received null pointer".into())
    } else {
        unsafe { CStr::from_ptr(ptr).to_str().map_err(|e| e.to_string()) }
    }
}

fn optional_string(ptr: *const c_char) -> Result<Option<String>, String> {
    if ptr.is_null() {
        Ok(None)
    } else {
        cstr_to_str(ptr).map(|s| Some(s.to_string()))
    }
}

#[no_mangle]
pub extern "C" fn sendPushMessage(
    title: *const c_char,
    body: *const c_char,
    token: *const c_char,
) -> i32 {
    let result = (|| -> Result<(), String> {
        let title = cstr_to_str(title)?;
        let body = cstr_to_str(body)?;
        let token = cstr_to_str(token)?;
        fcm::send_push_message(title, body, token)
    })();

    match result {
        Ok(_) => 0,
        Err(err) => {
            eprintln!("sendPushMessage error: {}", err);
            1
        }
    }
}

#[no_mangle]
pub extern "C" fn acme_request_certificate(
    domain: *const c_char,
    contact: *const c_char,
) -> i32 {
    let result = (|| -> Result<(), String> {
        let domain = cstr_to_str(domain)?.to_string();
        let contact = optional_string(contact)?;
        acme::request_certificate(&domain, contact.as_deref())
    })();

    match result {
        Ok(_) => 0,
        Err(err) => {
            eprintln!("acme_request_certificate error: {}", err);
            -1
        }
    }
}

#[no_mangle]
pub extern "C" fn acme_get_http_challenge(
    token: *const c_char,
    buffer: *mut c_char,
    buffer_len: usize,
) -> bool {
    if token.is_null() || buffer.is_null() || buffer_len == 0 {
        return false;
    }
    let token = match cstr_to_str(token) {
        Ok(t) => t,
        Err(_) => return false,
    };
    let payload = match acme::get_http_challenge(token) {
        Some(p) => p,
        None => return false,
    };
    if payload.len() + 1 > buffer_len {
        return false;
    }
    unsafe {
        let raw = slice::from_raw_parts_mut(buffer as *mut u8, buffer_len);
        raw[..payload.len()].copy_from_slice(payload.as_bytes());
        raw[payload.len()] = 0;
    }
    true
}
