use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Website {
    pub name: String,
    pub base_url: String,
    #[serde(rename = "url_probe")]
    pub url_probe: Option<String>,
    pub follow_redirects: bool,
    pub user_agent: Option<String>,
    #[serde(rename = "errorType")]
    pub error_type: String,
    #[serde(rename = "errorMsg")]
    pub error_msg: Option<String>,
    #[serde(rename = "errorCode")]
    pub error_code: Option<u16>,
    pub response_url: Option<String>,
    pub cookies: Option<Vec<Cookie>>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Cookie {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Data {
    pub websites: Vec<Website>,
}

#[derive(Debug, Deserialize)]
pub struct Stealer {
    pub total_corporate_services: i32,
    pub total_user_services: i32,
    pub date_compromised: String,
    pub stealer_family: String,
    pub computer_name: String,
    pub operating_system: String,
    pub malware_path: String,
    pub antiviruses: serde_json::Value,
    pub ip: String,
    pub top_passwords: Vec<String>,
    pub top_logins: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct HudsonRockResponse {
    pub message: String,
    pub stealers: Vec<Stealer>,
}

#[derive(Debug, Deserialize)]
pub struct WeakpassResponse {
    #[serde(rename = "type")]
    pub hash_type: String,
    pub hash: String,
    pub pass: String,
}

#[derive(Debug, Deserialize)]
pub struct ProxyNova {
    pub count: i32,
    pub lines: Vec<String>,
}

// Breach Directory related structures
#[derive(Debug, Deserialize)]
pub struct BreachDirectoryResponse {
    pub found: i32,
    pub result: Vec<BreachEntry>,
}

#[derive(Debug, Deserialize)]
pub struct BreachEntry {
    pub email: Option<String>,
    pub password: Option<String>,
    pub sha1: Option<String>,
    pub hash: Option<String>,
    pub sources: String,
}