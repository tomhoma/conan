use anyhow::{Context, Result};
use reqwest::{Client, header::{HeaderMap, HeaderValue}};
use crate::models::{BreachDirectoryResponse, WeakpassResponse};

pub struct BreachDirectoryClient {
    client: Client,
    _api_key: String,
}

impl BreachDirectoryClient {
    pub fn new(api_key: String) -> Result<Self> {
        let mut headers = HeaderMap::new();
        headers.insert("X-API-KEY", HeaderValue::from_str(&api_key)?);
        
        let client = Client::builder()
            .default_headers(headers)
            .build()?;
            
        Ok(Self { client, _api_key: api_key })
    }
    
    pub async fn search(&self, username: &str) -> Result<BreachDirectoryResponse> {
        let url = format!("https://breachdirectory.org/api/search?username={}", username);
        
        let response = self.client
            .get(&url)
            .send()
            .await
            .context("Failed to search Breach Directory")?;
            
        let breach_response: BreachDirectoryResponse = response
            .json()
            .await
            .context("Failed to parse Breach Directory response")?;
            
        Ok(breach_response)
    }
}

pub async fn crack_hash(hash: &str, client: &Client) -> Result<Option<String>> {
    let url = format!("https://weakpass.com/api/v1/search/{}.json", hash);
    
    match client.get(&url).send().await {
        Ok(response) => {
            if response.status().is_success() {
                match response.json::<WeakpassResponse>().await {
                    Ok(weakpass) => Ok(Some(weakpass.pass)),
                    Err(_) => Ok(None),
                }
            } else {
                Ok(None)
            }
        }
        Err(_) => Ok(None),
    }
}