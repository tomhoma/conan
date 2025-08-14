use anyhow::Result;
use crate::models::Data;
use reqwest::Client;
use once_cell::sync::Lazy;

pub static HTTP_CLIENT: Lazy<Client> = Lazy::new(|| {
    Client::builder()
        .pool_idle_timeout(std::time::Duration::from_secs(90))
        .pool_max_idle_per_host(10)
        .timeout(std::time::Duration::from_secs(30))
        .gzip(true)
        .brotli(true)
        .deflate(true)
        .danger_accept_invalid_certs(false)
        .build()
        .expect("Failed to create HTTP client")
});

pub async fn load_website_data() -> Result<Data> {
    let url = "https://raw.githubusercontent.com/ibnaleem/gosearch/refs/heads/main/data.json";
    let response = HTTP_CLIENT.get(url).send().await?;
    
    if !response.status().is_success() {
        anyhow::bail!("Failed to download data.json, status code: {}", response.status());
    }
    
    let data: Data = response.json().await?;
    Ok(data)
}
