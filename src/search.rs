use anyhow::Result;
use chrono::{DateTime, Utc};
use colored::*;
use comfy_table::Table;
use futures::stream::{FuturesUnordered, StreamExt};
use once_cell::sync::Lazy;
use reqwest::{Client, StatusCode, header::USER_AGENT};
use std::fs;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::Semaphore;
use tokio::time::timeout;

use crate::models::*;
use crate::utils::write_to_file;

const DEFAULT_USER_AGENT: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:140.0) Gecko/20100101 Firefox/140.0";
const MAX_CONCURRENT_REQUESTS: usize = 50;

pub static PROFILE_COUNT: AtomicU32 = AtomicU32::new(0);
pub static HTTP_CLIENT: Lazy<Client> = Lazy::new(|| {
    Client::builder()
        .pool_idle_timeout(Duration::from_secs(90))
        .pool_max_idle_per_host(10)
        .timeout(Duration::from_secs(30))
        .gzip(true)
        .brotli(true)
        .deflate(true)
        .danger_accept_invalid_certs(false)
        .build()
        .expect("Failed to create HTTP client")
});
static HTTP_CLIENT_NO_REDIRECT: Lazy<Client> = Lazy::new(|| {
    Client::builder()
        .pool_idle_timeout(Duration::from_secs(90))
        .pool_max_idle_per_host(10)
        .timeout(Duration::from_secs(30))
        .gzip(true)
        .brotli(true)
        .deflate(true)
        .danger_accept_invalid_certs(false)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("Failed to create HTTP client with no redirect")
});

pub fn load_website_data() -> Result<Data> {
    let data_str = include_str!("data.json");
    let data: Data = serde_json::from_str(data_str)?;
    Ok(data)
}

pub async fn search_websites_batched(
    username: &str,
    websites: Vec<Website>,
    file_mutex: &Arc<Mutex<()>>,
    no_false_positives: bool,
) {
    let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_REQUESTS));
    let mut futures = FuturesUnordered::new();
    for website in websites {
        let permit = semaphore.clone();
        let username = username.to_string();
        let file_mutex = file_mutex.clone();
        futures.push(tokio::spawn(async move {
            let _permit = permit.acquire_owned().await.unwrap();
            search_website_optimized(&website, &username, &file_mutex, no_false_positives).await
        }));
    }
    while let Some(result) = futures.next().await {
        if let Err(e) = result {
            eprintln!("Task error: {}", e);
        }
    }
}

async fn search_website_optimized(
    website: &Website,
    username: &str,
    file_mutex: &Arc<Mutex<()>>,
    no_false_positives: bool,
) -> Result<()> {
    let url = if let Some(probe_url) = &website.url_probe {
        build_url(probe_url, username)
    } else {
        build_url(&website.base_url, username)
    };
    match website.error_type.as_str() {
        "status_code" => {
            check_by_status_code_optimized(website, &url, username, file_mutex).await?;
        }
        "errorMsg" => {
            check_by_error_msg_optimized(website, &url, username, file_mutex).await?;
        }
        "profilePresence" => {
            check_by_profile_presence(website, &url, username, file_mutex).await?;
        }
        "response_url" => {
            check_by_response_url(website, &url, username, file_mutex).await?;
        }
        _ => {
            if !no_false_positives {
                let display_url = build_url(&website.base_url, username);
                println!("{} {} {}", "[?]".yellow(), website.name.yellow(), display_url.yellow());
                write_to_file(username, &format!("[?] {}\n", display_url), file_mutex)?;
                PROFILE_COUNT.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
    Ok(())
}

async fn check_by_status_code_optimized(
    website: &Website,
    url: &str,
    username: &str,
    file_mutex: &Arc<Mutex<()>>,
) -> Result<()> {
    let client = if !website.follow_redirects {
        &HTTP_CLIENT_NO_REDIRECT
    } else {
        &HTTP_CLIENT
    };
    let request = client.head(url);
    let request = add_headers_and_cookies(request, website);
    let response = timeout(Duration::from_secs(15), request.send()).await??;
    if response.status().as_u16() < 400 {
        let should_mark_found = if let Some(error_code) = website.error_code {
            response.status().as_u16() != error_code
        } else {
            true
        };
        if should_mark_found {
            let display_url = build_url(&website.base_url, username);
            println!("{} {} {}", "[+]".green(), website.name, display_url);
            write_to_file(username, &format!("{}\n", display_url), file_mutex)?;
            PROFILE_COUNT.fetch_add(1, Ordering::Relaxed);
        }
    }
    Ok(())
}

async fn check_by_error_msg_optimized(
    website: &Website,
    url: &str,
    username: &str,
    file_mutex: &Arc<Mutex<()>>,
) -> Result<()> {
    let client = if !website.follow_redirects {
        &HTTP_CLIENT_NO_REDIRECT
    } else {
        &HTTP_CLIENT
    };
    let request = client.get(url);
    let request = add_headers_and_cookies(request, website);
    let mut response = timeout(Duration::from_secs(15), request.send()).await??;
    if response.status().as_u16() < 400 {
        if let Some(error_msg) = &website.error_msg {
            let mut buffer = Vec::with_capacity(8192);
            let mut found_error = false;
            while let Some(chunk) = response.chunk().await? {
                buffer.extend_from_slice(&chunk);
                if let Ok(text) = std::str::from_utf8(&buffer) {
                    if text.contains(error_msg) {
                        found_error = true;
                        break;
                    }
                }
                if buffer.len() > 65536 {
                    break;
                }
            }
            if !found_error {
                let display_url = build_url(&website.base_url, username);
                println!("{} {} {}", "[+]".green(), website.name, display_url);
                write_to_file(username, &format!("{}\n", display_url), file_mutex)?;
                PROFILE_COUNT.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
    Ok(())
}

async fn check_by_profile_presence(
    website: &Website,
    url: &str,
    username: &str,
    file_mutex: &Arc<Mutex<()>>,
) -> Result<()> {
    let client = if !website.follow_redirects {
        &HTTP_CLIENT_NO_REDIRECT
    } else {
        &HTTP_CLIENT
    };
    let request = client.get(url);
    let request = add_headers_and_cookies(request, website);
    let response = timeout(Duration::from_secs(15), request.send()).await??;
    if response.status().as_u16() < 400 {
        if let Some(error_msg) = &website.error_msg {
            let body = response.text().await?;
            if body.contains(error_msg) {
                println!("{} {} {}", "[+]".green(), website.name, url);
                write_to_file(username, &format!("{}\n", url), file_mutex)?;
                PROFILE_COUNT.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
    Ok(())
}

async fn check_by_response_url(
    website: &Website,
    url: &str,
    username: &str,
    file_mutex: &Arc<Mutex<()>>,
) -> Result<()> {
    let client = if !website.follow_redirects {
        &HTTP_CLIENT_NO_REDIRECT
    } else {
        &HTTP_CLIENT
    };
    let request = client.get(url);
    let request = add_headers_and_cookies(request, website);
    let response = timeout(Duration::from_secs(15), request.send()).await??;
    if response.status().as_u16() < 400 {
        if let Some(response_url_template) = &website.response_url {
            let expected_url = build_url(response_url_template, username);
            let actual_url = response.url().to_string();
            if actual_url != expected_url {
                let display_url = build_url(&website.base_url, username);
                println!("{} {} {}", "[+]".green(), website.name, display_url);
                write_to_file(username, &format!("{}\n", display_url), file_mutex)?;
                PROFILE_COUNT.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
    Ok(())
}

pub async fn hudson_rock_search(
    username: &str,
    file_mutex: &Arc<Mutex<()>>,
) -> Result<()> {
    let url = format!("https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-username?username={}", username);
    match HTTP_CLIENT.get(&url).send().await {
        Ok(response) => {
            let hudson_response: HudsonRockResponse = response.json().await?;
            if hudson_response.message.contains("This username is not associated with a computer infected") {
                println!("{}", "✓ No info-stealer association found".green());
                write_to_file(username, ":: No info-stealer association found", file_mutex)?;
            } else {
                println!("{}", "‼ Info-stealer compromise detected".red());
                println!("{}", "  All credentials on this computer may be exposed".yellow());
                let mut table = Table::new();
                table.set_header(vec!["#", "Stealer", "Date", "Computer", "Passwords"]);
                let mut file_content = String::new();
                for (i, stealer) in hudson_response.stealers.iter().enumerate() {
                    let computer_name = if stealer.computer_name.trim().eq_ignore_ascii_case("Not Found") {
                        stealer.computer_name.clone()
                    } else {
                        stealer.computer_name.red().to_string()
                    };
                    table.add_row(vec![
                        (i + 1).to_string(),
                        stealer.stealer_family.clone(),
                        format_stealer_date(&stealer.date_compromised),
                        computer_name,
                        stealer.top_passwords.join("\n"),
                    ]);
                    file_content.push_str(&format!("[-] Stealer #{}\n", i + 1));
                    file_content.push_str(&format!(":: Family: {}\n", stealer.stealer_family));
                    file_content.push_str(&format!(":: Date: {}\n", stealer.date_compromised));
                    file_content.push_str(&format!(":: Computer: {}\n", stealer.computer_name));
                    file_content.push_str(&format!(":: OS: {}\n", stealer.operating_system));
                    file_content.push_str(&format!(":: Path: {}\n", stealer.malware_path));
                    file_content.push_str(&format!(":: IP: {}\n", stealer.ip));
                    file_content.push_str(":: Passwords:\n");
                    for p in &stealer.top_passwords {
                        file_content.push_str(&format!("   {}\n", p));
                    }
                    file_content.push_str(":: Logins:\n");
                    for l in &stealer.top_logins {
                        file_content.push_str(&format!("   {}\n", l));
                    }
                    file_content.push_str("\n");
                }
                println!("{}", table);
                write_to_file(username, &file_content, file_mutex)?;
            }
        }
        Err(e) => {
            anyhow::bail!("Error fetching HudsonRock data: {}", e);
        }
    }
    Ok(())
}

pub async fn search_proxy_nova(
    username: &str,
    file_mutex: &Arc<Mutex<()>>,
) -> Result<()> {
    println!("{}", format!("[*] Searching {} on ProxyNova for any compromised passwords...", username).yellow());
    let url = format!("https://api.proxynova.com/comb?query={}", username);
    match HTTP_CLIENT.get(&url).send().await {
        Ok(response) => {
            match response.text().await {
                Ok(text) => {
                    match serde_json::from_str::<ProxyNova>(&text) {
                        Ok(proxy_nova) => {
                            if proxy_nova.count > 0 {
                                println!("{}", format!("[+] Found {} compromised passwords for {}:", proxy_nova.count, username).green());
                                let mut table = Table::new();
                                table.set_header(vec!["No", "Email", "Password"]);
                                for (i, line) in proxy_nova.lines.iter().enumerate() {
                                    if let Some((email, password)) = line.split_once(':') {
                                        table.add_row(vec![
                                            (i + 1).to_string(),
                                            email.green().to_string(),
                                            password.red().to_string(),
                                        ]);
                                        write_to_file(username, &format!("[+] Email: {}\n[+] Password: {}\n\n", email, password), file_mutex)?;
                                    }
                                }
                                println!("{}", table);
                            } else {
                                println!("{}", format!("[-] No compromised passwords found for {}.", username).red());
                            }
                        }
                        Err(e) => {
                            anyhow::bail!("Error parsing ProxyNova response: {}. Raw response: {}", e, text);
                        }
                    }
                }
                Err(e) => {
                    anyhow::bail!("Error reading ProxyNova response: {}", e);
                }
            }
        }
        Err(e) => {
            anyhow::bail!("Error searching ProxyNova: {}", e);
        }
    }
    Ok(())
}

pub fn build_domains(username: &str) -> Vec<String> {
    let tlds = vec![
        ".com", ".net", ".org", ".biz", ".info", ".name", ".pro", ".cat",
        ".co", ".me", ".io", ".tech", ".dev", ".app", ".shop", ".fail",
        ".xyz", ".blog", ".portfolio", ".store", ".online", ".about",
        ".space", ".lol", ".fun", ".social",
    ];
    tlds.iter()
        .map(|tld| format!("{}{}", username, tld))
        .collect()
}

pub async fn search_domains(
    username: &str,
    domains: Vec<String>,
    file_mutex: &Arc<Mutex<()>>,
) -> Result<()> {
    println!("{}", format!("[*] Searching {} domains with the username {}...", domains.len(), username).yellow());
    let mut found_count = 0;
    let mut table = Table::new();
    table.set_header(vec!["NO", "DOMAIN", "STATUS"]);
    let semaphore = Arc::new(Semaphore::new(20));
    let mut futures = FuturesUnordered::new();
    for domain in domains {
        let permit = semaphore.clone();
        let domain = domain.clone();
        futures.push(tokio::spawn(async move {
            let _permit = permit.acquire_owned().await.unwrap();
            let url = format!("http://{}", domain);
            match timeout(Duration::from_secs(10), HTTP_CLIENT.get(&url).send()).await {
                Ok(Ok(response)) => {
                    if response.status() == StatusCode::OK {
                        Some((domain, response.status()))
                    } else {
                        None
                    }
                }
                _ => None,
            }
        }));
    }
    let mut row_num = 0;
    while let Some(result) = futures.next().await {
        if let Ok(Some((domain, status))) = result {
            row_num += 1;
            table.add_row(vec![
                row_num.to_string(),
                domain.clone(),
                status.as_u16().to_string().green().to_string(),
            ]);
            write_to_file(username, &format!("[+] 200 OK: {}", domain), file_mutex)?;
            found_count += 1;
        }
    }
    if found_count > 0 {
        println!("{}", table);
        println!("{}", format!("[+] Found {} domains with the username {}", found_count, username).green());
        write_to_file(username, &format!("[+] Found {} domains with the username: {}", found_count, username), file_mutex)?;
    } else {
        println!("{}", format!("[-] No domains found with the username {}", username).red());
        write_to_file(username, &format!("[-] No domains found with the username: {}", username), file_mutex)?;
    }
    Ok(())
}

fn add_headers_and_cookies(mut request: reqwest::RequestBuilder, website: &Website) -> reqwest::RequestBuilder {
    let user_agent = website.user_agent.as_deref().unwrap_or(DEFAULT_USER_AGENT);
    request = request.header(USER_AGENT, user_agent)
        .header("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
        .header("Accept-Language", "en-US,en;q=0.5")
        .header("Accept-Encoding", "gzip, deflate, br")
        .header("Connection", "keep-alive")
        .header("Upgrade-Insecure-Requests", "1")
        .header("Sec-Fetch-Dest", "document")
        .header("Sec-Fetch-Mode", "navigate")
        .header("Sec-Fetch-Site", "none")
        .header("Sec-Fetch-User", "?1")
        .header("Cache-Control", "max-age=0");
    if let Some(cookies) = &website.cookies {
        for cookie in cookies {
            request = request.header("Cookie", format!("{}={}", cookie.name, cookie.value));
        }
    }
    request
}

fn build_url(base_url: &str, username: &str) -> String {
    base_url.replace("{}", username)
}

pub fn delete_old_file(username: &str) {
    let filename = format!("{}.txt", username);
    let _ = fs::remove_file(filename);
}

fn format_stealer_date(date_str: &str) -> String {
    match DateTime::parse_from_rfc3339(date_str) {
        Ok(dt) => {
            let now = Utc::now();
            let diff = now.signed_duration_since(dt.with_timezone(&Utc));
            if diff.num_hours() < 1 {
                "just now".to_string()
            } else if diff.num_hours() < 24 {
                let hours = diff.num_hours();
                format!("{} hour{} ago", hours, if hours == 1 { "" } else { "s" })
            } else if diff.num_days() < 7 {
                let days = diff.num_days();
                format!("{} day{} ago", days, if days == 1 { "" } else { "s" })
            } else {
                dt.format("%b %d, %Y").to_string()
            }
        }
        Err(_) => date_str.to_string(),
    }
}