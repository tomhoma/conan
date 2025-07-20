use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use clap::Parser;
use colored::*;
use comfy_table::{Table, Cell, Attribute};
use futures::future::join_all;
use reqwest::{Client, StatusCode, header::USER_AGENT};
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::time::timeout;

const ASCII_LOGO: &str = r#"
 ________   ________   ________    ________   ________      
|\   ____\ |\   __  \ |\   ___  \ |\   __  \ |\   ___  \    
\ \  \___| \ \  \|\  \\ \  \\ \  \\ \  \|\  \\ \  \\ \  \   
 \ \  \     \ \  \\\  \\ \  \\ \  \\ \   __  \\ \  \\ \  \  
  \ \  \____ \ \  \\\  \\ \  \\ \  \\ \  \ \  \\ \  \\ \  \ 
   \ \_______\\ \_______\\ \__\\ \__\\ \__\ \__\\ \__\\ \__\
    \|_______| \|_______| \|__| \|__| \|__|\|__| \|__| \|__|

"#;

const DEFAULT_USER_AGENT: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:140.0) Gecko/20100101 Firefox/140.0";
const VERSION: &str = "v1.0.0";

static PROFILE_COUNT: AtomicU32 = AtomicU32::new(0);

#[derive(Parser, Debug)]
#[command(name = "conan")]
#[command(version = VERSION)]
#[command(about = "Search for usernames across various websites", long_about = None)]
struct Args {
    /// Username to search
    #[arg(short, long)]
    username: Option<String>,

    /// Do not show false positives
    #[arg(long = "no-false-positives")]
    no_false_positives: bool,

    /// Search Breach Directory with an API Key
    #[arg(short = 'b', long = "breach-directory")]
    breach_directory_api_key: Option<String>,

    /// Username as positional argument
    #[arg(index = 1)]
    positional_username: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct Website {
    name: String,
    base_url: String,
    #[serde(rename = "url_probe")]
    url_probe: Option<String>,
    follow_redirects: bool,
    user_agent: Option<String>,
    #[serde(rename = "errorType")]
    error_type: String,
    #[serde(rename = "errorMsg")]
    error_msg: Option<String>,
    #[serde(rename = "errorCode")]
    error_code: Option<u16>,
    response_url: Option<String>,
    cookies: Option<Vec<Cookie>>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct Cookie {
    name: String,
    value: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct Data {
    websites: Vec<Website>,
}

#[derive(Debug, Deserialize)]
struct Stealer {
    total_corporate_services: i32,
    total_user_services: i32,
    date_compromised: String,
    stealer_family: String,
    computer_name: String,
    operating_system: String,
    malware_path: String,
    antiviruses: serde_json::Value,
    ip: String,
    top_passwords: Vec<String>,
    top_logins: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct HudsonRockResponse {
    message: String,
    stealers: Vec<Stealer>,
}

#[derive(Debug, Deserialize)]
struct WeakpassResponse {
    #[serde(rename = "type")]
    hash_type: String,
    hash: String,
    pass: String,
}

#[derive(Debug, Deserialize)]
struct ProxyNova {
    count: i32,
    lines: Vec<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    
    let args = Args::parse();
    
    // Determine username from various sources
    let username = args.username
        .or(args.positional_username)
        .unwrap_or_else(|| {
            eprintln!("Usage: conan -u <username>\nIssues: https://github.com/ibnaleem/gosearch/issues");
            std::process::exit(1);
        });

    // Delete old output file
    delete_old_file(&username);
    
    // Load website data
    let data = match load_website_data().await {
        Ok(data) => data,
        Err(e) => {
            eprintln!("{} {}", "Error loading website data:".red(), e);
            std::process::exit(1);
        }
    };
    
    // Clear screen and display header
    print!("\x1B[2J\x1B[1;1H");
    println!("{}", ASCII_LOGO);
    println!("{}", VERSION);
    println!("{}", "⎯".repeat(85));
    println!(":: Username                              :  {}", username);
    println!(":: Websites                              :  {}", data.websites.len());
    
    if args.no_false_positives {
        println!(":: No False Positives                    :  {}", args.no_false_positives);
    }
    
    println!("{}", "⎯".repeat(85));
    println!();
    
    if !args.no_false_positives {
        println!("{}", "[!] A yellow link indicates that I was unable to verify whether the username exists on the platform.".yellow());
    }
    
    let start = Instant::now();
    
    // Create HTTP client
    let client = match create_http_client() {
        Ok(client) => client,
        Err(e) => {
            eprintln!("{} {}", "Error creating HTTP client:".red(), e);
            std::process::exit(1);
        }
    };
    let file_mutex = Arc::new(Mutex::new(()));
    
    // Search websites concurrently
    let search_tasks: Vec<_> = data.websites.iter()
        .map(|website| {
            let website = website.clone();
            let username = username.clone();
            let client = client.clone();
            let file_mutex = file_mutex.clone();
            let no_false_positives = args.no_false_positives;
            
            tokio::spawn(async move {
                search_website(&website, &username, &client, &file_mutex, no_false_positives).await
            })
        })
        .collect();
    
    join_all(search_tasks).await;
    
    println!("\n");
    
    // Search HudsonRock
    if let Err(e) = write_to_file(&username, &"⎯".repeat(85), &file_mutex) {
        eprintln!("{} {}", "Error writing to file:".red(), e);
    }
    println!("{}", "[*] Searching HudsonRock's Cybercrime Intelligence Database...".yellow());
    if let Err(e) = hudson_rock_search(&username, &client, &file_mutex).await {
        eprintln!("{} {}", "Error searching HudsonRock:".red(), e);
    }
    
    // Search Breach Directory if API key provided
    if let Some(api_key) = args.breach_directory_api_key {
        println!("\n");
        if let Err(e) = search_breach_directory(&username, &api_key, &client, &file_mutex).await {
            eprintln!("{} {}", "Error searching Breach Directory:".red(), e);
        }
    }
    
    println!("\n");
    
    // Search ProxyNova
    if let Err(e) = write_to_file(&username, &"⎯".repeat(85), &file_mutex) {
        eprintln!("{} {}", "Error writing to file:".red(), e);
    }
    if let Err(e) = search_proxy_nova(&username, &client, &file_mutex).await {
        eprintln!("{} {}", "Error searching ProxyNova:".red(), e);
    }
    
    println!("\n");
    
    // Search domains
    let domains = build_domains(&username);
    if let Err(e) = search_domains(&username, domains, &client, &file_mutex).await {
        eprintln!("{} {}", "Error searching domains:".red(), e);
    }
    
    println!("\n");
    
    // Display summary
    let elapsed = start.elapsed();
    let mut table = Table::new();
    table.load_preset(comfy_table::presets::NOTHING);
    table.add_row(vec![
        Cell::new("Number of profiles found").add_attribute(Attribute::Bold),
        Cell::new(PROFILE_COUNT.load(Ordering::Relaxed)).fg(comfy_table::Color::Red),
    ]);
    table.add_row(vec![
        Cell::new("Total time taken").add_attribute(Attribute::Bold),
        Cell::new(format!("{:?}", elapsed)).fg(comfy_table::Color::Green),
    ]);
    println!("{}", table);
    
    if let Err(e) = write_to_file(&username, &format!(":: Number of profiles found              : {}", PROFILE_COUNT.load(Ordering::Relaxed)), &file_mutex) {
        eprintln!("{} {}", "Error writing to file:".red(), e);
    }
    if let Err(e) = write_to_file(&username, &format!(":: Total time taken                      : {:?}", elapsed), &file_mutex) {
        eprintln!("{} {}", "Error writing to file:".red(), e);
    }
    
    Ok(())
}

async fn load_website_data() -> Result<Data> {
    let url = "https://raw.githubusercontent.com/ibnaleem/gosearch/refs/heads/main/data.json";
    let response = reqwest::get(url).await?;
    
    if !response.status().is_success() {
        anyhow::bail!("Failed to download data.json, status code: {}", response.status());
    }
    
    let data: Data = response.json().await?;
    Ok(data)
}

fn create_http_client() -> Result<Client> {
    Client::builder()
        .timeout(Duration::from_secs(120))
        .gzip(true)
        .brotli(true)
        .deflate(true)
        .danger_accept_invalid_certs(false)
        .build()
        .context("Failed to create HTTP client")
}

fn create_http_client_no_redirect() -> Result<Client> {
    Client::builder()
        .timeout(Duration::from_secs(120))
        .gzip(true)
        .brotli(true)
        .deflate(true)
        .danger_accept_invalid_certs(false)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .context("Failed to create HTTP client with no redirect")
}

async fn search_website(
    website: &Website,
    username: &str,
    client: &Client,
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
            check_by_status_code(website, &url, username, client, file_mutex).await?;
        }
        "errorMsg" => {
            check_by_error_msg(website, &url, username, client, file_mutex).await?;
        }
        "profilePresence" => {
            check_by_profile_presence(website, &url, username, client, file_mutex).await?;
        }
        "response_url" => {
            check_by_response_url(website, &url, username, client, file_mutex).await?;
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

async fn check_by_status_code(
    website: &Website,
    url: &str,
    username: &str,
    client: &Client,
    file_mutex: &Arc<Mutex<()>>,
) -> Result<()> {
    let client_to_use = if !website.follow_redirects {
        create_http_client_no_redirect()?
    } else {
        client.clone()
    };
    
    let request = client_to_use.get(url);
    let request = add_headers_and_cookies(request, website);
    
    match timeout(Duration::from_secs(30), request.send()).await {
        Ok(Ok(response)) => {
            if response.status().as_u16() < 400 {
                let should_mark_found = if let Some(error_code) = website.error_code {
                    // If error_code is defined, profile exists if status != error_code
                    response.status().as_u16() != error_code
                } else {
                    // If no error_code is defined, any successful response means profile exists
                    true
                };
                
                if should_mark_found {
                    let display_url = build_url(&website.base_url, username);
                    println!("{} {} {}", "[+]".green(), website.name, display_url);
                    write_to_file(username, &format!("{}\n", display_url), file_mutex)?;
                    PROFILE_COUNT.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
        _ => {}
    }
    
    Ok(())
}

async fn check_by_error_msg(
    website: &Website,
    url: &str,
    username: &str,
    client: &Client,
    file_mutex: &Arc<Mutex<()>>,
) -> Result<()> {
    let client_to_use = if !website.follow_redirects {
        create_http_client_no_redirect()?
    } else {
        client.clone()
    };
    
    let request = client_to_use.get(url);
    let request = add_headers_and_cookies(request, website);
    
    match timeout(Duration::from_secs(30), request.send()).await {
        Ok(Ok(response)) => {
            if response.status().as_u16() < 400 {
                if let Some(error_msg) = &website.error_msg {
                    let body = response.text().await.unwrap_or_default();
                    if !body.contains(error_msg) {
                        let display_url = build_url(&website.base_url, username);
                        println!("{} {} {}", "[+]".green(), website.name, display_url);
                        write_to_file(username, &format!("{}\n", display_url), file_mutex)?;
                        PROFILE_COUNT.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        }
        _ => {}
    }
    
    Ok(())
}

async fn check_by_profile_presence(
    website: &Website,
    url: &str,
    username: &str,
    client: &Client,
    file_mutex: &Arc<Mutex<()>>,
) -> Result<()> {
    let client_to_use = if !website.follow_redirects {
        create_http_client_no_redirect()?
    } else {
        client.clone()
    };
    
    let request = client_to_use.get(url);
    let request = add_headers_and_cookies(request, website);
    
    match timeout(Duration::from_secs(30), request.send()).await {
        Ok(Ok(response)) => {
            if response.status().as_u16() < 400 {
                if let Some(error_msg) = &website.error_msg {
                    let body = response.text().await.unwrap_or_default();
                    if body.contains(error_msg) {
                        println!("{} {} {}", "[+]".green(), website.name, url);
                        write_to_file(username, &format!("{}\n", url), file_mutex)?;
                        PROFILE_COUNT.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        }
        _ => {}
    }
    
    Ok(())
}

async fn check_by_response_url(
    website: &Website,
    url: &str,
    username: &str,
    client: &Client,
    file_mutex: &Arc<Mutex<()>>,
) -> Result<()> {
    let client_to_use = if !website.follow_redirects {
        create_http_client_no_redirect()?
    } else {
        client.clone()
    };
    
    let request = client_to_use.get(url);
    let request = add_headers_and_cookies(request, website);
    
    match timeout(Duration::from_secs(30), request.send()).await {
        Ok(Ok(response)) => {
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
        }
        _ => {}
    }
    
    Ok(())
}

async fn hudson_rock_search(
    username: &str,
    client: &Client,
    file_mutex: &Arc<Mutex<()>>,
) -> Result<()> {
    let url = format!("https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-username?username={}", username);
    
    match client.get(&url).send().await {
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
            println!("{} {}", "Error fetching HudsonRock data:".red(), e);
        }
    }
    
    Ok(())
}

async fn search_proxy_nova(
    username: &str,
    client: &Client,
    file_mutex: &Arc<Mutex<()>>,
) -> Result<()> {
    println!("{}", format!("[*] Searching {} on ProxyNova for any compromised passwords...", username).yellow());
    
    let url = format!("https://api.proxynova.com/comb?query={}", username);
    
    match client.get(&url).send().await {
        Ok(response) => {
            // Get the response text first
            match response.text().await {
                Ok(text) => {
                    // First try to parse as ProxyNova struct
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
                        Err(_) => {
                            // If parsing as ProxyNova fails, try to parse as raw JSON to see the structure
                            match serde_json::from_str::<serde_json::Value>(&text) {
                                Ok(json_value) => {
                                    println!("{}", "[-] ProxyNova API response format has changed or no results found".red());
                                    println!("{}", format!("Debug response: {:?}", json_value).yellow());
                                }
                                Err(e) => {
                                    println!("{} {}", "Error parsing ProxyNova response:".red(), e);
                                    println!("{}", format!("Raw response: {}", text).yellow());
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    println!("{} {}", "Error reading ProxyNova response:".red(), e);
                }
            }
        }
        Err(e) => {
            println!("{} {}", "Error searching ProxyNova:".red(), e);
        }
    }
    
    Ok(())
}

async fn search_breach_directory(
    username: &str,
    _api_key: &str,
    _client: &Client,
    _file_mutex: &Arc<Mutex<()>>,
) -> Result<()> {
    println!("{}", format!("[*] Searching {} on Breach Directory for any compromised passwords...", username).yellow());
    
    // Note: This is a placeholder as the gobreach library would need to be reimplemented
    // You would need to implement the actual Breach Directory API client
    println!("{}", "[-] Breach Directory search not yet implemented in Rust version".red());
    
    Ok(())
}

fn build_domains(username: &str) -> Vec<String> {
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

async fn search_domains(
    username: &str,
    domains: Vec<String>,
    client: &Client,
    file_mutex: &Arc<Mutex<()>>,
) -> Result<()> {
    println!("{}", format!("[*] Searching {} domains with the username {}...", domains.len(), username).yellow());
    
    let mut found_count = 0;
    let mut table = Table::new();
    table.set_header(vec!["NO", "DOMAIN", "STATUS"]);
    
    let search_tasks: Vec<_> = domains.iter()
        .map(|domain| {
            let domain = domain.clone();
            let client = client.clone();
            
            tokio::spawn(async move {
                let url = format!("http://{}", domain);
                match timeout(Duration::from_secs(10), client.get(&url).send()).await {
                    Ok(Ok(response)) => {
                        if response.status() == StatusCode::OK {
                            Some((domain, response.status()))
                        } else {
                            None
                        }
                    }
                    _ => None,
                }
            })
        })
        .collect();
    
    let results = join_all(search_tasks).await;
    
    let mut row_num = 0;
    for result in results {
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

fn write_to_file(username: &str, content: &str, file_mutex: &Arc<Mutex<()>>) -> Result<()> {
    let _guard = file_mutex.lock().map_err(|e| anyhow::anyhow!("Failed to acquire file mutex lock: {}", e))?;
    
    let filename = format!("{}.txt", username);
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&filename)?;
    
    writeln!(file, "{}", content)?;
    Ok(())
}

fn delete_old_file(username: &str) {
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