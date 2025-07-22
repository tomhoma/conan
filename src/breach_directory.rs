use anyhow::Result;
use colored::*;
use comfy_table::{Table, Cell};
use reqwest::Client;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::time::timeout;

use crate::models::{BreachDirectoryResponse, WeakpassResponse};

const DEFAULT_USER_AGENT: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:140.0) Gecko/20100101 Firefox/140.0";

pub struct BreachDirectoryClient {
    client: Client,
    api_key: String,
}

impl BreachDirectoryClient {
    pub fn new(api_key: String, client: Client) -> Self {
        Self { client, api_key }
    }
    
    pub async fn search(&self, username: &str, file_mutex: &Arc<Mutex<()>>) -> Result<()> {
        println!("{}", format!("[*] Searching {} on Breach Directory for any compromised passwords...", username).yellow());
        
        // Construct API URL for RapidAPI Breach Directory
        let url = format!("https://breachdirectory.p.rapidapi.com/?func=auto&term={}", username);
        
        let request = self.client.get(&url)
            .header("x-rapidapi-key", &self.api_key)
            .header("x-rapidapi-host", "breachdirectory.p.rapidapi.com")
            .header("User-Agent", DEFAULT_USER_AGENT);
        
        match timeout(Duration::from_secs(30), request.send()).await {
            Ok(Ok(response)) => {
                if !response.status().is_success() {
                    println!("{}", format!("[-] API request failed with status: {}", response.status()).red());
                    return Ok(());
                }
                
                // Parse JSON response and properly handle breach data
                match response.json::<BreachDirectoryResponse>().await {
                    Ok(breach_response) => {
                        if !breach_response.success {
                            println!("{}", format!("[-] Breach Directory API returned error").red());
                            return Ok(());
                        }
                        
                        if breach_response.found == 0 {
                            println!("{}", format!("[-] No breaches found for {}.", username).red());
                            self.write_to_file(username, &format!("[-] No breaches found on Breach Directory for: {}", username), file_mutex)?;
                            return Ok(());
                        }
                        
                        // Display found breaches
                        println!("{}", format!("[+] Found {} breaches for {}:", breach_response.found, username).green());
                        
                        let mut table = Table::new();
                        table.load_preset(comfy_table::presets::UTF8_FULL);
                        table.set_header(vec!["#", "Email", "Password", "Hash", "Sources"]);
                        
                        let mut file_content = String::new();
                        file_content.push_str(&format!("[+] Found {} breaches for {}\n", breach_response.found, username));
                        
                        for (i, entry) in breach_response.result.iter().enumerate() {
                            let mut cracked_password = String::new();
                            
                            // Attempt to crack hash if available
                            if let Some(hash) = &entry.hash {
                                if !hash.is_empty() {
                                    println!("{}", format!("[*] Attempting to crack hash: {}...", &hash[..8.min(hash.len())]).yellow());
                                    match self.crack_hash(hash).await {
                                        Ok(pass) if !pass.is_empty() => {
                                            cracked_password = pass;
                                            println!("{}", format!("[+] Hash cracked successfully!").green());
                                        }
                                        _ => {
                                            println!("{}", format!("[-] Unable to crack hash").red());
                                        }
                                    }
                                }
                            }
                            
                            // Use cracked password if available, otherwise use stored password
                            let display_password = if !cracked_password.is_empty() {
                                format!("{} (cracked)", cracked_password)
                            } else if let Some(password) = &entry.password {
                                password.clone()
                            } else {
                                "N/A".to_string()
                            };
                            
                            table.add_row(vec![
                                Cell::new(i + 1),
                                Cell::new(entry.email.as_deref().unwrap_or("N/A")),
                                Cell::new(&display_password),
                                Cell::new(entry.hash.as_deref().unwrap_or("N/A")),
                                Cell::new(&entry.sources),
                            ]);
                            
                            // Add to file content
                            file_content.push_str(&format!("[-] Breach #{}\n", i + 1));
                            file_content.push_str(&format!(":: Email: {}\n", entry.email.as_deref().unwrap_or("N/A")));
                            file_content.push_str(&format!(":: Password: {}\n", display_password));
                            file_content.push_str(&format!(":: Hash: {}\n", entry.hash.as_deref().unwrap_or("N/A")));
                            file_content.push_str(&format!(":: SHA1: {}\n", entry.sha1.as_deref().unwrap_or("N/A")));
                            file_content.push_str(&format!(":: Sources: {}\n", entry.sources));
                            file_content.push_str("\n");
                        }
                        
                        println!("{}", table);
                        self.write_to_file(username, &file_content, file_mutex)?;
                    }
                    Err(e) => {
                        println!("{}", format!("[-] Error parsing Breach Directory response: {}", e).red());
                    }
                }
            }
            Ok(Err(e)) => {
                println!("{}", format!("[-] Error searching Breach Directory: {}", e).red());
            }
            Err(_) => {
                println!("{}", format!("[-] Breach Directory request timed out").red());
            }
        }
        
        Ok(())
    }
    
    async fn crack_hash(&self, hash: &str) -> Result<String> {
        let url = format!("https://weakpass.com/api/v1/search/{}.json", hash);
        
        let request = self.client.get(&url)
            .header("User-Agent", DEFAULT_USER_AGENT)
            .header("Accept", "application/json");
        
        match timeout(Duration::from_secs(15), request.send()).await {
            Ok(Ok(response)) => {
                if response.status().is_success() {
                    match response.json::<WeakpassResponse>().await {
                        Ok(weakpass_response) => Ok(weakpass_response.pass),
                        Err(_) => Ok(String::new()),
                    }
                } else {
                    Ok(String::new())
                }
            }
            _ => Ok(String::new()),
        }
    }
    
    fn write_to_file(&self, username: &str, content: &str, file_mutex: &Arc<Mutex<()>>) -> Result<()> {
        use std::fs::OpenOptions;
        use std::io::Write;
        
        let _guard = file_mutex.lock().map_err(|e| anyhow::anyhow!("Failed to acquire file mutex lock: {}", e))?;
        
        let filename = format!("{}.txt", username);
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&filename)?;
        
        writeln!(file, "{}", content)?;
        Ok(())
    }
}