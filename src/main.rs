use anyhow::Result;
use clap::{Parser, Subcommand, Args};
use colored::*;
use comfy_table::{Table, Cell, Attribute};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::Instant;

// Import models and modules
use conan::breach_directory::BreachDirectoryClient;
use conan::search::{
    self, load_website_data, search_websites_batched, hudson_rock_search, search_proxy_nova,
    search_domains, delete_old_file, PROFILE_COUNT, HTTP_CLIENT,
};
use conan::utils::write_to_file;
use conan::web::server::start_server;

const ASCII_LOGO: &str = r#"
 ________   ________   ________    ________   ________      
|\   ____\ |\   __  \ |\   ___  \ |\   __  \ |\   ___  \    
\ \  \___| \ \  \|\  \\ \  \\ \  \\ \  \|\  \\ \  \\ \  \   
 \ \  \     \ \  \\\  \\ \  \\ \  \\ \   __  \\ \  \\ \  \  
  \ \  \____ \ \  \\\  \\ \  \\ \  \\ \  \ \  \\ \  \\ \  \ 
   \ \_______\\ \_______\\ \__\\ \__\\ \__\ \__\\ \__\\ \__\
    \|_______| \|_______| \|__| \|__| \|__|\|__| \|__| \|__|

"#;

const VERSION: &str = "v1.0.0";

#[derive(Parser, Debug)]
#[command(name = "conan")]
#[command(version = VERSION)]
#[command(about = "Search for usernames across various websites", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Run a CLI search
    Search(SearchArgs),
    /// Start the web server
    Web,
}

#[derive(Debug, Args)]
struct SearchArgs {
    /// Username to search
    #[arg(short, long)]
    username: String,

    /// Do not show false positives
    #[arg(long = "no-false-positives")]
    no_false_positives: bool,

    /// Search Breach Directory with an API Key
    #[arg(short = 'b', long = "breach-directory")]
    breach_directory_api_key: Option<String>,
}


#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    
    let cli = Cli::parse();
    
    match cli.command {
        Commands::Web => {
            println!("Starting web server at http://127.0.0.1:8080");
            start_server().await?;
        }
        Commands::Search(args) => {
            let username = &args.username;

            // Delete old output file
            delete_old_file(username);

            // Load website data
            let data = match load_website_data() {
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

            let file_mutex = Arc::new(Mutex::new(()));

            // Search websites with smart batching
            search_websites_batched(username, data.websites, &file_mutex, args.no_false_positives).await;

            println!("\n");

            // Search HudsonRock
            if let Err(e) = write_to_file(username, &"⎯".repeat(85), &file_mutex) {
                eprintln!("{} {}", "Error writing to file:".red(), e);
            }
            println!("{}", "[*] Searching HudsonRock's Cybercrime Intelligence Database...".yellow());
            if let Err(e) = hudson_rock_search(username, &file_mutex).await {
                eprintln!("{} {}", "Error searching HudsonRock:".red(), e);
            }
            
            // Search Breach Directory if API key provided
            if let Some(api_key) = args.breach_directory_api_key {
                println!("\n");
                let breach_client = BreachDirectoryClient::new(api_key, HTTP_CLIENT.clone());
                if let Err(e) = breach_client.search(username, &file_mutex).await {
                    eprintln!("{} {}", "Error searching Breach Directory:".red(), e);
                }
            }

            println!("\n");

            // Search ProxyNova
            if let Err(e) = write_to_file(username, &"⎯".repeat(85), &file_mutex) {
                eprintln!("{} {}", "Error writing to file:".red(), e);
            }
            if let Err(e) = search_proxy_nova(username, &file_mutex).await {
                eprintln!("{} {}", "Error searching ProxyNova:".red(), e);
            }

            println!("\n");

            // Search domains
            let domains = search::build_domains(username);
            if let Err(e) = search_domains(username, domains, &file_mutex).await {
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
            
            if let Err(e) = write_to_file(username, &format!(":: Number of profiles found              : {}", PROFILE_COUNT.load(Ordering::Relaxed)), &file_mutex) {
                eprintln!("{} {}", "Error writing to file:".red(), e);
            }
            if let Err(e) = write_to_file(username, &format!(":: Total time taken                      : {:?}", elapsed), &file_mutex) {
                eprintln!("{} {}", "Error writing to file:".red(), e);
            }
        }
    }

    Ok(())
}