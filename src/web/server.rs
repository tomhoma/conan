use actix_files::Files;
use actix_web::{web, App, HttpServer, Responder, HttpResponse, middleware};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};

use crate::search::{
    self, load_website_data, search_websites_batched, hudson_rock_search, search_proxy_nova,
    search_domains, delete_old_file, HTTP_CLIENT, PROFILE_COUNT,
};
use crate::breach_directory::BreachDirectoryClient;

#[derive(Deserialize)]
struct SearchRequest {
    username: String,
    api_key: Option<String>,
}

async fn search(req: web::Json<SearchRequest>) -> impl Responder {
    let username = &req.username;
    let api_key = req.api_key.as_deref();

    // Validate username input
    if username.is_empty() || username.len() > 100 {
        return HttpResponse::BadRequest().body("Invalid username: must be between 1-100 characters");
    }

    // Sanitize username to prevent path traversal
    if username.contains("..") || username.contains("/") || username.contains("\\") {
        return HttpResponse::BadRequest().body("Invalid username: contains illegal characters");
    }

    // Reset profile count for this search
    search::PROFILE_COUNT.store(0, std::sync::atomic::Ordering::Relaxed);

    // The search functions write to a file, so we'll use that to capture the output.
    let output_filename = format!("{}.txt", username);
    delete_old_file(username);

    let file_mutex = Arc::new(Mutex::new(()));

    // Run all the search functions.
    let data = match load_website_data() {
        Ok(data) => data,
        Err(e) => {
            eprintln!("Failed to load website data: {}", e);
            return HttpResponse::InternalServerError().body("Failed to load website data.");
        },
    };
    // Execute search with proper error handling and cleanup
    let search_result = async {
        search_websites_batched(username, data.websites, &file_mutex, false).await;

        hudson_rock_search(username, &file_mutex).await
            .map_err(|e| format!("HudsonRock search failed: {}", e))?;

        if let Some(key) = api_key {
            if !key.is_empty() {
                let breach_client = BreachDirectoryClient::new(key.to_string(), HTTP_CLIENT.clone());
                breach_client.search(username, &file_mutex).await
                    .map_err(|e| format!("Breach Directory search failed: {}", e))?;
            }
        }

        search_proxy_nova(username, &file_mutex).await
            .map_err(|e| format!("ProxyNova search failed: {}", e))?;

        let domains = search::build_domains(username);
        search_domains(username, domains, &file_mutex).await
            .map_err(|e| format!("Domain search failed: {}", e))?;

        Ok::<(), String>(())
    }.await;

    // Ensure file cleanup happens regardless of success or failure
    let response = match std::fs::read_to_string(&output_filename) {
        Ok(contents) => {
            if let Err(e) = search_result {
                eprintln!("Search completed with errors: {}", e);
                HttpResponse::Ok().body(format!("{}\n\n[!] Some searches failed: {}", contents, e))
            } else {
                HttpResponse::Ok().body(contents)
            }
        }
        Err(e) => {
            eprintln!("Failed to read results file: {}", e);
            HttpResponse::InternalServerError().body("Could not retrieve search results.")
        }
    };

    // Always cleanup the file
    let _ = std::fs::remove_file(&output_filename);

    response
}

#[derive(Serialize)]
struct HealthResponse {
    status: String,
    version: String,
}

#[derive(Serialize)]
struct StatusResponse {
    server: String,
    version: String,
    uptime: String,
    websites_loaded: bool,
}

async fn health_check() -> impl Responder {
    HttpResponse::Ok().json(HealthResponse {
        status: "healthy".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
    })
}

async fn status() -> impl Responder {
    let websites_loaded = load_website_data().is_ok();

    HttpResponse::Ok().json(StatusResponse {
        server: "Conan OSINT".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        uptime: format!("{:?}", std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()),
        websites_loaded,
    })
}

#[derive(Deserialize)]
struct BatchSearchRequest {
    usernames: Vec<String>,
    api_key: Option<String>,
}

#[derive(Serialize)]
struct BatchSearchResponse {
    results: Vec<BatchResult>,
}

#[derive(Serialize)]
struct BatchResult {
    username: String,
    success: bool,
    message: String,
    profile_count: u32,
}

async fn batch_search(req: web::Json<BatchSearchRequest>) -> impl Responder {
    let mut results = Vec::new();

    for username in &req.usernames {
        // Validate username
        if username.is_empty() || username.len() > 100 {
            results.push(BatchResult {
                username: username.clone(),
                success: false,
                message: "Invalid username".to_string(),
                profile_count: 0,
            });
            continue;
        }

        if username.contains("..") || username.contains("/") || username.contains("\\") {
            results.push(BatchResult {
                username: username.clone(),
                success: false,
                message: "Invalid characters in username".to_string(),
                profile_count: 0,
            });
            continue;
        }

        // Reset counter and perform search
        PROFILE_COUNT.store(0, std::sync::atomic::Ordering::Relaxed);
        delete_old_file(username);

        let file_mutex = Arc::new(Mutex::new(()));

        let data = match load_website_data() {
            Ok(data) => data,
            Err(_) => {
                results.push(BatchResult {
                    username: username.clone(),
                    success: false,
                    message: "Failed to load website data".to_string(),
                    profile_count: 0,
                });
                continue;
            }
        };

        search_websites_batched(username, data.websites, &file_mutex, false).await;
        let _ = hudson_rock_search(username, &file_mutex).await;

        if let Some(key) = &req.api_key {
            if !key.is_empty() {
                let breach_client = BreachDirectoryClient::new(key.to_string(), HTTP_CLIENT.clone());
                let _ = breach_client.search(username, &file_mutex).await;
            }
        }

        let _ = search_proxy_nova(username, &file_mutex).await;
        let domains = search::build_domains(username);
        let _ = search_domains(username, domains, &file_mutex).await;

        let count = PROFILE_COUNT.load(std::sync::atomic::Ordering::Relaxed);

        results.push(BatchResult {
            username: username.clone(),
            success: true,
            message: format!("Found {} profiles", count),
            profile_count: count,
        });
    }

    HttpResponse::Ok().json(BatchSearchResponse { results })
}

pub async fn start_server() -> std::io::Result<()> {
    println!("🚀 Starting Conan OSINT Server");
    println!("📍 Server URL: http://127.0.0.1:8080");
    println!("🏥 Health check: http://127.0.0.1:8080/health");
    println!("📊 Status: http://127.0.0.1:8080/status");

    HttpServer::new(|| {
        App::new()
            .wrap(middleware::Logger::default())
            .wrap(
                middleware::DefaultHeaders::new()
                    .add(("X-Version", env!("CARGO_PKG_VERSION")))
            )
            .route("/health", web::get().to(health_check))
            .route("/status", web::get().to(status))
            .route("/search", web::post().to(search))
            .route("/batch-search", web::post().to(batch_search))
            .service(Files::new("/", "src/web/static/").index_file("index.html"))
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}