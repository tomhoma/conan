use actix_files::Files;
use actix_web::{web, App, HttpServer, Responder, HttpResponse};
use serde::Deserialize;
use std::sync::{Arc, Mutex};

use crate::search::{
    self, load_website_data, search_websites_batched, hudson_rock_search, search_proxy_nova,
    search_domains, delete_old_file, HTTP_CLIENT,
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

    // The search functions write to a file, so we'll use that to capture the output.
    let output_filename = format!("{}.txt", username);
    delete_old_file(username);

    let file_mutex = Arc::new(Mutex::new(()));

    // Run all the search functions.
    let data = match load_website_data() {
        Ok(data) => data,
        Err(_) => return HttpResponse::InternalServerError().body("Failed to load website data."),
    };
    search_websites_batched(username, data.websites, &file_mutex, false).await;

    if let Err(e) = hudson_rock_search(username, &file_mutex).await {
        return HttpResponse::InternalServerError().body(format!("Error during HudsonRock search: {}", e));
    }

    if let Some(key) = api_key {
        if !key.is_empty() {
            let breach_client = BreachDirectoryClient::new(key.to_string(), HTTP_CLIENT.clone());
            if let Err(e) = breach_client.search(username, &file_mutex).await {
                return HttpResponse::InternalServerError().body(format!("Error during Breach Directory search: {}", e));
            }
        }
    }

    if let Err(e) = search_proxy_nova(username, &file_mutex).await {
        return HttpResponse::InternalServerError().body(format!("Error during ProxyNova search: {}", e));
    }

    let domains = search::build_domains(username);
    if let Err(e) = search_domains(username, domains, &file_mutex).await {
        return HttpResponse::InternalServerError().body(format!("Error during domain search: {}", e));
    }

    // Read the output file.
    match std::fs::read_to_string(&output_filename) {
        Ok(contents) => {
            // Clean up the file.
            let _ = std::fs::remove_file(&output_filename);
            HttpResponse::Ok().body(contents)
        }
        Err(_) => HttpResponse::InternalServerError().body("Could not retrieve search results."),
    }
}

pub async fn start_server() -> std::io::Result<()> {
    HttpServer::new(|| {
        App::new()
            .route("/search", web::post().to(search))
            .service(Files::new("/", "src/web/static/").index_file("index.html"))
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}