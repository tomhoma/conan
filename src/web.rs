use actix_files::Files;
use actix_web::{web, App, HttpServer, Responder, HttpResponse};

async fn index() -> impl Responder {
    HttpResponse::Ok().content_type("text/html").body(r#"
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Conan OSINT Tool</title>
            <style>
                body {
                    font-family: Arial, sans-serif;
                    line-height: 1.6;
                    max-width: 800px;
                    margin: 40px auto;
                    padding: 0 20px;
                    background: #f7f7f7;
                }
                h1 {
                    color: #333;
                    text-align: center;
                    margin-bottom: 30px;
                }
                form {
                    background: white;
                    padding: 20px;
                    border-radius: 8px;
                    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                }
                input[type="text"] {
                    width: 100%;
                    padding: 10px;
                    margin-bottom: 10px;
                    border: 1px solid #ddd;
                    border-radius: 4px;
                    font-size: 16px;
                }
                button {
                    width: 100%;
                    padding: 10px;
                    background: #0066cc;
                    color: white;
                    border: none;
                    border-radius: 4px;
                    font-size: 16px;
                    cursor: pointer;
                }
                button:hover {
                    background: #0052a3;
                }
            </style>
        </head>
        <body>
            <h1>Conan OSINT Tool</h1>
            <form id="conan-form" method="post" action="/run">
                <input type="text" name="query" placeholder="Enter username to search..." required>
                <button type="submit">Search</button>
            </form>
        </body>
        </html>
    "#)
}


use conan::website;

async fn run_conan(query: web::Form<std::collections::HashMap<String, String>>) -> impl Responder {
    let username = query.get("query").cloned().unwrap_or_default();
    if username.is_empty() {
        return HttpResponse::BadRequest().body("No username provided");
    }

    // Load website data
    let data = match website::load_website_data().await {
        Ok(data) => data,
        Err(e) => return HttpResponse::InternalServerError().body(format!("Error loading website data: {}", e)),
    };

    let mut output = String::new();
    output.push_str(&format!("<b>Username:</b> {}<br><b>Websites:</b> {}<br><br>", username, data.websites.len()));

    // Create a nicely formatted HTML result
    let mut result_html = format!(r#"
        <div class="results">
            <div class="summary">
                <h2>Results for username: {}</h2>
                <p>Checking {} websites...</p>
            </div>
            <div class="profiles">
    "#, username, data.websites.len());

    // Search websites and format results
    for website in &data.websites {
        let url = if let Some(probe_url) = &website.url_probe {
            probe_url.replace("{}", &username)
        } else {
            website.base_url.replace("{}", &username)
        };
        result_html.push_str(&format!(r#"
            <div class="profile-item">
                <span class="site-name">{}</span>
                <a href="{}" target="_blank" rel="noopener noreferrer">{}</a>
            </div>
        "#, website.name, url, url));
    }

    result_html.push_str("</div></div>");

    // Return formatted HTML with styles
    HttpResponse::Ok().content_type("text/html").body(format!(r#"
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Conan OSINT Results</title>
            <style>
                body {{ font-family: Arial, sans-serif; padding: 20px; max-width: 1200px; margin: 0 auto; }}
                .results {{ background: #f5f5f5; padding: 20px; border-radius: 8px; }}
                .summary {{ margin-bottom: 20px; }}
                .profile-item {{ 
                    background: white;
                    padding: 10px;
                    margin: 10px 0;
                    border-radius: 4px;
                    box-shadow: 0 1px 3px rgba(0,0,0,0.1);
                }}
                .site-name {{
                    font-weight: bold;
                    margin-right: 10px;
                    color: #333;
                }}
                a {{ color: #0066cc; text-decoration: none; }}
                a:hover {{ text-decoration: underline; }}
            </style>
        </head>
        <body>
            {}
            <p><a href="/">&larr; Back to Search</a></p>
        </body>
        </html>
    "#, result_html))
}

pub fn main() -> std::io::Result<()> {
    actix_web::rt::System::new().block_on(async move {
        HttpServer::new(|| {
            App::new()
                .route("/", web::get().to(index))
                .service(web::resource("/run").route(web::post().to(run_conan)))
                .service(Files::new("/static", "static").show_files_listing())
        })
        .bind(("127.0.0.1", 8080))?
        .run()
        .await
    })
}
