use std::env;
use actix_session::{SessionMiddleware, storage::CookieSessionStore};
use actix_web::{cookie::Key, web, App, HttpServer};

mod server;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let oauth_client = web::Data::new(server::create_oauth_client());
    let host = env::var("HOST").expect("Missing HOST");
    env_logger::init();

    // Generate a random secret key for cookie encryption
    // let secret_key = Key::generate();

    HttpServer::new(move || {
        App::new()
            // .wrap(SessionMiddleware::new(
            //     CookieSessionStore::default(),
            //     secret_key.clone(),
            // ))
            .app_data(oauth_client.clone())
            .route("/login", web::get().to(server::initiate_login))
            .route("/callback", web::get().to(server::handle_callback))
    })
    .bind(host)?
    .run()
    .await
}
