use std::env;
use actix_web::{web, App, HttpServer};
use server::AppState;

mod server;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let oauth_client = web::Data::new(server::create_oauth_client());
    let host = env::var("HOST").expect("Missing HOST");
    env_logger::init();

    let app_state = web::Data::new(AppState::new());

    HttpServer::new(move || {
        App::new()
            .app_data(app_state.clone())
            .app_data(oauth_client.clone())
            .route("/login", web::get().to(server::initiate_login))
            .route("/callback", web::get().to(server::handle_callback))
    })
    .bind(host)?
    .run()
    .await
}
