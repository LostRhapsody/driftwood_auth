use actix_web::{web, HttpResponse, Responder};
use base64::{engine::general_purpose, Engine as _};
use dotenv::dotenv;
use oauth2::{
    basic::BasicClient, AuthUrl, AuthorizationCode, ClientId, ClientSecret, RedirectUrl,
    TokenResponse, TokenUrl,
};
use rand::rngs::OsRng;
use rsa::{pkcs8::DecodePublicKey, Pkcs1v15Encrypt, RsaPublicKey};
use std::env;

// Encrypt the token
fn encrypt_token(token: &str, public_key_pem: &str) -> String {
    let public_key =
        RsaPublicKey::from_public_key_pem(public_key_pem).expect("failed to parse public key");
    let mut rng = OsRng;
    let enc_data = public_key
        .encrypt(&mut rng, Pkcs1v15Encrypt, token.as_bytes())
        .expect("failed to encrypt");
    general_purpose::STANDARD.encode(enc_data)
}

pub(crate) fn create_oauth_client() -> BasicClient {
    dotenv().ok();
    let host = env::var("HOST").expect("Missing HOST");

    let client_id =
        ClientId::new(env::var("NETLIFY_CLIENT_ID").expect("Missing NETLIFY_CLIENT_ID"));
    let client_secret = ClientSecret::new(
        env::var("NETLIFY_CLIENT_SECRET").expect("Missing NETLIFY_CLIENT_SECRET"),
    );
    let auth_url = AuthUrl::new("https://app.netlify.com/authorize".to_string())
        .expect("Invalid authorization endpoint URL");
    let token_url = TokenUrl::new("https://api.netlify.com/oauth/token".to_string())
        .expect("Invalid token endpoint URL");

    BasicClient::new(client_id, Some(client_secret), auth_url, Some(token_url)).set_redirect_uri(
        RedirectUrl::new(host)
            .expect("Invalid redirect URL"),
    )
}

pub(crate) async fn initiate_login() -> impl Responder {
    let client = create_oauth_client();
    let (auth_url, _csrf_token) = client.authorize_url(oauth2::CsrfToken::new_random).url();

    HttpResponse::Found()
        .append_header(("Location", auth_url.to_string()))
        .finish()
}

pub(crate) async fn handle_callback(
    query: web::Query<std::collections::HashMap<String, String>>,
    client: web::Data<BasicClient>,
    public_key_pem: web::Data<String>,
) -> Result<impl Responder, actix_web::Error> {
    let code = query
        .get("code")
        .ok_or_else(|| actix_web::error::ErrorBadRequest("No code in query string"))?;
    let auth_code = AuthorizationCode::new(code.to_string());

    let token_result = client
        .get_ref()
        .exchange_code(auth_code)
        .request_async(oauth2::reqwest::async_http_client)
        .await
        .map_err(|e| {
            eprintln!("Token exchange error: {:?}", e);
            actix_web::error::ErrorInternalServerError("Token exchange failed")
        })?;

    let access_token = token_result.access_token().secret();
    let encrypted_token = encrypt_token(access_token, &public_key_pem);
    Ok(HttpResponse::Ok().json(serde_json::json!({ "encrypted_token": encrypted_token })))
}
