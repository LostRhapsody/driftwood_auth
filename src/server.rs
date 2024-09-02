use actix_web::{web, HttpResponse, Responder};
use base64::{engine::general_purpose, Engine as _};
use dotenv::dotenv;
use oauth2::{
    basic::BasicClient, AuthUrl, AuthorizationCode, ClientId, ClientSecret, RedirectUrl,
    TokenResponse, TokenUrl,
};
use rand::rngs::OsRng;
use rsa::{pkcs8::DecodePublicKey, Pkcs1v15Encrypt, RsaPublicKey};
use std::{env,sync::Arc, time::Instant, time::Duration};
use dashmap::DashMap;

/// For storing public key's in memory between requests
pub struct KeyValueStore {
    store: Arc<DashMap<String, (String,Instant)>>
}

impl KeyValueStore {
    pub fn new() -> Self {
        Self {
            store: Arc::new(DashMap::new())
        }
    }

    pub fn set(&self, key: String, value: String, ttl: Duration) {
        let expiry = Instant::now() + ttl;
        self.store.insert(key, (value, expiry));
    }

    pub fn get(&self, key: &str) -> Option<String> {
        self.store.get(key).and_then(|entry| {
            let (value, expiry) = entry.value();
            if Instant::now() < *expiry {
                Some(value.clone())
            } else {
                self.store.remove(key);
                None
            }
        })
    }

    pub fn remove(&self, key: &str){
        self.store.remove(key);
    }
}

pub struct AppState {
    kv_store: KeyValueStore,
}

impl AppState {
    pub fn new() -> Self {
        Self {
            kv_store: KeyValueStore::new(),
        }
    }
}

// Encrypt the token
fn encrypt_token(token: &str, public_key_pem: &str) -> String {
    println!("Encrypting token");
    let public_key =
        RsaPublicKey::from_public_key_pem(public_key_pem).expect("failed to parse public key");
    let mut rng = OsRng;
    let enc_data = public_key
        .encrypt(&mut rng, Pkcs1v15Encrypt, token.as_bytes())
        .expect("failed to encrypt");
    general_purpose::STANDARD.encode(enc_data)
}

pub(crate) fn create_oauth_client() -> BasicClient {
    println!("Creating OAuth2.0 Client");
    dotenv().ok();
    let redirect_url = env::var("NETLIFY_REDIRECT_URI").expect("Missing HOST");

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
        RedirectUrl::new(redirect_url)
            .expect("Invalid redirect URL"),
    )
}

pub(crate) async fn initiate_login(
    query: web::Query<std::collections::HashMap<String, String>>,
    app_state: web::Data<AppState>,
) -> impl Responder {
    println!("Logging in...");
    let client = create_oauth_client();
    let (auth_url, _csrf_token) = client.authorize_url(oauth2::CsrfToken::new_random).url();

    let public_key_pem = query.get("public_key_pem").unwrap();

    // store in memory in app state
    app_state.kv_store.set(
        _csrf_token.secret().to_string(),
        public_key_pem.to_string(),
        Duration::from_secs(600) // 10 mintues
    );

    HttpResponse::Found()
        .append_header(("Location", auth_url.to_string()))
        .finish()
}

pub(crate) async fn handle_callback(
    query: web::Query<std::collections::HashMap<String, String>>,
    client: web::Data<BasicClient>,
    app_state: web::Data<AppState>,
) -> Result<impl Responder, actix_web::Error> {
    println!("Callback...");
    let code = query
        .get("code")
        .ok_or_else(|| actix_web::error::ErrorBadRequest("No code in query string"))?;

    println!("Code: {}", code);

    let auth_code = AuthorizationCode::new(code.to_string());

    let state = query
        .get("state")
        .ok_or_else(|| actix_web::error::ErrorBadRequest("No state in query string"))?;

    println!("State: {}", state);

    // retrieve public_key_pem from in-memory storage
    let public_key_pem = app_state.kv_store.get(state)
        .ok_or_else(|| {
            eprintln!("No public key found for state: {}", state);
            actix_web::error::ErrorInternalServerError("No public key found for this state")
        })?;

    print!("Public key pem: {}", public_key_pem);

    let token_result = client
        .exchange_code(auth_code)
        .request_async(oauth2::reqwest::async_http_client)
        .await
        .map_err(|e| {
            eprintln!("Token exchange error: {:?}", e);
            actix_web::error::ErrorInternalServerError("Token exchange failed")
        })?;

    let access_token = token_result.access_token().secret();
    println!("Token: {}", access_token);

    // encrypt the token
    let encrypted_token = encrypt_token(access_token, &public_key_pem);
    // remove the state/public key from memory, we no longer need it
    app_state.kv_store.remove(state);

    println!("Encrypted token: {}", encrypted_token);
    Ok(HttpResponse::Ok().json(serde_json::json!({ "token": encrypted_token })))
}
