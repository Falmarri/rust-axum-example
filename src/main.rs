use std::env;
use std::error::Error;
use std::sync::Arc;

use argon2::Argon2;
use axum::extract::State;
use axum::{
    Extension,
    extract::{FromRef, FromRequest},
    middleware,
    RequestPartsExt,
    response::{IntoResponse, Response}, Router, routing::get,
};
use axum_session::{Session, SessionConfig, SessionLayer, SessionRedisPool, SessionStore};
use handlebars::{Handlebars, Output};
use redis::aio::Connection;
use redis::Client;
use redis_pool::RedisPool;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use tower_cookies::CookieManagerLayer;
use tower_http::services::ServeDir;
use tower_http::trace;
use tower_http::trace::TraceLayer;
use tracing::{info, Level};
use validator::Validate;
use state::AppState;

use crate::generated::db::PrismaClient;
use crate::template::{debug_helper, TemplateContext, TemplateResponse};
use crate::types::Sess;


mod generated;
mod template;
mod routes;
mod errors;
mod state;
mod types;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenvy::dotenv().ok();

    let prisma_client: PrismaClient =
        generated::db::new_client_with_url(env::var("DATABASE_URL").expect("DATABASE_URL env variable expected").as_str()).await?;

    tracing_subscriber::fmt()
        .with_target(false)
        .compact()
        .init();

    info!("initializing router and assets");

    let redis_client = redis::Client::open(env::var("REDIS_URL").expect("No Redis"))
        .expect("Error while trying to open the redis connection");

    let argon = Argon2::default();

    //info!("{}", Key::generate().master());
    let redis_pool = RedisPool::from(redis_client);
    // No need here to specify a table name because redis does not support tables
    let session_config = SessionConfig::default()
        //.with_security_mode(SecurityMode::PerSession)
        //.with_database_key(Key::from("test12345611111111111".as_bytes()))
        // This is How you will enable PerSession SessionID Private Cookie Encryption. When enabled it will
        // Encrypt the SessionID and Storage with an Encryption key generated and stored per session.
        // This allows for Key renewing without needing to force the entire Session from being destroyed.
        // This Also helps prevent impersonation attempts.
        //.with_security_mode(SecurityMode::Simple)
        ;

    // create SessionStore and initiate the database tables
    let session_store =
        SessionStore::<SessionRedisPool>::new(Some(redis_pool.clone().into()), session_config)
            .await
            .unwrap();

    let assets_path = env::var("ASSETS_PATH").unwrap_or(format!(
        "{}/assets",
        env::current_dir().unwrap().to_str().unwrap()
    ));

    let mut handlebars = Handlebars::new();

    handlebars.set_dev_mode(true);
    handlebars.register_helper("debug", Box::new(debug_helper));
    handlebars
        .register_templates_directory(".html", "templates/")
        .unwrap();
    let state = AppState {
        db: Arc::new(prisma_client),
        //redis: Arc::new(redis_pool),
        handlebars: Arc::new(handlebars),
    };

    let api_router = Router::new().route("/hello", get(say_hello));
    let app = Router::new()
        .route("/", get(home))
        .merge(routes::auth::auth_router())
        .with_state(state.clone())
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            routes::auth::strict_cookie_setter,
        ))
        .route_layer(SessionLayer::new(session_store))
        .route_layer(CookieManagerLayer::new())
        .nest("/api", api_router)
        .route_layer(Extension(argon))
        .nest_service("/assets", ServeDir::new(assets_path))
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(trace::DefaultMakeSpan::new().level(Level::INFO))
                .on_response(trace::DefaultOnResponse::new().level(Level::INFO)),
        );

    // run it, make sure you handle parsing your environment variables properly!
    let port = std::env::var("PORT")
        .unwrap_or_else(|_| "8000".into())
        .parse::<u16>()?;
    let addr = std::net::SocketAddr::from(([0, 0, 0, 0], port));

    info!("router initialized, not listening on port {}", port);

    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
    Ok(())
}

async fn home(
    State(state): State<AppState>, session: Sess
) -> Response {
    TemplateResponse {
        state: &state,
        template: "pages/home".into(),
        data: TemplateContext::builder(&session, ()).build(),
    }
    .into_response()
}

async fn say_hello() -> &'static str {
    "Hello!"
}
