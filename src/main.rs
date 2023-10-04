use std::collections::HashMap;
use std::env;
use std::error::Error;
use std::sync::Arc;

use argon2::Argon2;
use axum::extract::State;
use axum::http::Request;
use axum::{
    async_trait,
    extract::{rejection::FormRejection, Form, FromRef, FromRequest},
    http::StatusCode,
    middleware,
    response::{Html, IntoResponse, Response},
    routing::get,
    Extension, RequestPartsExt, Router,
};
use axum_htmx::HxBoosted;
use axum_session::{Session, SessionConfig, SessionLayer, SessionRedisPool, SessionStore};
use derive_builder::Builder;
use handlebars::{Context, Handlebars, Helper, Output, RenderContext, RenderError};
use prisma_client_rust::serde_json::{json, Value};
use prisma_client_rust::NewClientError;
use redis::aio::Connection;
use redis::Client;
use redis_pool::RedisPool;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tower_cookies::CookieManagerLayer;
use tower_http::services::ServeDir;
use tower_http::trace;
use tower_http::trace::TraceLayer;
use tracing::{error, info, Level};
use validator::Validate;

use crate::generated::db::PrismaClient;

type Database = Arc<PrismaClient>;
type Redis = Arc<RedisPool<Client, Connection>>;
type Templates = Arc<Handlebars<'static>>;
type Sess = Session<SessionRedisPool>;
mod generated;
pub mod routes;

#[derive(Clone)]
struct AppState {
    db: Database,
    redis: Redis,
    handlebars: Templates,
}

impl FromRef<AppState> for Templates {
    fn from_ref(app_state: &AppState) -> Self {
        app_state.handlebars.clone()
    }
}

// support converting an `AppState` in an `ApiState`
impl FromRef<AppState> for Database {
    fn from_ref(app_state: &AppState) -> Database {
        app_state.db.clone()
    }
}

impl FromRef<AppState> for Redis {
    fn from_ref(app_state: &AppState) -> Redis {
        app_state.redis.clone()
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenvy::dotenv().ok();

    let prisma_client: PrismaClient =
        generated::db::new_client_with_url(env::var("DATABASE_URL").unwrap().as_str()).await?;

    tracing_subscriber::fmt()
        .with_target(false)
        .compact()
        .init();

    info!("initializing router and assets");

    let redis_client = redis::Client::open(env::var("REDIS_URL").expect("No Redis"))
        .expect("Error while tryiong to open the redis connection");

    let argon = Argon2::default();

    //info!("{}", Key::generate().master());
    let redis_pool: RedisPool<Client, Connection> = RedisPool::from(redis_client);
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
    handlebars.register_helper("debug", Box::new(format_helper));
    handlebars
        .register_templates_directory(".html", "templates/")
        .unwrap();
    let state = AppState {
        db: Arc::new(prisma_client),
        redis: Arc::new(redis_pool),
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

// Make our own error that wraps `anyhow::Error`.
#[derive(Debug, Error)]
pub enum ServerError {
    #[error(transparent)]
    ValidationError(#[from] validator::ValidationErrors),

    #[error(transparent)]
    AxumFormRejection(#[from] FormRejection),
}

#[derive(Debug, Clone, Copy, Default)]
pub struct ValidatedForm<T: FormWithTemplate>(pub T);

pub trait FormWithTemplate {
    fn full_template(&self) -> &'static str;
    fn partial_template(&self) -> &'static str;
}

fn format_helper(
    h: &Helper,
    _: &Handlebars,
    _: &Context,
    _: &mut RenderContext,
    _: &mut dyn Output,
) -> Result<(), RenderError> {
    // get parameter from helper or throw an error
    let param = h.param(0).unwrap();
    info!("{:?}", param.value());
    Ok(())
}

#[async_trait]
impl<T, S, B> FromRequest<S, B> for ValidatedForm<T>
where
    AppState: FromRef<S>,
    T: DeserializeOwned + Validate + FormWithTemplate,
    S: Send + Sync,
    Form<T>: FromRequest<S, B, Rejection = FormRejection>,
    B: Send + 'static,
{
    type Rejection = Response;

    async fn from_request(req: Request<B>, state: &S) -> Result<Self, Self::Rejection> {
        let (mut parts, body) = req.into_parts();
        let HxBoosted(boosted) = parts.extract().await.unwrap();
        let sess = parts.extract::<Sess>().await.unwrap();

        let new_req = Request::from_parts(parts, body);

        let Form(value) = Form::<T>::from_request(new_req, state).await.unwrap();

        // let (HxBoosted(boosted), sess, Form(value)): (HxBoosted, Sess, Form<T>) = req.extract().await.unwrap();
        match value.validate() {
            Ok(_) => Ok(ValidatedForm(value)),
            Err(errs) => {
                let mut m: HashMap<String, Vec<String>> = HashMap::new();
                for (k, v) in errs.field_errors() {
                    m.insert(
                        k.to_string(),
                        v.into_iter().map(|e| format!("{}", e)).collect(),
                    );
                }
                // use axum::RequestExt;

                Err(TemplateResponse {
                    template: (if boosted {
                        value.partial_template()
                    } else {
                        value.full_template()
                    })
                    .into(),
                    state: AppState::from_ref(state),
                    data: TemplateContext::builder(&sess, m).build(),
                }
                .into_response())
            }
        }
    }
}

impl IntoResponse for ServerError {
    fn into_response(self) -> Response {
        match self {
            ServerError::ValidationError(_) => {
                let message = format!("Input validation error: [{self}]").replace('\n', ", ");
                (StatusCode::BAD_REQUEST, message)
            }
            ServerError::AxumFormRejection(_) => (StatusCode::BAD_REQUEST, self.to_string()),
        }
        .into_response()
    }
}

#[derive(Serialize, Deserialize, Clone)]
struct UserSession {
    user_id: String,
    username: String,
}

struct TemplateResponse<T: Serialize + Clone> {
    template: &'static str,
    state: AppState,
    data: TemplateContext<T>,
}

#[derive(Builder, Serialize)]
#[builder(custom_constructor, build_fn(private, name = "fallible_build"))]
#[builder(field(private))]
struct TemplateContext<T: Serialize + Clone> {
    data: T,
    #[builder(setter(strip_option))]
    user: Option<UserSession>,
    #[builder(default, setter(into))]
    flash: Vec<Flash>,
}

impl<T> TemplateContext<T>
where
    T: Serialize + Clone,
{
    pub fn builder(sess: &Sess, data: T) -> TemplateContextBuilder<T> {
        TemplateContextBuilder::new(sess, data)
    }
}

impl<T> TemplateContextBuilder<T>
where
    T: Serialize + Clone,
{
    pub fn new(sess: &Sess, data: T) -> Self {
        Self {
            data: Some(data),
            user: Some(sess.get("user")),
            flash: Some(vec![]),
        }
    }

    pub fn build(&self) -> TemplateContext<T> {
        self.fallible_build()
            .expect("All required fields set upfront")
    }
}

#[derive(Debug, Serialize, Clone)]
struct Flash {
    message: &'static str,
}

impl<'a, T> IntoResponse for TemplateResponse<T>
where
    T: Send + Sync + Serialize + Clone,
{
    fn into_response(self) -> Response {
        match self.state.handlebars.render(self.template, &self.data) {
            Ok(r) => Html(r),
            Err(e) => {
                error!("Error rendering template: {:?}", e);
                Html("Error".into())
            }
        }
        .into_response()
    }
}

async fn home(State(state): State<AppState>, session: Sess) -> Response {
    let j: &Value = &json!({
        "name": "test",
        "age": 1
    });
    TemplateResponse {
        state,
        template: "pages/home".into(),
        data: TemplateContext::builder(&session, j.clone()).build(),
    }
    .into_response()
}

async fn say_hello() -> &'static str {
    "Hello!"
}
