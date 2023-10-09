use argon2::{Argon2, password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, rand_core::OsRng, SaltString}, password_hash};
use axum::extract::{FromRef, FromRequestParts, State};
use axum::http::request::Parts;
use axum::middleware::Next;
use axum::response::{AppendHeaders, IntoResponse, Redirect, Response};
use axum::routing::get;
use axum::{async_trait, debug_handler, Extension, http, Router};
use axum_htmx::HxBoosted;
use axum_session::{Session, SessionRedisPool};
use http::{Request, StatusCode};
use serde::Deserialize;
use tower_cookies::cookie::SameSite;
use tower_cookies::{Cookie, Cookies};
use tracing::{error, info};
use validator::{Validate, ValidationError};

use crate::generated::db;
use crate::{
    TemplateContext, TemplateResponse,
};
use crate::errors::ServerError;
use crate::state::AppState;
use crate::template::{FormWithTemplate, ValidatedForm};
use crate::types::{Database, Sess, UserSession};

const STRICT_COOKIE_NAME: &str = "_s";

pub struct Strict;

pub async fn strict_cookie_setter<B>(
    strict: Option<Strict>,
    cookies: Cookies,
    request: Request<B>,
    next: Next<B>,
) -> Result<Response, StatusCode> {
    let response = next.run(request).await;
    if let None = strict {
        cookies.add(
            Cookie::build(STRICT_COOKIE_NAME, "ZC2CucXpm5")
                .path("/")
                .same_site(SameSite::Strict)
                .http_only(true)
                .finish(),
        );
    }
    Ok(response)
}

#[async_trait]
impl<S> FromRequestParts<S> for Strict
where
    AppState: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = StatusCode;

    async fn from_request_parts(req: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let cookies = Cookies::from_request_parts(req, state).await.unwrap();

        match cookies.get(STRICT_COOKIE_NAME) {
            Some(_) => Ok(Strict),
            None => Err(StatusCode::UNAUTHORIZED),
        }
    }
}

#[async_trait]
impl<S> FromRequestParts<S> for UserSession
where
    AppState: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = StatusCode;

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Self::Rejection> {
        use axum::RequestPartsExt;
        let session = parts.extract::<Session<SessionRedisPool>>().await.unwrap();

        session.get("user").ok_or(StatusCode::UNAUTHORIZED)
    }
}

pub(crate) fn auth_router() -> Router<AppState> {
    Router::new()
        .route("/login", get(get_login).post(do_login))
        .route("/signup", get(get_signup).post(do_signup))
        .route("/logout", get(do_logout))
}

#[derive(Debug, Deserialize, Validate)]
struct Login {
    #[validate(length(min = 2, max = 16, message = "Must be between 2 and 16 characters"))]
    username: String,
    #[validate(length(min = 3, message = "Must be longer than 3 characters"))]
    password: String,
}

impl FormWithTemplate for Login {

    fn template(&self, partial: &bool) -> &'static str {
        if *partial { "components/login_form" } else { "pages/login" }
    }
}

async fn do_logout(_: Strict, session: Sess) -> Response {
    session.destroy();
    Redirect::to("/").into_response()
}

async fn get_login(State(state): State<AppState>, session: Sess) -> Response {
    TemplateResponse {
        template: "pages/login",
        state: &state,
        data: TemplateContext::builder(&session, ()).build(),
    }.into_response()
}

async fn do_login(
    _: Strict,
    HxBoosted(boosted): HxBoosted,
    Extension(argon): Extension<Argon2<'static>>,
    State(db): State<Database>,
    State(state): State<AppState>,
    session: Sess,
    ValidatedForm(login): ValidatedForm<Login>,
) -> Response {

    let err = | e: &'static str, v: &'static str| -> TemplateResponse<validator::ValidationErrors> {
        let mut error = validator::ValidationErrors::new();
        error.add(e, validator::ValidationError::new(v));
        TemplateResponse {
            template: login.template(&boosted),
            state: &state,
            data: TemplateContext::builder(&session, error).build()
        }
    };

    if let Some(user) = db
        .account()
        .find_unique(db::account::username::equals(login.username.to_lowercase()))
        .exec()
        .await
        .unwrap()
    {
        if let Some(user_password) = user.password_hash {
            let parsed_hash = PasswordHash::new(&user_password).unwrap();

            match argon.verify_password(login.password.as_bytes(), &parsed_hash) {
                Ok(_) => {
                    session.set(
                        "user",
                        UserSession {
                            user_id: user.user_id.clone(),
                            username: user.username.clone(),
                        },
                    );
                    session.renew();
                    info!("User {} logged in", user.user_id);
                    if boosted {
                        AppendHeaders([("HX-Location", "/")]).into_response()
                    } else {
                        Redirect::to("/").into_response()
                    }
                }
                Err(password_hash::errors::Error::Password) => {
                    info!("Incorrect password for user {}", user.user_id);
                    err("password", "Incorrect password").into_response()
                }
                Err(e) => {
                    error!("Error authenticating user {}", user.user_id);
                    err("form", "Unknown error authenticating").into_response()
                }
            }
        } else {
            error!("User is disabled or something {}", user.user_id);
            err("form", "Unable to log in, contact administrator").into_response()
        }
    } else {
        info!("Unknown user {} attempted login", login.username);
        err("username", "User doesn't exist").into_response()
    }

}

#[derive(Debug, Deserialize, Validate)]
struct Signup {
    username: String,
    password: String,
    email: Option<String>,
}

impl FormWithTemplate for Signup {

    fn template(&self, partial: &bool) -> &'static str {
        if *partial { "components/signup_form" } else { "pages/signup" }
    }
}

async fn get_signup(State(state): State<AppState>, session: Sess) -> Response {
    TemplateResponse {
        state: &state,
        template: "pages/signup",
        data: TemplateContext::builder(&session, ()).build(),
    }.into_response()
}


async fn do_signup(
    _: Strict,
    HxBoosted(boosted): HxBoosted,
    Extension(argon): Extension<Argon2<'static>>,
    State(state): State<AppState>,
    session: Sess,
    ValidatedForm(signup): ValidatedForm<Signup>,
) -> Response {

    let err = | e: &'static str, v: &'static str| -> TemplateResponse<validator::ValidationErrors> {
        let mut error = validator::ValidationErrors::new();
        error.add(e, validator::ValidationError::new(v));
        TemplateResponse {
            template: signup.template(&boosted),
            state: &state,
            data: TemplateContext::builder(&session, error).build()
        }
    };

    let salt = SaltString::generate(&mut OsRng);

    let password_hash = match argon
        .hash_password(signup.password.as_bytes(), &salt)
        .map(|t| t.to_string()) {
        Ok(v) => {v}
        Err(e) => return err("form", "Unexpected Error").into_response()
        };

    let new_user = match state.db
        .account()
        .create(
            signup.username.clone(),
            vec![db::account::password_hash::set(Some(password_hash))],
        )
        .exec()
        .await {
        Ok(v) => { v }
        Err(e) => {
            error!("Error creating user {}", e);
            return err("form", "Unexpected Error").into_response();
        }
    };

    if let Some(email) = signup.email {
        match state.db
            .email()
            .create(
                email,
                db::account::user_id::equals(new_user.user_id),
                vec![],
            )
            .exec()
            .await {
            Ok(_) => {()}
            Err(e) => {
                error!("Could not save email address: {}", e);
            }
        }
    }

    if boosted {
        TemplateResponse {
            template: "components/login_form",
            state: &state,
            data: TemplateContext::builder(&session, ()).build(),
        }
        .into_response()
    } else {
        Redirect::to("/").into_response()
    }
}
