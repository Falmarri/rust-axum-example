use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use axum::extract::{FromRef, FromRequestParts, State};
use axum::http::request::Parts;
use axum::middleware::Next;
use axum::response::{AppendHeaders, IntoResponse, Redirect, Response};
use axum::routing::get;
use axum::{async_trait, http, Extension, Router};
use axum_htmx::HxBoosted;
use axum_session::{Session, SessionRedisPool};
use http::{Request, StatusCode};
use serde::Deserialize;
use tower_cookies::cookie::SameSite;
use tower_cookies::{Cookie, Cookies};
use tracing::info;
use validator::Validate;

use crate::generated::db;
use crate::{
    AppState, Database, FormWithTemplate, Sess, TemplateContext, TemplateResponse, UserSession,
    ValidatedForm,
};

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
    fn full_template(&self) -> &'static str {
        "pages/login"
    }

    fn partial_template(&self) -> &'static str {
        "components/login_form"
    }
}

async fn do_logout(_: Strict, session: Sess) -> Response {
    session.destroy();
    Redirect::to("/").into_response()
}

async fn get_login(State(state): State<AppState>, session: Sess) -> impl IntoResponse {
    TemplateResponse {
        template: "pages/login".into(),
        state,
        data: TemplateContext::builder(&session, ()).build(),
    }
}

async fn do_login(
    _: Strict,
    HxBoosted(boosted): HxBoosted,
    Extension(argon): Extension<Argon2<'static>>,
    State(db): State<Database>,
    session: Sess,

    ValidatedForm(login): ValidatedForm<Login>,
) -> impl IntoResponse {
    if let Some(user) = db
        .account()
        .find_unique(db::account::username::equals(login.username.to_lowercase()))
        .exec()
        .await
        .unwrap()
    {
        if let Some(user_password) = user.password_hash {
            let parsed_hash = PasswordHash::new(&user_password).unwrap();

            return if argon
                .verify_password(login.password.as_bytes(), &parsed_hash)
                .is_ok()
            {
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
                    Ok(AppendHeaders([("HX-Location", "/")]).into_response())
                } else {
                    Ok(Redirect::to("/").into_response())
                }
            } else {
                info!("Authentication failed for user {}", user.user_id);
                Err("IncorrectPassword")
            };
        }
    } else {
        info!("Unknown user {} attempted login", login.username);
        return Err("Unknown User");
    }

    Err("Unknown error")
}

#[derive(Debug, Deserialize, Validate)]
struct Signup {
    username: String,
    password: String,
    email: Option<String>,
}

impl FormWithTemplate for Signup {
    fn full_template(&self) -> &'static str {
        "pages/signup"
    }

    fn partial_template(&self) -> &'static str {
        "components/signup_form"
    }
}

async fn get_signup(State(state): State<AppState>, session: Sess) -> impl IntoResponse {
    TemplateResponse {
        state,
        template: "pages/signup",
        data: TemplateContext::builder(&session, ()).build(),
    }
}

async fn do_signup(
    _: Strict,
    HxBoosted(boosted): HxBoosted,
    Extension(argon): Extension<Argon2<'static>>,
    State(state): State<AppState>,
    session: Sess,
    ValidatedForm(signup): ValidatedForm<Signup>,
) -> impl IntoResponse {
    let salt = SaltString::generate(&mut OsRng);

    let password_hash = argon
        .hash_password(signup.password.as_bytes(), &salt)
        .map(|t| t.to_string())
        .unwrap();

    let _new_user = state
        .db
        .account()
        .create(
            signup.username,
            vec![db::account::password_hash::set(Some(password_hash))],
        )
        .exec()
        .await
        .unwrap();

    if let Some(email) = signup.email {
        state
            .db
            .email()
            .create(
                email,
                db::account::user_id::equals(_new_user.user_id),
                vec![],
            )
            .exec()
            .await
            .unwrap();
    }

    if boosted {
        TemplateResponse {
            template: "components/login_form",
            state,
            data: TemplateContext::builder(&session, ()).build(),
        }
        .into_response()
    } else {
        Redirect::to("/").into_response()
    }
}
