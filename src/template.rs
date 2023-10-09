use std::collections::HashMap;
use axum::{async_trait, Form};
use axum::extract::{FromRef, FromRequest};
use axum::extract::rejection::FormRejection;
use axum::http::Request;
use axum::response::{Html, IntoResponse, Response};
use axum_htmx::HxBoosted;
use derive_builder::Builder;
use handlebars::{Context, Handlebars, Helper, Output, RenderContext, RenderError};
use serde::de::DeserializeOwned;
use serde::Serialize;
use tracing::{error, info};
use validator::Validate;
use crate::state::AppState;
use crate::types::*;

pub struct TemplateResponse<'a, T: Serialize + Clone> {
    pub template: &'static str,
    pub state: &'a AppState,
    pub data: TemplateContext<T>,
}

#[derive(Builder, Serialize)]
#[builder(custom_constructor, build_fn(private, name = "fallible_build"))]
#[builder(field(private))]
pub struct TemplateContext<T: Serialize + Clone> {
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

impl<'a, T> IntoResponse for TemplateResponse<'a, T>
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

#[derive(Debug, Clone, Copy, Default)]
pub struct ValidatedForm<T: FormWithTemplate>(pub T);

pub trait FormWithTemplate {

    fn template(&self, partial: &bool) -> &'static str;
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
        use axum::RequestPartsExt;
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
                    template: value.template(&boosted).into(),
                    state: &AppState::from_ref(state),
                    data: TemplateContext::builder(&sess, m).build(),
                }
                    .into_response())
            }
        }
    }
}



pub fn debug_helper(
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
