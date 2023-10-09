use axum::extract::rejection::FormRejection;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use thiserror::Error;

// Make our own error that wraps `anyhow::Error`.
#[derive(Debug, Error)]
pub enum ServerError {
    #[error("internal server error")]
    Generic,
    #[error(transparent)]
    ValidationError(#[from] validator::ValidationErrors),

    #[error(transparent)]
    AxumFormRejection(#[from] FormRejection),

    #[error("internal server error")]
    Database
}


impl IntoResponse for ServerError {
    fn into_response(self) -> Response {
        match self {
            ServerError::Generic | ServerError::Database => {(StatusCode::INTERNAL_SERVER_ERROR, self.to_string())}
            ServerError::ValidationError(_) => {
                let message = format!("Input validation error: [{self}]").replace('\n', ", ");
                (StatusCode::BAD_REQUEST, message)
            }
            ServerError::AxumFormRejection(_) => (StatusCode::BAD_REQUEST, self.to_string()),

        }
            .into_response()
    }
}
