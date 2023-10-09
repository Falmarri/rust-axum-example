use axum::extract::FromRef;
use crate::types::*;

#[derive(Clone)]
pub struct AppState {
    pub db: Database,
    //pub redis: Redis,
    pub handlebars: Templates,
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

// impl FromRef<AppState> for Redis {
//     fn from_ref(app_state: &AppState) -> Redis {
//         app_state.redis.clone()
//     }
// }
