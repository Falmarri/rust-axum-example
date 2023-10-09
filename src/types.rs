use std::sync::Arc;
use axum_session::{Session, SessionRedisPool};
use handlebars::Handlebars;
use redis::{Client, Connection};
use redis_pool::RedisPool;
use serde::{Deserialize, Serialize};
use crate::errors::ServerError;
use crate::generated::db::PrismaClient;

pub type Database = Arc<PrismaClient>;
//pub type Redis = Arc<RedisPool<Client, Connection>>;
pub type Templates = Arc<Handlebars<'static>>;
pub type Sess = Session<SessionRedisPool>;

pub type Response = Result<axum::response::Response, ServerError>;

#[derive(Debug, Serialize, Clone)]
pub enum Flash {
    Error(&'static str),
    Info(&'static str)
}


#[derive(Serialize, Deserialize, Clone)]
pub struct UserSession {
    pub user_id: String,
    pub username: String,
}