use async_trait::async_trait;
use axum::{
    extract::FromRequestParts,
    http::{request::Parts, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use jsonwebtoken::{decode, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::sync::OnceLock;
use uuid::Uuid;

use crate::AppState;

static JWT_SECRET: OnceLock<String> = OnceLock::new();

pub fn init(secret: String) {
    let _ = JWT_SECRET.set(secret);
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: Uuid,
    pub exp: usize,
    pub iat: usize,
}

pub fn verify_token(token: &str) -> Result<Claims, jsonwebtoken::errors::Error> {
    let secret = JWT_SECRET
        .get()
        .ok_or_else(|| jsonwebtoken::errors::Error::from(jsonwebtoken::errors::ErrorKind::InvalidKeyFormat))?;

    let data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &Validation::default(),
    )?;
    Ok(data.claims)
}

/// Extractor: resolves a valid JWT Bearer token or X-API-Key header to a user_id.
#[derive(Debug, Clone)]
pub struct AuthenticatedUser {
    pub user_id: Uuid,
}

pub struct AuthRejection {
    message: String,
    status: StatusCode,
}

impl IntoResponse for AuthRejection {
    fn into_response(self) -> Response {
        let body = Json(json!({ "error": self.message, "status": self.status.as_u16() }));
        (self.status, body).into_response()
    }
}

#[async_trait]
impl FromRequestParts<AppState> for AuthenticatedUser {
    type Rejection = AuthRejection;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        // 1. JWT Bearer token
        if let Some(header) = parts
            .headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
        {
            if let Some(token) = header.strip_prefix("Bearer ") {
                if let Ok(claims) = verify_token(token) {
                    return Ok(AuthenticatedUser { user_id: claims.sub });
                }
            }
        }

        // 2. X-API-Key header — hash it and look up in shared api_keys table
        if let Some(raw_key) = parts
            .headers
            .get("X-API-Key")
            .and_then(|v| v.to_str().ok())
        {
            let mut hasher = Sha256::new();
            hasher.update(raw_key.as_bytes());
            let key_hash = format!("{:x}", hasher.finalize());

            let result = sqlx::query_scalar::<_, Uuid>(
                "SELECT user_id FROM api_keys WHERE key_hash = $1 AND revoked = FALSE",
            )
            .bind(&key_hash)
            .fetch_optional(&state.db)
            .await
            .map_err(|_| AuthRejection {
                message: "Internal error resolving API key".into(),
                status: StatusCode::INTERNAL_SERVER_ERROR,
            })?;

            if let Some(user_id) = result {
                return Ok(AuthenticatedUser { user_id });
            }
        }

        Err(AuthRejection {
            message: "Missing or invalid authentication. Provide Authorization: Bearer <jwt> or X-API-Key header.".into(),
            status: StatusCode::UNAUTHORIZED,
        })
    }
}
