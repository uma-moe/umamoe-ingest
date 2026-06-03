use async_trait::async_trait;
use axum::{
    body::Body,
    extract::{FromRequestParts, State},
    http::{request::Parts, HeaderMap, HeaderName, HeaderValue, Method, Request, StatusCode, Uri},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use serde::Deserialize;
use serde_json::json;
use std::time::Duration;
use uuid::Uuid;

use crate::{
    auth_common::{
        self, AuthRequestContext as RequestContext, BrowserProofRequest, Credential,
        AUTHORIZATION_HEADER, BROWSER_PROOF_HEADER,
    },
    AppState,
};

const DEFAULT_BACKEND_INTERNAL_BASE: &str = "http://umamoe-backend:3201";

#[derive(Debug, Clone)]
pub struct AuthBackend {
    client: reqwest::Client,
    base_url: String,
}

impl AuthBackend {
    pub fn from_env() -> Self {
        let base_url = std::env::var("AUTH_BACKEND_INTERNAL_BASE")
            .or_else(|_| std::env::var("BACKEND_INTERNAL_BASE"))
            .unwrap_or_else(|_| DEFAULT_BACKEND_INTERNAL_BASE.to_string());

        Self {
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(5))
                .build()
                .expect("failed to build authentication backend HTTP client"),
            base_url: base_url.trim_end_matches('/').to_string(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct AuthContext {
    pub user_id: Option<Uuid>,
}

/// Extractor for handlers that need an authenticated backend user.
#[derive(Debug, Clone)]
pub struct AuthenticatedUser {
    pub user_id: Uuid,
}

#[derive(Debug)]
pub struct AuthRejection {
    message: String,
    status: StatusCode,
}

impl AuthRejection {
    fn unauthorized(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            status: StatusCode::UNAUTHORIZED,
        }
    }

    fn forbidden(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            status: StatusCode::FORBIDDEN,
        }
    }

    fn bad_gateway(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            status: StatusCode::BAD_GATEWAY,
        }
    }
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
        _state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let context = parts
            .extensions
            .get::<AuthContext>()
            .ok_or_else(|| AuthRejection::unauthorized("Missing authentication context"))?;

        let user_id = context.user_id.ok_or_else(|| {
            AuthRejection::forbidden("Authenticated credential did not identify a user")
        })?;

        Ok(Self { user_id })
    }
}

#[derive(Debug, Deserialize)]
struct VerifyInternalResponse {
    valid: bool,
    credential: Option<String>,
    message: Option<String>,
    error: Option<String>,
    user_id: Option<Uuid>,
    sub: Option<Uuid>,
    api_key: Option<ApiKeyVerify>,
    browser_proof: Option<BrowserProofVerify>,
}

#[derive(Debug, Deserialize)]
struct ApiKeyVerify {
    user_id: Uuid,
}

#[derive(Debug, Deserialize)]
struct BrowserProofVerify {
    user_id: Option<Uuid>,
}

impl VerifyInternalResponse {
    fn user_id(&self) -> Option<Uuid> {
        self.api_key
            .as_ref()
            .map(|api_key| api_key.user_id)
            .or_else(|| {
                self.browser_proof
                    .as_ref()
                    .and_then(|browser_proof| browser_proof.user_id)
            })
            .or(self.user_id)
            .or(self.sub)
    }
}

#[derive(Debug)]
enum AuthDecision {
    Allow(AuthContext),
    Bootstrap(Vec<(HeaderName, HeaderValue)>),
    Reject(AuthRejection),
}

pub async fn require_auth(
    State(state): State<AppState>,
    mut request: Request<Body>,
    next: Next,
) -> Response {
    match authorize_request(
        &state.auth_backend,
        request.method(),
        request.uri(),
        request.headers(),
    )
    .await
    {
        AuthDecision::Allow(context) => {
            request.extensions_mut().insert(context);
            next.run(request).await
        }
        AuthDecision::Bootstrap(headers) => {
            let mut response = next.run(request).await;
            for (name, value) in headers {
                response.headers_mut().append(name, value);
            }
            response
        }
        AuthDecision::Reject(rejection) => rejection.into_response(),
    }
}

async fn authorize_request(
    backend: &AuthBackend,
    method: &Method,
    uri: &Uri,
    headers: &HeaderMap,
) -> AuthDecision {
    let context = build_context(method, uri, headers);
    log_auth_request(&context, headers);

    if let Some(bearer_token) = auth_common::extract_bearer_token(headers) {
        tracing::info!(
            method = %context.method,
            path = %context.path,
            host = context.host.as_deref().unwrap_or("<none>"),
            token_len = bearer_token.len(),
            "Verifying ingest request with bearer token"
        );
        return match backend.verify_bearer_token(context, bearer_token).await {
            Ok(response) if response.valid && response.credential.as_deref() == Some("bearer") => {
                let user_id = response.user_id();
                if user_id.is_none() {
                    tracing::warn!(
                        credential = response.credential.as_deref().unwrap_or("<none>"),
                        message = response.message.as_deref().unwrap_or("<none>"),
                        error = response.error.as_deref().unwrap_or("<none>"),
                        "Backend accepted bearer token without user_id"
                    );
                }
                AuthDecision::Allow(AuthContext { user_id })
            }
            Ok(response) => {
                tracing::warn!(
                    valid = response.valid,
                    credential = response.credential.as_deref().unwrap_or("<none>"),
                    message = response.message.as_deref().unwrap_or("<none>"),
                    error = response.error.as_deref().unwrap_or("<none>"),
                    has_user_id = response.user_id().is_some(),
                    "Backend rejected bearer token for ingest request"
                );
                AuthDecision::Reject(AuthRejection::unauthorized("Invalid bearer token"))
            }
            Err(err) => {
                tracing::error!("Backend bearer token verification failed: {err:?}");
                AuthDecision::Reject(AuthRejection::bad_gateway(
                    "Authentication backend unavailable",
                ))
            }
        };
    }

    if let Some(api_credential) = auth_common::extract_api_credential(headers) {
        let (header_name, value) = match api_credential {
            Credential::ApiCredential { header_name, value } => (header_name, value.to_owned()),
            Credential::BrowserProof(_) => unreachable!("API extractor cannot return proof"),
        };
        tracing::info!(
            method = %context.method,
            path = %context.path,
            host = context.host.as_deref().unwrap_or("<none>"),
            header_name,
            token_len = value.len(),
            "Verifying ingest request with API credential"
        );
        return match backend
            .verify_api_credential(context, header_name, value)
            .await
        {
            Ok(response) if response.valid => AuthDecision::Allow(AuthContext {
                user_id: response.user_id(),
            }),
            Ok(response) => {
                tracing::warn!(
                    valid = response.valid,
                    credential = response.credential.as_deref().unwrap_or("<none>"),
                    message = response.message.as_deref().unwrap_or("<none>"),
                    error = response.error.as_deref().unwrap_or("<none>"),
                    has_user_id = response.user_id().is_some(),
                    "Backend rejected API credential for ingest request"
                );
                AuthDecision::Reject(AuthRejection::unauthorized("Invalid API credential"))
            }
            Err(err) => {
                tracing::error!("Backend API credential verification failed: {err:?}");
                AuthDecision::Reject(AuthRejection::bad_gateway(
                    "Authentication backend unavailable",
                ))
            }
        };
    }

    if let Some(browser_proof) = auth_common::extract_browser_proof(headers) {
        tracing::info!(
            method = %context.method,
            path = %context.path,
            host = context.host.as_deref().unwrap_or("<none>"),
            proof_len = browser_proof.len(),
            "Verifying ingest request with browser proof"
        );
        return match backend.verify_browser_proof(context, browser_proof).await {
            Ok(response)
                if response.valid && response.credential.as_deref() == Some("browser_proof") =>
            {
                AuthDecision::Allow(AuthContext {
                    user_id: response.user_id(),
                })
            }
            Ok(response) => {
                tracing::warn!(
                    valid = response.valid,
                    credential = response.credential.as_deref().unwrap_or("<none>"),
                    message = response.message.as_deref().unwrap_or("<none>"),
                    error = response.error.as_deref().unwrap_or("<none>"),
                    has_user_id = response.user_id().is_some(),
                    "Backend rejected browser proof for ingest request"
                );
                AuthDecision::Reject(AuthRejection::forbidden("Invalid browser proof"))
            }
            Err(err) => {
                tracing::error!("Backend browser proof verification failed: {err:?}");
                AuthDecision::Reject(AuthRejection::bad_gateway(
                    "Authentication backend unavailable",
                ))
            }
        };
    }

    if method == Method::GET || method == Method::HEAD {
        tracing::info!(
            method = %context.method,
            path = %context.path,
            host = context.host.as_deref().unwrap_or("<none>"),
            "Requesting browser proof bootstrap for safe ingest request"
        );
        return match backend.request_browser_proof(context).await {
            Ok(headers) => AuthDecision::Bootstrap(headers),
            Err(err) => {
                tracing::error!("Backend browser proof bootstrap failed: {err:?}");
                AuthDecision::Reject(AuthRejection::forbidden("Browser proof required"))
            }
        };
    }

    AuthDecision::Reject(AuthRejection::forbidden(
        "API credential or browser proof required",
    ))
}

impl AuthBackend {
    async fn verify_bearer_token(
        &self,
        context: RequestContext,
        bearer_token: &str,
    ) -> anyhow::Result<VerifyInternalResponse> {
        let request = self
            .client
            .post(format!("{}/api/auth/verify/internal", self.base_url))
            .header(AUTHORIZATION_HEADER, format!("Bearer {bearer_token}"))
            .json(&context);

        verify_response(request.send().await?).await
    }

    async fn verify_api_credential(
        &self,
        context: RequestContext,
        header_name: &'static str,
        value: String,
    ) -> anyhow::Result<VerifyInternalResponse> {
        let request = self
            .client
            .post(format!("{}/api/auth/verify/internal", self.base_url))
            .header(header_name, value)
            .json(&context);

        verify_response(request.send().await?).await
    }

    async fn verify_browser_proof(
        &self,
        context: RequestContext,
        browser_proof: &str,
    ) -> anyhow::Result<VerifyInternalResponse> {
        let request = self
            .client
            .post(format!("{}/api/auth/verify/internal", self.base_url))
            .header(BROWSER_PROOF_HEADER, browser_proof)
            .json(&context);

        verify_response(request.send().await?).await
    }

    async fn request_browser_proof(
        &self,
        context: RequestContext,
    ) -> anyhow::Result<Vec<(HeaderName, HeaderValue)>> {
        let response = self
            .client
            .post(format!("{}/api/auth/browser-proof/internal", self.base_url))
            .json(&BrowserProofRequest {
                origin: context.origin.as_deref(),
                referer: context.referer.as_deref(),
                host: context.host.as_deref(),
            })
            .send()
            .await?;

        let status = response.status();
        let headers = auth_common::collect_browser_proof_headers(response.headers());

        if !status.is_success() {
            anyhow::bail!("browser-proof/internal returned HTTP {status}");
        }

        Ok(headers)
    }
}

async fn verify_response(response: reqwest::Response) -> anyhow::Result<VerifyInternalResponse> {
    let status = response.status();
    let body_text = response.text().await?;

    if status != reqwest::StatusCode::OK {
        let parsed = serde_json::from_str::<VerifyInternalResponse>(&body_text).ok();
        if let Some(response) = parsed {
            tracing::warn!(
                status = status.as_u16(),
                valid = response.valid,
                credential = response.credential.as_deref().unwrap_or("<none>"),
                message = response.message.as_deref().unwrap_or("<none>"),
                error = response.error.as_deref().unwrap_or("<none>"),
                has_user_id = response.user_id().is_some(),
                "Backend auth verification returned non-OK response"
            );
            return Ok(response);
        }

        tracing::warn!(
            status = status.as_u16(),
            body_preview = %body_preview(&body_text),
            "Backend auth verification returned non-OK non-JSON response"
        );
        return Ok(VerifyInternalResponse::invalid());
    }

    let response = serde_json::from_str::<VerifyInternalResponse>(&body_text)?;
    tracing::info!(
        status = status.as_u16(),
        valid = response.valid,
        credential = response.credential.as_deref().unwrap_or("<none>"),
        message = response.message.as_deref().unwrap_or("<none>"),
        error = response.error.as_deref().unwrap_or("<none>"),
        has_user_id = response.user_id().is_some(),
        "Backend auth verification response"
    );
    Ok(response)
}

impl VerifyInternalResponse {
    fn invalid() -> Self {
        Self {
            valid: false,
            credential: None,
            message: None,
            error: None,
            user_id: None,
            sub: None,
            api_key: None,
            browser_proof: None,
        }
    }
}

fn build_context(method: &Method, uri: &Uri, headers: &HeaderMap) -> RequestContext {
    let path = uri
        .path_and_query()
        .map(|path| path.as_str())
        .unwrap_or_else(|| uri.path());

    auth_common::request_context(headers, method, path)
}

fn log_auth_request(context: &RequestContext, headers: &HeaderMap) {
    tracing::info!(
        method = %context.method,
        path = %context.path,
        origin = context.origin.as_deref().unwrap_or("<none>"),
        referer = context.referer.as_deref().unwrap_or("<none>"),
        host = context.host.as_deref().unwrap_or("<none>"),
        has_authorization = headers.contains_key(AUTHORIZATION_HEADER),
        has_bearer = auth_common::extract_bearer_token(headers).is_some(),
        has_api_credential = auth_common::extract_api_credential(headers).is_some(),
        has_browser_proof = auth_common::extract_browser_proof(headers).is_some(),
        "Ingest auth request"
    );
}

fn body_preview(body: &str) -> String {
    const MAX_BODY_PREVIEW_CHARS: usize = 256;
    body.chars().take(MAX_BODY_PREVIEW_CHARS).collect()
}

#[cfg(test)]
mod tests {
    use super::{auth_common, build_context};
    use axum::http::{HeaderMap, HeaderValue, Method, Uri};

    #[test]
    fn extracts_bearer_token() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "Authorization",
            HeaderValue::from_static("Bearer user-session-token"),
        );

        assert_eq!(
            auth_common::extract_bearer_token(&headers),
            Some("user-session-token")
        );
    }

    #[test]
    fn build_context_uses_public_forwarded_host_and_tracks_api_usage() {
        let mut headers = HeaderMap::new();
        headers.insert("X-API-Token", HeaderValue::from_static("uma_t_test"));
        headers.insert("X-Forwarded-Host", HeaderValue::from_static("uma.moe"));
        headers.insert("Host", HeaderValue::from_static("umamoe-ingest"));

        let context = build_context(
            &Method::POST,
            &Uri::from_static("/ingest/veteran?source=frontend"),
            &headers,
        );

        assert_eq!(context.method, "POST");
        assert_eq!(context.path, "/ingest/veteran?source=frontend");
        assert_eq!(context.host.as_deref(), Some("uma.moe"));
        assert_eq!(context.record_usage, Some(true));
    }

    #[test]
    fn build_context_omits_internal_host_without_browser_context() {
        let mut headers = HeaderMap::new();
        headers.insert("Host", HeaderValue::from_static("umamoe-ingest"));

        let context = build_context(
            &Method::POST,
            &Uri::from_static("/ingest/veteran"),
            &headers,
        );

        assert_eq!(context.origin, None);
        assert_eq!(context.referer, None);
        assert_eq!(context.host, None);
        assert_eq!(context.record_usage, None);
    }
}
