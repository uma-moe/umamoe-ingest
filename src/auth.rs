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
        BROWSER_PROOF_HEADER,
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

    if let Some(api_credential) = auth_common::extract_api_credential(headers) {
        let (header_name, value) = match api_credential {
            Credential::ApiCredential { header_name, value } => (header_name, value.to_owned()),
            Credential::BrowserProof(_) => unreachable!("API extractor cannot return proof"),
        };
        return match backend
            .verify_api_credential(context, header_name, value)
            .await
        {
            Ok(response) if response.valid => AuthDecision::Allow(AuthContext {
                user_id: response.user_id(),
            }),
            Ok(_) => AuthDecision::Reject(AuthRejection::unauthorized("Invalid API credential")),
            Err(err) => {
                tracing::error!("Backend API credential verification failed: {err:?}");
                AuthDecision::Reject(AuthRejection::bad_gateway(
                    "Authentication backend unavailable",
                ))
            }
        };
    }

    if let Some(browser_proof) = auth_common::extract_browser_proof(headers) {
        return match backend.verify_browser_proof(context, browser_proof).await {
            Ok(response)
                if response.valid && response.credential.as_deref() == Some("browser_proof") =>
            {
                AuthDecision::Allow(AuthContext {
                    user_id: response.user_id(),
                })
            }
            Ok(_) => AuthDecision::Reject(AuthRejection::forbidden("Invalid browser proof")),
            Err(err) => {
                tracing::error!("Backend browser proof verification failed: {err:?}");
                AuthDecision::Reject(AuthRejection::bad_gateway(
                    "Authentication backend unavailable",
                ))
            }
        };
    }

    if method == Method::GET || method == Method::HEAD {
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
    if status != reqwest::StatusCode::OK {
        return Ok(VerifyInternalResponse {
            valid: false,
            credential: None,
            user_id: None,
            sub: None,
            api_key: None,
            browser_proof: None,
        });
    }

    Ok(response.json::<VerifyInternalResponse>().await?)
}

fn build_context(method: &Method, uri: &Uri, headers: &HeaderMap) -> RequestContext {
    let path = uri
        .path_and_query()
        .map(|path| path.as_str())
        .unwrap_or_else(|| uri.path());

    auth_common::request_context(headers, method, path)
}

#[cfg(test)]
mod tests {
    use super::build_context;
    use axum::http::{HeaderMap, HeaderValue, Method, Uri};

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
