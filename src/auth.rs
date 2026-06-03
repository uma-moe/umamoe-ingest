use async_trait::async_trait;
use axum::{
    body::Body,
    extract::{FromRequestParts, State},
    http::{
        header, request::Parts, HeaderMap, HeaderName, HeaderValue, Method, Request, StatusCode,
        Uri,
    },
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::time::Duration;
use uuid::Uuid;

use crate::AppState;

const DEFAULT_BACKEND_INTERNAL_BASE: &str = "http://umamoe-backend:3201";
const X_API_KEY: &str = "X-API-Key";
const X_API_TOKEN: &str = "X-API-Token";
const X_BROWSER_PROOF: &str = "X-Browser-Proof";
const BROWSER_PROOF_COOKIE: &str = "uma_browser_proof";

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

#[derive(Debug, Serialize)]
struct VerifyInternalRequest {
    method: String,
    path: String,
    origin: String,
    referer: String,
    host: String,
    record_usage: bool,
}

#[derive(Debug, Serialize)]
struct BrowserProofRequest {
    origin: String,
    referer: String,
    host: String,
}

#[derive(Debug, Deserialize)]
struct VerifyInternalResponse {
    valid: bool,
    credential: Option<String>,
    user_id: Option<Uuid>,
    sub: Option<Uuid>,
}

#[derive(Debug, Clone)]
struct RequestContext {
    method: String,
    path: String,
    origin: String,
    referer: String,
    host: String,
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
    let api_key = header_string(headers, X_API_KEY);
    let api_token = header_string(headers, X_API_TOKEN);

    if api_key.is_some() || api_token.is_some() {
        return match backend
            .verify_api_credential(context, api_key, api_token)
            .await
        {
            Ok(response) if response.valid => AuthDecision::Allow(AuthContext {
                user_id: response.user_id.or(response.sub),
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

    let browser_proof =
        header_string(headers, X_BROWSER_PROOF).or_else(|| browser_proof_cookie(headers));

    if let Some(browser_proof) = browser_proof {
        return match backend.verify_browser_proof(context, browser_proof).await {
            Ok(response)
                if response.valid && response.credential.as_deref() == Some("browser_proof") =>
            {
                AuthDecision::Allow(AuthContext {
                    user_id: response.user_id.or(response.sub),
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
        api_key: Option<String>,
        api_token: Option<String>,
    ) -> anyhow::Result<VerifyInternalResponse> {
        let mut request = self
            .client
            .post(format!("{}/api/auth/verify/internal", self.base_url))
            .json(&VerifyInternalRequest {
                method: context.method,
                path: context.path,
                origin: context.origin,
                referer: context.referer,
                host: context.host,
                record_usage: true,
            });

        if let Some(api_key) = api_key {
            request = request.header(X_API_KEY, api_key);
        }
        if let Some(api_token) = api_token {
            request = request.header(X_API_TOKEN, api_token);
        }

        verify_response(request.send().await?).await
    }

    async fn verify_browser_proof(
        &self,
        context: RequestContext,
        browser_proof: String,
    ) -> anyhow::Result<VerifyInternalResponse> {
        let request = self
            .client
            .post(format!("{}/api/auth/verify/internal", self.base_url))
            .header(X_BROWSER_PROOF, browser_proof)
            .json(&VerifyInternalRequest {
                method: context.method,
                path: context.path,
                origin: context.origin,
                referer: context.referer,
                host: context.host,
                record_usage: true,
            });

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
                origin: context.origin,
                referer: context.referer,
                host: context.host,
            })
            .send()
            .await?;

        let status = response.status();
        let headers = collect_browser_proof_headers(response.headers());

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
        });
    }

    Ok(response.json::<VerifyInternalResponse>().await?)
}

fn build_context(method: &Method, uri: &Uri, headers: &HeaderMap) -> RequestContext {
    RequestContext {
        method: method.as_str().to_string(),
        path: uri
            .path_and_query()
            .map(|path| path.as_str().to_string())
            .unwrap_or_else(|| uri.path().to_string()),
        origin: header_string(headers, header::ORIGIN.as_str()).unwrap_or_default(),
        referer: header_string(headers, header::REFERER.as_str()).unwrap_or_default(),
        host: header_string(headers, header::HOST.as_str()).unwrap_or_default(),
    }
}

fn collect_browser_proof_headers(
    headers: &reqwest::header::HeaderMap,
) -> Vec<(HeaderName, HeaderValue)> {
    let mut forwarded = Vec::new();

    for value in headers.get_all(reqwest::header::SET_COOKIE).iter() {
        if let Ok(value) = HeaderValue::from_bytes(value.as_bytes()) {
            forwarded.push((header::SET_COOKIE, value));
        }
    }

    copy_header(
        headers,
        reqwest::header::HeaderName::from_static("x-browser-proof"),
        HeaderName::from_static("x-browser-proof"),
        &mut forwarded,
    );
    copy_header(
        headers,
        reqwest::header::HeaderName::from_static("x-browser-proof-ttl"),
        HeaderName::from_static("x-browser-proof-ttl"),
        &mut forwarded,
    );

    forwarded
}

fn copy_header(
    source: &reqwest::header::HeaderMap,
    source_name: reqwest::header::HeaderName,
    target_name: HeaderName,
    target: &mut Vec<(HeaderName, HeaderValue)>,
) {
    for value in source.get_all(source_name).iter() {
        if let Ok(value) = HeaderValue::from_bytes(value.as_bytes()) {
            target.push((target_name.clone(), value));
        }
    }
}

fn header_string(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn browser_proof_cookie(headers: &HeaderMap) -> Option<String> {
    let cookie_header = header_string(headers, header::COOKIE.as_str())?;

    cookie_header.split(';').find_map(|cookie| {
        let (name, value) = cookie.trim().split_once('=')?;
        (name == BROWSER_PROOF_COOKIE && !value.is_empty()).then(|| value.to_string())
    })
}
