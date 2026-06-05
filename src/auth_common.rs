// Shared auth edge helpers; each service intentionally uses a subset.
#![allow(dead_code)]

use axum::http::{
    header::{self, SET_COOKIE},
    HeaderMap, HeaderName, HeaderValue, Method,
};
use reqwest::Url;
use serde::Serialize;

pub const BROWSER_PROOF_COOKIE: &str = "uma_browser_proof";
pub const BROWSER_WARMUP_COOKIE: &str = "uma_browser_warmup";
pub const BROWSER_PROOF_HEADER: &str = "X-Browser-Proof";
pub const BROWSER_PROOF_TTL_HEADER: &str = "X-Browser-Proof-TTL";
pub const BROWSER_PROOF_SOURCE_HEADER: &str = "X-Browser-Proof-Source";
pub const API_KEY_HEADER: &str = "X-API-Key";
pub const API_TOKEN_HEADER: &str = "X-API-Token";
pub const AUTHORIZATION_HEADER: &str = "Authorization";

#[derive(Debug, Clone, Serialize)]
pub struct AuthRequestContext {
    pub method: String,
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub origin: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub referer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub warmup_marker: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub record_usage: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct BrowserProofRequest<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub origin: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub referer: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_ip: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub warmup_marker: Option<&'a str>,
}

#[derive(Debug)]
pub enum Credential<'a> {
    ApiCredential {
        header_name: &'static str,
        value: &'a str,
    },
    BrowserProof(&'a str),
}

pub fn request_context(headers: &HeaderMap, method: &Method, path: &str) -> AuthRequestContext {
    AuthRequestContext {
        method: method.as_str().to_string(),
        path: path.to_string(),
        origin: header_str(headers, header::ORIGIN.as_str()).map(ToOwned::to_owned),
        referer: header_str(headers, header::REFERER.as_str()).map(ToOwned::to_owned),
        host: browser_context_host(headers),
        client_ip: client_ip(headers).map(ToOwned::to_owned),
        user_agent: header_str(headers, header::USER_AGENT.as_str()).map(ToOwned::to_owned),
        warmup_marker: cookie_value(headers, BROWSER_WARMUP_COOKIE).map(ToOwned::to_owned),
        record_usage: extract_api_credential(headers).map(|_| true),
    }
}

pub fn extract_api_credential(headers: &HeaderMap) -> Option<Credential<'_>> {
    header_str(headers, API_KEY_HEADER)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| Credential::ApiCredential {
            header_name: API_KEY_HEADER,
            value,
        })
        .or_else(|| {
            header_str(headers, API_TOKEN_HEADER)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(|value| Credential::ApiCredential {
                    header_name: API_TOKEN_HEADER,
                    value,
                })
        })
}

pub fn extract_bearer_token(headers: &HeaderMap) -> Option<&str> {
    let value = header_str(headers, header::AUTHORIZATION.as_str())?.trim();
    let (scheme, token) = value.split_once(' ')?;
    (scheme.eq_ignore_ascii_case("Bearer") && !token.trim().is_empty()).then_some(token.trim())
}

pub fn extract_browser_proof(headers: &HeaderMap) -> Option<&str> {
    header_str(headers, BROWSER_PROOF_HEADER)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .or_else(|| cookie_value(headers, BROWSER_PROOF_COOKIE))
}

pub fn forward_browser_proof_headers(source: &HeaderMap, target: &mut HeaderMap) {
    for value in source.get_all(SET_COOKIE).iter() {
        target.append(SET_COOKIE, value.clone());
    }

    for header_name in [
        BROWSER_PROOF_HEADER,
        BROWSER_PROOF_TTL_HEADER,
        BROWSER_PROOF_SOURCE_HEADER,
    ] {
        for value in source.get_all(header_name).iter() {
            target.append(header_name, value.clone());
        }
    }
}

pub fn collect_browser_proof_headers(
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
    copy_header(
        headers,
        reqwest::header::HeaderName::from_static("x-browser-proof-source"),
        HeaderName::from_static("x-browser-proof-source"),
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

pub fn browser_context_host(headers: &HeaderMap) -> Option<String> {
    header_str(headers, header::ORIGIN.as_str())
        .and_then(url_host)
        .or_else(|| header_str(headers, header::REFERER.as_str()).and_then(url_host))
        .or_else(|| header_str(headers, "X-Original-Host").and_then(public_header_host))
        .or_else(|| header_str(headers, "X-Forwarded-Host").and_then(public_header_host))
        .or_else(|| header_str(headers, header::HOST.as_str()).and_then(public_header_host))
}

fn url_host(value: &str) -> Option<String> {
    let parsed = Url::parse(value).ok()?;
    parsed.host_str().map(ToOwned::to_owned)
}

fn public_header_host(value: &str) -> Option<String> {
    host_header_value(value).filter(|host| !is_internal_service_host(host))
}

fn host_header_value(value: &str) -> Option<String> {
    let host = value.split(',').next()?.trim();
    if host.is_empty() {
        return None;
    }

    url_host(host).or_else(|| url_host(&format!("http://{}", host)))
}

fn is_internal_service_host(host: &str) -> bool {
    let host = host
        .trim()
        .trim_matches(&['[', ']'][..])
        .to_ascii_lowercase();
    if host.is_empty() {
        return true;
    }

    if host == "host.docker.internal"
        || host == "redis"
        || host.starts_with("umamoe-")
        || host.ends_with(".docker.internal")
    {
        return true;
    }

    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return ip.is_loopback()
            || ip.is_unspecified()
            || match ip {
                std::net::IpAddr::V4(ip) => ip.is_private() || ip.is_link_local(),
                std::net::IpAddr::V6(ip) => ip.is_unique_local() || ip.is_unicast_link_local(),
            };
    }

    !host.contains('.') && host != "localhost"
}

pub fn header_str<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|value| value.to_str().ok())
}

fn client_ip(headers: &HeaderMap) -> Option<&str> {
    header_str(headers, "CF-Connecting-IP")
        .or_else(|| {
            header_str(headers, "X-Forwarded-For")
                .and_then(|value| value.split(',').next())
                .map(str::trim)
                .filter(|value| !value.is_empty())
        })
        .or_else(|| header_str(headers, "X-Real-IP"))
        .or_else(|| forwarded_for(headers))
}

fn forwarded_for(headers: &HeaderMap) -> Option<&str> {
    let forwarded = header_str(headers, "Forwarded")?;
    forwarded.split(';').find_map(|part| {
        let (key, value) = part.split_once('=')?;
        key.trim()
            .eq_ignore_ascii_case("for")
            .then_some(value.trim().trim_matches('"'))
            .filter(|value| !value.is_empty())
    })
}

fn cookie_value<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let cookie = header_str(headers, header::COOKIE.as_str())?;
    cookie.split(';').find_map(|part| {
        let (cookie_name, value) = part.trim().split_once('=')?;
        (cookie_name == name && !value.trim().is_empty()).then_some(value)
    })
}

pub fn should_skip_api_protection(method: &Method, path: &str, extra_paths: &[&str]) -> bool {
    *method == Method::OPTIONS
        || matches!(path, "/health" | "/healthz")
        || extra_paths.iter().any(|extra| path == *extra)
}
