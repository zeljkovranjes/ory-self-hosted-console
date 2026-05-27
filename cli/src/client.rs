//! The ONLINE HTTP client (CLI-02 exemplar of "never a second writer").
//!
//! A thin wrapper over a `reqwest::Client` that injects the
//! `Authorization: Api-Key <raw>` header (the [`console_core`] convention) on
//! EVERY request and NEVER sets `X-CSRF-Token` (api-key requests are CSRF-exempt
//! by the Plan-02 `csrf_guard` branch). It requires the api key for online calls
//! and maps a non-2xx status to a friendly, secret-free error.
//!
//! The raw key is NEVER logged. This module imports NO `sqlx` and NO YAML writer
//! (T-19-11) — it is purely an HTTP client.

use console_core::{API_KEY_HEADER, API_KEY_SCHEME};
use reqwest::{Client, Method, Response, StatusCode};
use serde::Serialize;

use crate::CliError;

/// An authenticated client of the backend's protected subtree.
pub struct ApiClient {
    base_url: String,
    /// The composed `Api-Key <raw>` Authorization header value. Built once;
    /// never logged.
    auth_value: String,
    http: Client,
}

impl ApiClient {
    /// Build a client. `api_key` is the RAW key (from `CONSOLE_API_KEY` in normal
    /// use); a missing/empty key is [`CliError::MissingApiKey`] — ONLINE commands
    /// cannot proceed without it.
    pub fn new(base_url: &str, api_key: Option<&str>) -> Result<Self, CliError> {
        let raw = api_key
            .map(str::trim)
            .filter(|k| !k.is_empty())
            .ok_or(CliError::MissingApiKey)?;

        let http = Client::builder()
            .build()
            .map_err(|e| CliError::Http(e.to_string()))?;

        Ok(Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            // `Authorization: Api-Key <raw>` — the SAME scheme the backend hoop
            // strips. Single source of truth via the console-core constant.
            auth_value: format!("{API_KEY_SCHEME} {raw}"),
            http,
        })
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }

    /// Issue a request with the Api-Key header and NO CSRF token, with an optional
    /// JSON body. Returns the response body text on 2xx, else a mapped error.
    async fn send(
        &self,
        method: Method,
        path: &str,
        json: Option<&(impl Serialize + ?Sized)>,
    ) -> Result<String, CliError> {
        let mut req = self
            .http
            .request(method, self.url(path))
            // The api key IS the credential — no X-CSRF-Token is ever attached.
            .header(API_KEY_HEADER, &self.auth_value);
        if let Some(body) = json {
            req = req.json(body);
        }
        let resp = req.send().await.map_err(|e| CliError::Http(e.to_string()))?;
        map_response(resp).await
    }

    /// `GET {path}` with the Api-Key header.
    pub async fn get(&self, path: &str) -> Result<String, CliError> {
        self.send(Method::GET, path, None::<&()>).await
    }

    /// `PUT {path}` with a JSON body and the Api-Key header.
    pub async fn put_json(
        &self,
        path: &str,
        body: &(impl Serialize + ?Sized),
    ) -> Result<String, CliError> {
        self.send(Method::PUT, path, Some(body)).await
    }

    /// `POST {path}` with a JSON body and the Api-Key header.
    pub async fn post_json(
        &self,
        path: &str,
        body: &(impl Serialize + ?Sized),
    ) -> Result<String, CliError> {
        self.send(Method::POST, path, Some(body)).await
    }
}

/// Map a `reqwest::Response` to the body text (2xx) or an operator-safe error.
///
/// 401 → a clear "check CONSOLE_API_KEY"; 404 → "feature off or unknown"; any
/// other non-2xx surfaces the backend's (already secret-free) error body.
async fn map_response(resp: Response) -> Result<String, CliError> {
    let status = resp.status();
    if status.is_success() {
        return resp.text().await.map_err(|e| CliError::Http(e.to_string()));
    }
    let body = resp.text().await.unwrap_or_default();
    let msg = match status {
        StatusCode::UNAUTHORIZED => {
            "auth failed (check CONSOLE_API_KEY: unset, wrong, or revoked)".to_string()
        }
        StatusCode::NOT_FOUND => {
            "not found (feature flag off, unknown key, or route disabled)".to_string()
        }
        _ => {
            let trimmed = body.trim();
            if trimmed.is_empty() {
                format!("backend returned {status}")
            } else {
                format!("backend returned {status}: {trimmed}")
            }
        }
    };
    Err(CliError::Backend(msg))
}
