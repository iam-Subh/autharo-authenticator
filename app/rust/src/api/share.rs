//! Dart-facing temporary encrypted sharing.
//!
//! Rust encrypts and decrypts the account payload. Dart receives the finished
//! URL because the fragment key must be copied or shown as a QR code. The
//! server request never includes that fragment.

use anyhow::{anyhow, Context, Result};
use authcore::secret::SecretString;
use authcore::transport::{HttpClient, HttpRequest, Method};
use serde::{Deserialize, Serialize};

use crate::http::ReqwestClient;

use super::vault::ImportReportView;

#[derive(Serialize)]
struct CreateRequest<'a> {
    payload: &'a str,
    expires_in_seconds: i64,
    one_time: bool,
}

#[derive(Deserialize)]
struct ShareResponse {
    id: String,
    expires_at: String,
    payload: Option<String>,
}

pub struct ShareLinkView {
    pub link: String,
    pub expires_at: String,
}

pub fn create_entry_share(
    id: String,
    expires_in_seconds: i64,
    one_time: bool,
) -> Result<ShareLinkView> {
    if !(300..=86_400).contains(&expires_in_seconds) {
        return Err(anyhow!("Choose an expiry from 5 minutes to 24 hours."));
    }
    let payload = super::vault::with_vault_pub(|vault| Ok(vault.get(&id)?.payload))?;
    let sealed = authcore::share::seal(&[payload]).map_err(|error| anyhow!("{error}"))?;
    let (base, token) = authenticated_connection()?;
    let body = serde_json::to_vec(&CreateRequest {
        payload: &sealed.payload,
        expires_in_seconds,
        one_time,
    })?;
    let response = send_authenticated(
        token,
        HttpRequest {
            method: Method::Post,
            url: format!("{base}/v1/shares"),
            bearer: None,
            json: Some(body.clone()),
        },
    )?;
    let created: ShareResponse = parse_success(response.status, &response.body)?;
    Ok(ShareLinkView {
        link: format!("{base}/v1/shares/{}#{}", created.id, sealed.key.as_str()),
        expires_at: created.expires_at,
    })
}

pub fn import_entry_share(link: String, now_ms: i64) -> Result<ImportReportView> {
    let base = configured_server()?;
    let configured = reqwest::Url::parse(&base).context("The sync server address is not valid.")?;
    let mut share_url =
        reqwest::Url::parse(link.trim()).context("The shared-account link is not a valid URL.")?;
    if configured.scheme() != share_url.scheme()
        || configured.host_str() != share_url.host_str()
        || configured.port_or_known_default() != share_url.port_or_known_default()
    {
        return Err(anyhow!(
            "This link uses a different server. Select that sync server before importing it."
        ));
    }
    if !share_url.username().is_empty()
        || share_url.password().is_some()
        || share_url.query().is_some()
    {
        return Err(anyhow!(
            "The shared-account link contains unsupported URL fields."
        ));
    }
    let key = share_url
        .fragment()
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .ok_or_else(|| anyhow!("The shared-account link has no decryption key."))?;
    let expected_prefix = format!("{}/v1/shares/", configured.path().trim_end_matches('/'));
    let id = share_url
        .path()
        .strip_prefix(&expected_prefix)
        .filter(|value| !value.is_empty() && !value.contains('/'))
        .ok_or_else(|| anyhow!("The shared-account link has an invalid path."))?;
    if id.len() > 64 {
        return Err(anyhow!("The shared-account identifier is too long."));
    }
    share_url.set_fragment(None);

    let response = ReqwestClient::new()
        .send(HttpRequest {
            method: Method::Get,
            url: share_url.to_string(),
            bearer: None,
            json: None,
        })
        .map_err(|error| anyhow!("{error}"))?;
    let downloaded: ShareResponse = parse_success(response.status, &response.body)?;
    let payload = downloaded
        .payload
        .ok_or_else(|| anyhow!("The share server returned no encrypted data."))?;
    let entries = authcore::share::open(&payload, &key).map_err(|error| anyhow!("{error}"))?;
    super::vault::absorb(entries, Vec::new(), now_ms)
}

fn configured_server() -> Result<String> {
    super::vault::with_meta_pub(|meta| {
        super::sync::server_url(meta)?.ok_or_else(|| anyhow!("Choose a sync server first."))
    })
}

fn authenticated_connection() -> Result<(String, SecretString)> {
    super::vault::with_meta_pub(|meta| {
        let base =
            super::sync::server_url(meta)?.ok_or_else(|| anyhow!("Choose a sync server first."))?;
        let token = super::sync::access_token(meta)?
            .ok_or_else(|| anyhow!("Sign in before you create a share."))?;
        Ok((base, token))
    })
}

fn send_authenticated(
    token: SecretString,
    mut request: HttpRequest,
) -> Result<authcore::transport::HttpResponse> {
    request.bearer = Some(token.expose().to_string());
    let client = ReqwestClient::new();
    let first = client
        .send(request.clone())
        .map_err(|error| anyhow!("{error}"))?;
    if first.status != 401 {
        return Ok(first);
    }
    if !super::sync::try_refresh()? {
        return Err(anyhow!("This device has been signed out. Sign in again."));
    }
    let renewed = super::vault::with_meta_pub(super::sync::access_token)?
        .ok_or_else(|| anyhow!("This device has been signed out."))?;
    request.bearer = Some(renewed.expose().to_string());
    client.send(request).map_err(|error| anyhow!("{error}"))
}

fn parse_success<T: for<'de> Deserialize<'de>>(status: u16, body: &[u8]) -> Result<T> {
    if (200..300).contains(&status) {
        return serde_json::from_slice(body).context("The share server sent an unreadable reply.");
    }
    let message = serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|value| value.get("message")?.as_str().map(str::to_string))
        .unwrap_or_else(|| format!("The share server returned HTTP {status}."));
    Err(anyhow!(message))
}
