use blueprint_sdk::Error as SdkError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Blueprint SDK error: {0}")]
    SdkError(#[from] SdkError),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Hyper error: {0}")]
    HyperError(#[from] hyper::Error),

    #[error("Hyper Util error: {0}")]
    HyperUtilError(#[from] hyper_util::client::legacy::Error),

    #[error("HTTP error: {0}")]
    HttpError(#[from] hyper::http::Error),

    #[error("Invalid URI: {0}")]
    InvalidUri(#[from] hyper::http::uri::InvalidUri),

    #[error("URL parse error: {0}")]
    UrlParseError(#[from] url::ParseError),

    #[error("JSON serialization/deserialization error: {0}")]
    SerdeJsonError(#[from] serde_json::Error),

    #[error("Reqwest error: {0}")]
    ReqwestError(#[from] reqwest::Error),

    #[error("Axum error: {0}")]
    AxumError(#[from] axum::Error),

    #[error("Invalid IP address or CIDR: {0}")]
    InvalidIpNetwork(#[from] ipnetwork::IpNetworkError),

    #[error("Address parsing error: {0}")]
    AddressParseError(String),

    #[error("Access denied for IP: {0}")]
    AccessDeniedIp(std::net::IpAddr),

    #[error("Access denied for Account: {0}")]
    AccessDeniedAccount(sp_runtime::AccountId32),

    #[error("Webhook sending failed: {0}")]
    WebhookFailed(String),

    #[error("Invalid job input: {0}")]
    InvalidJobInput(String),
}
