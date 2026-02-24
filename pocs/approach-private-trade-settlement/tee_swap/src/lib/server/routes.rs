use std::sync::Arc;

use alloy::primitives::B256;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;

use crate::adapters::memory_store::InMemorySwapStore;
use crate::coordinator::{CoordinatorError, SwapCoordinator};
use crate::domain::swap::{PartySubmission, SwapAnnouncement};
use crate::ports::chain::ChainPort;
use crate::ports::tee::AttestationReport;
use crate::ports::TxReceipt;

/// Shared application state for axum route handlers.
pub struct AppState<C: ChainPort> {
    pub coordinator: Arc<SwapCoordinator<C, InMemorySwapStore>>,
    pub attestation: AttestationReport,
}

impl<C: ChainPort> Clone for AppState<C> {
    fn clone(&self) -> Self {
        Self {
            coordinator: self.coordinator.clone(),
            attestation: self.attestation.clone(),
        }
    }
}

// ── Response types ──

/// Response for POST /submit.
#[derive(serde::Serialize)]
#[serde(tag = "status")]
pub enum SubmitResponse {
    #[serde(rename = "pending")]
    Pending,
    #[serde(rename = "verified")]
    Verified {
        announcement: SwapAnnouncement,
        tx_receipt: TxReceipt,
    },
}

/// Response for GET /status/:swap_id (per PLAN.md: { matched, announced }).
#[derive(serde::Serialize, serde::Deserialize)]
pub struct SwapStatus {
    /// Whether a first-party submission has been buffered (waiting for counterparty).
    pub matched: bool,
    /// Whether the swap announcement has been posted on-chain.
    pub announced: bool,
}

// ── Route handlers ──

/// POST /submit — receives a `PartySubmission`, forwards to the coordinator.
pub async fn submit_handler<C: ChainPort>(
    State(state): State<AppState<C>>,
    Json(submission): Json<PartySubmission>,
) -> Result<Json<SubmitResponse>, AppError> {
    let result = state.coordinator.handle_submission(submission).await?;

    match result {
        crate::coordinator::SubmissionResult::Pending => {
            Ok(Json(SubmitResponse::Pending))
        }
        crate::coordinator::SubmissionResult::Verified {
            announcement,
            tx_receipt,
        } => Ok(Json(SubmitResponse::Verified {
            announcement,
            tx_receipt,
        })),
    }
}

/// GET /status/:swap_id — returns whether a pending submission exists and
/// whether an announcement has been posted.
pub async fn status_handler<C: ChainPort>(
    State(state): State<AppState<C>>,
    Path(swap_id_hex): Path<String>,
) -> Result<Json<SwapStatus>, AppError> {
    let swap_id = parse_b256(&swap_id_hex)?;

    let matched = state.coordinator.has_pending(swap_id).await?;
    let announced = state.coordinator.get_announcement(swap_id).await.is_ok();

    Ok(Json(SwapStatus { matched, announced }))
}

/// GET /announcement/:swap_id — returns the `SwapAnnouncement` if it exists.
pub async fn announcement_handler<C: ChainPort>(
    State(state): State<AppState<C>>,
    Path(swap_id_hex): Path<String>,
) -> Result<Json<SwapAnnouncement>, AppError> {
    let swap_id = parse_b256(&swap_id_hex)?;

    let announcement = state.coordinator.get_announcement(swap_id).await.map_err(
        |e| match e {
            CoordinatorError::Chain(crate::ports::chain::ChainError::AnnouncementNotFound(_)) => {
                AppError::NotFound(format!("announcement not found for swap_id {swap_id_hex}"))
            }
            other => AppError::Internal(other.to_string()),
        },
    )?;

    Ok(Json(announcement))
}

/// GET /attestation — returns the RA-TLS attestation report.
pub async fn attestation_handler<C: ChainPort>(
    State(state): State<AppState<C>>,
) -> Json<AttestationReport> {
    Json(state.attestation.clone())
}

// ── Error handling ──

/// Application error type that maps to HTTP status codes.
pub enum AppError {
    BadRequest(String),
    NotFound(String),
    Internal(String),
}

impl From<CoordinatorError> for AppError {
    fn from(e: CoordinatorError) -> Self {
        match &e {
            CoordinatorError::UnknownChain(_) => AppError::BadRequest(e.to_string()),
            _ => AppError::Internal(e.to_string()),
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        let (status, msg) = match self {
            AppError::BadRequest(m) => (StatusCode::BAD_REQUEST, m),
            AppError::NotFound(m) => (StatusCode::NOT_FOUND, m),
            AppError::Internal(m) => (StatusCode::INTERNAL_SERVER_ERROR, m),
        };
        (status, Json(serde_json::json!({ "error": msg }))).into_response()
    }
}

// ── Helpers ──

/// Parse a hex string (with or without "0x" prefix) into a B256.
fn parse_b256(s: &str) -> Result<B256, AppError> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(s)
        .map_err(|e| AppError::BadRequest(format!("invalid hex: {e}")))?;
    if bytes.len() != 32 {
        return Err(AppError::BadRequest(format!(
            "expected 32 bytes, got {}",
            bytes.len()
        )));
    }
    Ok(B256::from_slice(&bytes))
}
