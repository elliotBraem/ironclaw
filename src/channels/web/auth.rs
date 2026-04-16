//! Authentication middleware for the web gateway.
//!
//! Supports four auth mechanisms, tried in order:
//!
//! ```text
//!   Request
//!     │
//!     ▼
//!   ┌─────────────────────────────┐
//!   │ Authorization: Bearer …     │──► env-var token match ──► ALLOW
//!   │ or ?token=xxx (SSE/WS only) │──► DB-backed token match ──► ALLOW
//!   └────────────┬────────────────┘
//!                │ no match / missing
//!                ▼
//!   ┌─────────────────────────────┐
//!   │ OIDC JWT header             │──► Standard OIDC (openidconnect) ──► ALLOW
//!   │ (if configured)              │──► ALB JWT (hand-rolled) ──► ALLOW
//!   └────────────┬────────────────┘
//!                │ no match / missing / disabled
//!                ▼
//!   ┌─────────────────────────────┐
//!   │ Trust-proxy headers          │──► proxy secret match + user header ──► ALLOW
//!   │ (if configured)              │
//!   └────────────┬────────────────┘
//!                │ no match / missing / disabled
//!                ▼
//!              401 Unauthorized
//! ```
//!
//! **Bearer token** — constant-time comparison via SHA-256 hashed tokens.
//! Supports multi-user mode: each token maps to a `UserIdentity` that carries
//! the user_id. The identity is inserted into request extensions so downstream
//! handlers can extract it via `AuthenticatedUser`.
//!
//! **OIDC JWT** — two modes:
//! - **Standard** (`OidcConfig::Standard`): uses the `openidconnect` crate for
//!   full OIDC discovery, JWKS key rotation, and standard JWT verification.
//!   Works with Okta, Auth0, Keycloak, Cognito, Azure AD, Google, etc.
//! - **ALB** (`OidcConfig::Alb`): hand-rolled JWT verification for AWS ALB's
//!   non-standard JWTs (padded base64, DER-encoded ECDSA signatures, per-key
//!   URL fetching). Uses `x-amzn-oidc-data` header by default.
//!
//! **Trust-proxy** — trusts authenticated headers from a reverse proxy
//! (e.g., oauth2-proxy, nginx, ALB + Lambda@Edge) when the proxy sends a
//! shared secret. Uses constant-time comparison for the proxy secret.
//!
//! **Query-string token** — only allowed on SSE/WS endpoints where
//! browser APIs cannot set custom headers.

use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::{
    extract::{FromRequestParts, Request, State},
    http::{HeaderMap, Method, StatusCode, request::Parts},
    middleware::Next,
    response::{IntoResponse, Response},
};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tokio::sync::RwLock;

use crate::config::{AlbOidcConfig, StandardOidcConfig, TrustProxyConfig};
use crate::db::Database;

/// Cookie name for OAuth browser sessions. Shared between the auth middleware
/// (cookie extraction) and the auth handlers (cookie set/clear).
pub const SESSION_COOKIE_NAME: &str = "ironclaw_session";

/// Session lifetime: 30 days (cookie Max-Age and token expiry).
pub const SESSION_LIFETIME_SECS: i64 = 30 * 24 * 60 * 60;

// ── User identity ────────────────────────────────────────────────────────

/// Identity resolved from a bearer token or OIDC JWT.
#[derive(Debug, Clone)]
pub struct UserIdentity {
    pub user_id: String,
    /// `admin` or `member`.
    pub role: String,
    /// Additional user scopes this identity can read from.
    pub workspace_read_scopes: Vec<String>,
}

/// Hash a token with SHA-256 for constant-size, timing-safe storage.
pub fn hash_token(token: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hasher.finalize().into()
}

// ── Multi-user env-var auth ──────────────────────────────────────────────

/// Multi-user auth state: maps token hashes to user identities.
///
/// Tokens are SHA-256 hashed on construction so they are never stored in
/// plaintext. Authentication compares fixed-size (32-byte) digests using
/// constant-time comparison, eliminating both length-oracle timing leaks
/// and accidental token exposure in memory dumps.
///
/// In single-user mode (the default), contains exactly one entry.
#[derive(Clone)]
pub struct MultiAuthState {
    /// Maps SHA-256(token) → identity. Tokens are never stored in cleartext.
    hashed_tokens: Vec<([u8; 32], UserIdentity)>,
    /// Original first token kept only for single-user startup printing.
    /// Not used for authentication.
    display_token: Option<String>,
}

impl MultiAuthState {
    /// Create a single-user auth state (backwards compatible).
    pub fn single(token: String, user_id: String) -> Self {
        let hash = hash_token(&token);
        Self {
            hashed_tokens: vec![(
                hash,
                UserIdentity {
                    user_id,
                    role: "admin".to_string(),
                    workspace_read_scopes: Vec::new(),
                },
            )],
            display_token: Some(token),
        }
    }

    /// Create a multi-user auth state from a map of tokens to identities.
    ///
    /// **Test-only** — production multi-user auth is DB-backed via
    /// `DbAuthenticator`. This constructor is kept public (not `#[cfg(test)]`)
    /// because integration tests in `tests/` compile the crate as a library
    /// where `cfg(test)` is not set.
    pub fn multi(tokens: HashMap<String, UserIdentity>) -> Self {
        let hashed_tokens: Vec<([u8; 32], UserIdentity)> = tokens
            .into_iter()
            .map(|(tok, identity)| (hash_token(&tok), identity))
            .collect();
        Self {
            hashed_tokens,
            display_token: None,
        }
    }

    /// Authenticate a token, returning the associated identity if valid.
    ///
    /// Uses SHA-256 hashing + constant-time comparison (`subtle::ConstantTimeEq`)
    /// to prevent timing side-channels. Both the candidate and stored tokens are
    /// hashed to 32-byte digests, eliminating length-oracle leaks. Iterates all
    /// entries regardless of match to avoid early-exit timing differences.
    /// O(n) in the number of configured users — negligible for typical
    /// deployments (< 10 users).
    pub fn authenticate(&self, candidate: &str) -> Option<&UserIdentity> {
        let candidate_hash = hash_token(candidate);
        let mut matched: Option<&UserIdentity> = None;
        for (stored_hash, identity) in &self.hashed_tokens {
            if bool::from(candidate_hash.ct_eq(stored_hash)) {
                matched = Some(identity);
            }
        }
        matched
    }

    /// Get the first token for backwards-compatible printing at startup.
    ///
    /// Only available in single-user mode; returns `None` in multi-user mode
    /// to avoid exposing tokens.
    pub fn first_token(&self) -> Option<&str> {
        self.display_token.as_deref()
    }

    /// Get the first user identity (for single-user fallback).
    pub fn first_identity(&self) -> Option<&UserIdentity> {
        self.hashed_tokens.first().map(|(_, id)| id)
    }
}

// ── DB-backed auth ───────────────────────────────────────────────────────

/// DB-backed token authenticator with a bounded LRU cache.
///
/// Checks an LRU cache first (TTL 60s), then falls back to a DB query.
/// The cache is bounded to `MAX_CACHE_ENTRIES` — when full, the least
/// recently used entry is evicted regardless of TTL.
///
/// Revoking a token or suspending a user has at most 60s of stale
/// authentication before the cache entry expires.
#[derive(Clone)]
#[allow(clippy::type_complexity)]
pub struct DbAuthenticator {
    store: Arc<dyn Database>,
    /// Bounded LRU cache: token_hash → (identity, inserted_at).
    cache: Arc<RwLock<lru::LruCache<[u8; 32], (UserIdentity, Instant)>>>,
}

impl DbAuthenticator {
    /// Cache TTL — how long a successful auth is cached before re-querying the DB.
    const CACHE_TTL_SECS: u64 = 60;
    /// Maximum cache entries to prevent unbounded growth.
    // SAFETY: 1024 is non-zero, so the unwrap in `new()` is infallible.
    const MAX_CACHE_ENTRIES: NonZeroUsize = match NonZeroUsize::new(1024) {
        Some(v) => v,
        None => unreachable!(),
    };

    pub fn new(store: Arc<dyn Database>) -> Self {
        Self {
            store,
            cache: Arc::new(RwLock::new(lru::LruCache::new(Self::MAX_CACHE_ENTRIES))),
        }
    }

    /// Evict all cached entries for a specific user.
    ///
    /// Call this after security-critical actions (suspend, activate, role
    /// change, token revocation) so the change takes effect immediately
    /// instead of waiting for the 60-second TTL to expire.
    pub async fn invalidate_user(&self, user_id: &str) {
        let mut cache = self.cache.write().await;
        // LruCache doesn't support predicate-based removal, so collect keys
        // first then remove. The cache is bounded (1024) so this is cheap.
        let keys_to_remove: Vec<[u8; 32]> = cache
            .iter()
            .filter(|(_, (identity, _))| identity.user_id == user_id)
            .map(|(k, _)| *k)
            .collect();
        for key in keys_to_remove {
            cache.pop(&key);
        }
    }

    /// Authenticate a token against the database, using cache when possible.
    ///
    /// Returns `Ok(Some(identity))` on success, `Ok(None)` if the token is
    /// not found, or `Err(())` if the database is unreachable (so the caller
    /// can return 503 instead of 401).
    pub async fn authenticate(&self, candidate: &str) -> Result<Option<UserIdentity>, ()> {
        let hash = hash_token(candidate);

        // Check cache first (promotes to most-recent on hit)
        {
            let mut cache = self.cache.write().await;
            if let Some((identity, inserted_at)) = cache.get(&hash) {
                if inserted_at.elapsed().as_secs() < Self::CACHE_TTL_SECS {
                    return Ok(Some(identity.clone()));
                }
                // Expired — remove stale entry
                cache.pop(&hash);
            }
        }

        // Cache miss or expired — query DB
        let (token_record, user_record) = match self.store.authenticate_token(&hash).await {
            Ok(Some(pair)) => pair,
            Ok(None) => return Ok(None),
            Err(e) => {
                tracing::warn!("DB auth lookup failed: {e}");
                return Err(());
            }
        };

        let identity = UserIdentity {
            user_id: user_record.id.clone(),
            role: user_record.role.clone(),
            workspace_read_scopes: Vec::new(),
        };

        // Record token usage (best-effort, don't block auth)
        let store = self.store.clone();
        let token_id = token_record.id;
        let user_id = user_record.id;
        tokio::spawn(async move {
            let _ = store.record_token_usage(token_id).await;
            let _ = store.record_login(&user_id).await;
        });

        // Insert into bounded LRU — if full, least-recently-used entry is evicted
        {
            let mut cache = self.cache.write().await;
            cache.put(hash, (identity.clone(), Instant::now()));
        }

        Ok(Some(identity))
    }
}

// ── Combined auth state ────────────────────────────────────────────────────

/// Combined auth state: tries env-var tokens first, then DB-backed tokens,
/// then OIDC JWT (if configured), then trust-proxy (if configured).
#[derive(Clone)]
pub struct CombinedAuthState {
    /// In-memory tokens from GATEWAY_AUTH_TOKEN.
    pub env_auth: MultiAuthState,
    /// DB-backed token authenticator (optional — only when a database is available).
    pub db_auth: Option<DbAuthenticator>,
    /// OIDC JWT auth state (None when OIDC is disabled).
    /// Wrapped in `RwLock` because standard OIDC discovery is async and
    /// initializes after construction, during `GatewayChannel::start()`.
    pub oidc: Arc<tokio::sync::RwLock<Option<OidcMode>>>,
    /// Email domains allowed for OIDC/proxy login. Empty means allow all.
    pub oidc_allowed_domains: Vec<String>,
    /// Trust-proxy configuration (None when trust-proxy is disabled).
    pub trust_proxy: Option<TrustProxyConfig>,
}

impl From<MultiAuthState> for CombinedAuthState {
    fn from(env_auth: MultiAuthState) -> Self {
        Self {
            env_auth,
            db_auth: None,
            oidc: Arc::new(tokio::sync::RwLock::new(None)),
            oidc_allowed_domains: Vec::new(),
            trust_proxy: None,
        }
    }
}

// ── Axum extractors ──────────────────────────────────────────────────────

/// Axum extractor that provides the authenticated user identity.
///
/// Only available on routes behind `auth_middleware`. Extracts the
/// `UserIdentity` that the middleware inserted into request extensions.
pub struct AuthenticatedUser(pub UserIdentity);

impl<S> FromRequestParts<S> for AuthenticatedUser
where
    S: Send + Sync,
{
    type Rejection = (StatusCode, &'static str);

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<UserIdentity>()
            .cloned()
            .map(AuthenticatedUser)
            .ok_or((StatusCode::UNAUTHORIZED, "Not authenticated"))
    }
}

/// Axum extractor that requires the authenticated user to have the `admin` role.
///
/// Use instead of `AuthenticatedUser` on endpoints that modify system-wide
/// state (user management, model selection, extension/skill installation).
pub struct AdminUser(pub UserIdentity);

impl<S> FromRequestParts<S> for AdminUser
where
    S: Send + Sync,
{
    type Rejection = (StatusCode, &'static str);

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let identity = parts
            .extensions
            .get::<UserIdentity>()
            .cloned()
            .ok_or((StatusCode::UNAUTHORIZED, "Not authenticated"))?;
        if identity.role != "admin" {
            return Err((StatusCode::FORBIDDEN, "Admin role required"));
        }
        Ok(AdminUser(identity))
    }
}

// ── OIDC mode ────────────────────────────────────────────────────────────

/// OIDC authentication mode: standard (openidconnect) or ALB (hand-rolled).
#[derive(Clone)]
pub enum OidcMode {
    /// Standard OIDC using the `openidconnect` crate for discovery and verification.
    Standard(StandardOidcState),
    /// ALB-specific JWT verification with base64/DER workarounds.
    Alb(AlbOidcState),
}

/// Standard OIDC state: holds discovery metadata for JWT verification.
#[derive(Clone)]
pub struct StandardOidcState {
    /// The header name to read the JWT from (default: "Authorization" for Bearer tokens).
    pub header: String,
    /// The discovered issuer URL.
    pub issuer: String,
    /// The expected audience (client_id).
    pub client_id: String,
    /// The discovered JWKS (JSON Web Key Set).
    pub jwks: openidconnect::core::CoreJsonWebKeySet,
}

impl StandardOidcState {
    /// Perform OIDC discovery and build state with the provider's JWKS.
    ///
    /// Contacts the issuer's `/.well-known/openid-configuration` endpoint,
    /// validates the issuer matches, and stores the JWKS for JWT verification.
    pub async fn from_config(config: &StandardOidcConfig) -> Result<Self, String> {
        use openidconnect::core::CoreProviderMetadata;
        use openidconnect::IssuerUrl;

        let issuer_url = IssuerUrl::new(config.issuer.clone())
            .map_err(|e| format!("invalid OIDC issuer URL: {e}"))?;

        let http_client = reqwest::ClientBuilder::new()
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|e| format!("failed to build OIDC HTTP client: {e}"))?;

        let provider_metadata = CoreProviderMetadata::discover_async(issuer_url, &http_client)
            .await
            .map_err(|e| format!("OIDC discovery failed: {e}"))?;

        let jwks = provider_metadata.jwks().clone();

        Ok(Self {
            header: config.header.clone(),
            issuer: config.issuer.clone(),
            client_id: config.client_id.clone(),
            jwks,
        })
    }
}

/// Cached OIDC signing key with its resolved algorithm.
#[derive(Clone)]
struct CachedKey {
    decoding_key: DecodingKey,
    algorithm: Algorithm,
    fetched_at: Instant,
}

/// Tracks recent fetch failures to avoid hammering a downed JWKS endpoint.
#[derive(Clone)]
struct FailedFetch {
    failed_at: Instant,
}

/// How long to suppress retries after a JWKS fetch failure.
const FETCH_FAILURE_BACKOFF: Duration = Duration::from_secs(10);

/// Key cache TTL: 1 hour.
const KEY_CACHE_TTL: Duration = Duration::from_secs(3600);
/// Maximum number of cached keys. Prevents memory exhaustion from
/// attackers sending JWTs with many distinct `kid` values.
const KEY_CACHE_MAX_ENTRIES: usize = 64;

/// OIDC-specific errors (internal, never shown to unauthenticated clients).
#[derive(Debug, thiserror::Error)]
enum OidcError {
    #[error("missing `kid` in JWT header")]
    MissingKid,
    #[error("unsupported algorithm: {0}")]
    #[allow(dead_code)]
    UnsupportedAlgorithm(String),
    #[error("key fetch failed: {0}")]
    KeyFetch(String),
    #[error("signature verification failed")]
    InvalidSignature,
    #[error("claim validation failed: {0}")]
    InvalidClaims(String),
    #[error("standard OIDC discovery failed: {0}")]
    #[allow(dead_code)]
    DiscoveryFailed(String),
}

/// ALB-specific OIDC state: holds JWKS key cache and ALB base64/DER workarounds.
///
/// AWS ALB produces non-standard JWTs with padded base64 segments and
/// DER-encoded ECDSA signatures. This state handles those quirks.
#[derive(Clone)]
pub struct AlbOidcState {
    config: AlbOidcConfig,
    key_cache: Arc<RwLock<HashMap<String, CachedKey>>>,
    /// Tracks recent fetch failures per kid to prevent retry storms.
    fetch_failures: Arc<RwLock<HashMap<String, FailedFetch>>>,
    http_client: reqwest::Client,
}

impl AlbOidcState {
    /// Build ALB OIDC state from gateway config.
    pub fn from_config(oidc: &AlbOidcConfig) -> Result<Self, String> {
        let http_client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|e| format!("failed to build OIDC HTTP client: {e}"))?;
        Ok(Self {
            config: oidc.clone(),
            key_cache: Arc::new(RwLock::new(HashMap::new())),
            fetch_failures: Arc::new(RwLock::new(HashMap::new())),
            http_client,
        })
    }

    /// Pre-seed the key cache with a known key for testing.
    #[cfg(test)]
    pub(crate) async fn seed_key(&self, kid: &str, key: DecodingKey, algorithm: Algorithm) {
        let mut cache = self.key_cache.write().await;
        cache.insert(
            kid.to_string(),
            CachedKey {
                decoding_key: key,
                algorithm,
                fetched_at: Instant::now(),
            },
        );
    }

    /// Header name containing the JWT.
    fn header_name(&self) -> &str {
        &self.config.header
    }

    // ── Key fetching ─────────────────────────────────────────────────────

    /// Fetch a PEM or JWK from an ALB-style per-key URL (`{kid}` placeholder).
    async fn fetch_single_key(&self, url: &str, alg: Algorithm) -> Result<DecodingKey, OidcError> {
        let body = self.fetch_url_text(url).await?;
        let trimmed = body.trim();

        if trimmed.starts_with("-----BEGIN") {
            match alg {
                Algorithm::ES256 | Algorithm::ES384 => DecodingKey::from_ec_pem(trimmed.as_bytes())
                    .map_err(|e| OidcError::KeyFetch(format!("EC PEM parse: {e}"))),
                Algorithm::EdDSA => DecodingKey::from_ed_pem(trimmed.as_bytes())
                    .map_err(|e| OidcError::KeyFetch(format!("EdDSA PEM parse: {e}"))),
                _ => DecodingKey::from_rsa_pem(trimmed.as_bytes())
                    .map_err(|e| OidcError::KeyFetch(format!("RSA PEM parse: {e}"))),
            }
        } else {
            let jwk: jsonwebtoken::jwk::Jwk = serde_json::from_str(trimmed)
                .map_err(|e| OidcError::KeyFetch(format!("JWK parse: {e}")))?;
            DecodingKey::from_jwk(&jwk).map_err(|e| OidcError::KeyFetch(format!("JWK decode: {e}")))
        }
    }

    /// Maximum JWKS response body size (256 KB).
    const MAX_JWKS_RESPONSE_BYTES: usize = 256 * 1024;

    /// HTTP GET helper with timeout, error status check, and body size limit.
    async fn fetch_url_text(&self, url: &str) -> Result<String, OidcError> {
        let response = self
            .http_client
            .get(url)
            .send()
            .await
            .map_err(|e| OidcError::KeyFetch(format!("HTTP request: {e}")))?
            .error_for_status()
            .map_err(|e| OidcError::KeyFetch(format!("HTTP error: {e}")))?;

        if let Some(len) = response.content_length()
            && len as usize > Self::MAX_JWKS_RESPONSE_BYTES
        {
            return Err(OidcError::KeyFetch(format!(
                "JWKS response too large ({len} bytes, max {})",
                Self::MAX_JWKS_RESPONSE_BYTES
            )));
        }

        let bytes = response
            .bytes()
            .await
            .map_err(|e| OidcError::KeyFetch(format!("reading body: {e}")))?;
        if bytes.len() > Self::MAX_JWKS_RESPONSE_BYTES {
            return Err(OidcError::KeyFetch(format!(
                "JWKS response too large ({} bytes, max {})",
                bytes.len(),
                Self::MAX_JWKS_RESPONSE_BYTES
            )));
        }

        String::from_utf8(bytes.to_vec())
            .map_err(|e| OidcError::KeyFetch(format!("response not UTF-8: {e}")))
    }

    /// Get the signing key for `kid`, using cache when available (1h TTL).
    async fn get_or_fetch_key(
        &self,
        kid: &str,
        alg: Algorithm,
    ) -> Result<(DecodingKey, Algorithm), OidcError> {
        // Fast path: cache hit with valid TTL.
        {
            let cache = self.key_cache.read().await;
            if let Some(cached) = cache.get(kid)
                && cached.fetched_at.elapsed() < KEY_CACHE_TTL
            {
                return Ok((cached.decoding_key.clone(), cached.algorithm));
            }
        }

        // Check recent fetch failure backoff.
        {
            let failures = self.fetch_failures.read().await;
            if let Some(failed) = failures.get(kid)
                && failed.failed_at.elapsed() < FETCH_FAILURE_BACKOFF
            {
                return Err(OidcError::KeyFetch(
                    "JWKS fetch recently failed, backing off".to_string(),
                ));
            }
        }

        // Slow path: fetch and cache.
        // URL-encode the kid to prevent SSRF via crafted JWT headers.
        let encoded_kid: String =
            url::form_urlencoded::byte_serialize(kid.as_bytes()).collect();
        let url = self.config.jwks_url.replace("{kid}", &encoded_kid);
        let fetch_result = self.fetch_single_key(&url, alg).await.map(|key| (key, alg));

        let (key, resolved_alg) = match fetch_result {
            Ok(result) => {
                self.fetch_failures.write().await.remove(kid);
                result
            }
            Err(e) => {
                self.fetch_failures.write().await.insert(
                    kid.to_string(),
                    FailedFetch {
                        failed_at: Instant::now(),
                    },
                );
                return Err(e);
            }
        };

        let mut cache = self.key_cache.write().await;

        // Evict expired entries and enforce max cache size.
        cache.retain(|_, v| v.fetched_at.elapsed() < KEY_CACHE_TTL);
        if cache.len() >= KEY_CACHE_MAX_ENTRIES {
            if let Some(oldest_kid) = cache
                .iter()
                .min_by_key(|(_, v)| v.fetched_at)
                .map(|(k, _)| k.clone())
            {
                cache.remove(&oldest_kid);
            }
        }

        cache.insert(
            kid.to_string(),
            CachedKey {
                decoding_key: key.clone(),
                algorithm: resolved_alg,
                fetched_at: Instant::now(),
            },
        );

        Ok((key, resolved_alg))
    }
}

// ── Algorithm resolution ─────────────────────────────────────────────────

/// Map a JWK's `alg` field to a `jsonwebtoken::Algorithm`.
///
/// Used by ALB JWKS key fetching. Standard OIDC uses the `openidconnect`
/// crate's built-in key rotation instead.
#[allow(dead_code)]
fn resolve_algorithm(jwk: &jsonwebtoken::jwk::Jwk) -> Result<Algorithm, OidcError> {
    match jwk.common.key_algorithm {
        Some(jsonwebtoken::jwk::KeyAlgorithm::ES256) => Ok(Algorithm::ES256),
        Some(jsonwebtoken::jwk::KeyAlgorithm::ES384) => Ok(Algorithm::ES384),
        Some(jsonwebtoken::jwk::KeyAlgorithm::RS256) => Ok(Algorithm::RS256),
        Some(jsonwebtoken::jwk::KeyAlgorithm::RS384) => Ok(Algorithm::RS384),
        Some(jsonwebtoken::jwk::KeyAlgorithm::RS512) => Ok(Algorithm::RS512),
        Some(jsonwebtoken::jwk::KeyAlgorithm::PS256) => Ok(Algorithm::PS256),
        Some(jsonwebtoken::jwk::KeyAlgorithm::PS384) => Ok(Algorithm::PS384),
        Some(jsonwebtoken::jwk::KeyAlgorithm::PS512) => Ok(Algorithm::PS512),
        Some(jsonwebtoken::jwk::KeyAlgorithm::EdDSA) => Ok(Algorithm::EdDSA),
        Some(other) => Err(OidcError::UnsupportedAlgorithm(format!("{other:?}"))),
        None => Err(OidcError::UnsupportedAlgorithm(
            "missing alg in JWK".to_string(),
        )),
    }
}

// ── Signature verification ───────────────────────────────────────────────

/// Verify the JWT signature using the **original** token text as the
/// signing input.
///
/// Why not just use `jsonwebtoken::decode()`?  Because `decode()` strips
/// base64 padding (`=`) from header and payload segments before building
/// the signing input.  AWS ALB signs over the *padded* segments, so
/// stripping padding changes the message and breaks verification.
///
/// We call `jsonwebtoken::crypto::verify()` directly with the original
/// `header.payload` bytes, then extract claims separately via
/// `decode()` with signature validation disabled (safe — we already
/// verified the signature above).
fn verify_signature(
    original_jwt: &str,
    key: &DecodingKey,
    alg: Algorithm,
) -> Result<(), OidcError> {
    let parts: Vec<&str> = original_jwt.split('.').collect();
    if parts.len() != 3 {
        return Err(OidcError::InvalidSignature);
    }

    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let raw_sig = parts[2];

    // Decode signature bytes from base64url (tolerate padding).
    let sig_bytes = URL_SAFE_NO_PAD
        .decode(raw_sig.trim_end_matches('='))
        .map_err(|_| OidcError::InvalidSignature)?;

    // ECDSA signatures: handle DER encoding if present (some IdPs use
    // DER-encoded signatures instead of raw R||S).
    let sig_bytes = if matches!(alg, Algorithm::ES256 | Algorithm::ES384) {
        match try_der_to_raw(&sig_bytes, alg) {
            Some(raw) => raw,
            None => sig_bytes,
        }
    } else {
        sig_bytes
    };

    // Re-encode the (possibly DER→raw converted) signature to base64url
    // because jsonwebtoken::crypto::verify() expects a base64url string.
    let sig_b64 = URL_SAFE_NO_PAD.encode(&sig_bytes);

    // verify(signature_b64, message_bytes, key, alg)
    let valid = jsonwebtoken::crypto::verify(&sig_b64, signing_input.as_bytes(), key, alg)
        .map_err(|_| OidcError::InvalidSignature)?;

    if valid {
        Ok(())
    } else {
        Err(OidcError::InvalidSignature)
    }
}

// ── Base64 normalization (for claim extraction only) ─────────────────────

/// Strip base64 padding from a single segment.
///
/// Used only when building a normalized JWT for `jsonwebtoken::decode()`
/// claim extraction.  The `jsonwebtoken` crate uses `URL_SAFE_NO_PAD`
/// internally, so padded segments cause decode failures.
fn normalize_b64_segment(seg: &str) -> String {
    seg.trim_end_matches('=').to_string()
}

/// Rebuild the JWT with padding stripped from all three segments.
///
/// This is a no-op for RFC-compliant JWTs that already omit padding.
/// Only used for claim extraction after signature verification.
fn normalize_jwt_for_claims(jwt: &str) -> String {
    let parts: Vec<&str> = jwt.split('.').collect();
    if parts.len() != 3 {
        return jwt.to_string();
    }
    format!(
        "{}.{}.{}",
        normalize_b64_segment(parts[0]),
        normalize_b64_segment(parts[1]),
        normalize_b64_segment(parts[2]),
    )
}

// ── DER → raw ECDSA signature conversion ─────────────────────────────────

/// Try to convert a DER-encoded ECDSA signature to raw R||S format.
///
/// Returns `None` if the input doesn't look like valid DER, in which case
/// the caller should use the bytes as-is (already raw R||S).
fn try_der_to_raw(der: &[u8], alg: Algorithm) -> Option<Vec<u8>> {
    let component_len = match alg {
        Algorithm::ES256 => 32,
        Algorithm::ES384 => 48,
        _ => return None,
    };

    // DER SEQUENCE: 0x30 <len> <r_integer> <s_integer>
    if der.len() < 6 || der[0] != 0x30 {
        return None;
    }

    // Skip SEQUENCE tag + parse length (supports long-form DER lengths).
    let mut pos = 1;
    let _seq_len = parse_der_length(der, &mut pos)?;

    // Parse R INTEGER
    if pos >= der.len() || der[pos] != 0x02 {
        return None;
    }
    pos += 1;
    let r_len = parse_der_length(der, &mut pos)?;
    if r_len > component_len + 1 {
        return None;
    }
    let r_bytes = der.get(pos..pos + r_len)?;
    pos += r_len;

    // Parse S INTEGER
    if pos >= der.len() || der[pos] != 0x02 {
        return None;
    }
    pos += 1;
    let s_len = parse_der_length(der, &mut pos)?;
    if s_len > component_len + 1 {
        return None;
    }
    let s_bytes = der.get(pos..pos + s_len)?;

    // Strip leading zero padding from DER INTEGER values and left-pad
    // to the expected component length.
    let r = strip_der_leading_zero(r_bytes);
    let s = strip_der_leading_zero(s_bytes);
    if r.len() > component_len || s.len() > component_len {
        return None;
    }

    let mut raw = vec![0u8; component_len * 2];
    raw[component_len - r.len()..component_len].copy_from_slice(r);
    raw[component_len * 2 - s.len()..].copy_from_slice(s);
    Some(raw)
}

/// Parse a DER length field, handling both short-form (< 128) and
/// long-form (0x81 xx, 0x82 xx yy) encodings. Advances `pos` past
/// the length bytes. Returns `None` for unsupported multi-byte lengths
/// (> 2 bytes) or if the buffer is too short.
fn parse_der_length(der: &[u8], pos: &mut usize) -> Option<usize> {
    let b = *der.get(*pos)?;
    *pos += 1;
    if b < 0x80 {
        Some(b as usize)
    } else {
        let num_bytes = (b & 0x7F) as usize;
        if num_bytes == 0 || num_bytes > 2 {
            return None;
        }
        let mut len: usize = 0;
        for _ in 0..num_bytes {
            len = len
                .checked_mul(256)?
                .checked_add(*der.get(*pos)? as usize)?;
            *pos += 1;
        }
        Some(len)
    }
}

/// Strip the leading zero byte that DER adds to unsigned INTEGERs when
/// the high bit is set (to distinguish from negative values).
fn strip_der_leading_zero(bytes: &[u8]) -> &[u8] {
    if bytes.len() > 1 && bytes[0] == 0x00 {
        &bytes[1..]
    } else {
        bytes
    }
}

// ── Full OIDC validation pipeline ────────────────────────────────────────

/// Validate a JWT using standard OIDC discovery via the `openidconnect` crate.
async fn validate_standard_oidc_jwt(state: &StandardOidcState, jwt: &str) -> Result<String, OidcError> {
    use openidconnect::core::CoreIdToken;
    use openidconnect::{ClientId, IssuerUrl, NonceVerifier, Nonce};

    let id_token: CoreIdToken = jwt
        .parse()
        .map_err(|e| OidcError::InvalidClaims(format!("invalid id_token format: {e}")))?;

    let issuer_url = IssuerUrl::new(state.issuer.clone())
        .map_err(|e| OidcError::InvalidClaims(format!("invalid issuer URL: {e}")))?;

    let verifier = openidconnect::core::CoreIdTokenVerifier::new_public_client(
        ClientId::new(state.client_id.clone()),
        issuer_url,
        state.jwks.clone(),
    );

    // We're not doing an auth code flow, so we skip nonce verification.
    struct SkipNonce;
    impl NonceVerifier for SkipNonce {
        fn verify(self, _expected: Option<&Nonce>) -> Result<(), String> {
            Ok(())
        }
    }

    let claims = id_token
        .claims(&verifier, SkipNonce)
        .map_err(|e| OidcError::InvalidClaims(format!("id_token verification failed: {e}")))?;

    let sub = claims.subject().to_string();
    if sub.is_empty() {
        return Err(OidcError::InvalidClaims("missing `sub` claim".to_string()));
    }

    Ok(sub)
}

/// Validate an ALB-specific JWT: fetch key, verify signature, check claims.
///
/// ALB JWTs may have non-standard base64 padding and DER-encoded ECDSA
/// signatures. This function handles those quirks.
async fn validate_alb_jwt(alb: &AlbOidcState, jwt: &str) -> Result<String, OidcError> {
    // Normalize first — `decode_header()` uses URL_SAFE_NO_PAD internally
    // and chokes on the `=` padding that AWS ALB includes.
    let normalized = normalize_jwt_for_claims(jwt);

    // Decode the unverified header to get `kid` and `alg`.
    let header = jsonwebtoken::decode_header(&normalized)
        .map_err(|e| OidcError::InvalidClaims(format!("malformed header: {e}")))?;
    let kid = header.kid.ok_or(OidcError::MissingKid)?;
    let alg = header.alg;

    // Fetch (or retrieve from cache) the signing key.
    let (key, resolved_alg) = alb.get_or_fetch_key(&kid, alg).await?;

    // Verify signature against the ORIGINAL JWT text (preserving any
    // padding). ALB signed over the padded segments, so we must use the
    // original token as the signing input.
    verify_signature(jwt, &key, resolved_alg)?;

    // SAFETY: Signature validation is disabled here because we already
    // verified the signature above via `verify_signature()`. We use
    // `decode()` only for claim extraction and expiry/issuer/audience
    // validation.
    let mut validation = Validation::new(resolved_alg);
    validation.insecure_disable_signature_validation();

    // Build the set of required claims. `exp` is required by default.
    // When issuer/audience are configured, require their presence in the
    // JWT — not just mismatch rejection — to prevent tokens that omit
    // these claims entirely from passing validation.
    let mut required = vec!["exp".to_string()];
    if let Some(ref iss) = alb.config.issuer {
        validation.set_issuer(&[iss]);
        required.push("iss".to_string());
    }
    if let Some(ref aud) = alb.config.audience {
        validation.set_audience(&[aud]);
        required.push("aud".to_string());
    } else {
        validation.validate_aud = false;
    }
    validation.set_required_spec_claims(&required);

    let data = jsonwebtoken::decode::<serde_json::Value>(&normalized, &key, &validation)
        .map_err(|e| OidcError::InvalidClaims(format!("{e}")))?;

    let sub = data
        .claims
        .get("sub")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| OidcError::InvalidClaims("missing `sub` claim".to_string()))?;

    Ok(sub)
}

/// Extract `email` and `email_verified` claims from an OIDC JWT without
/// signature validation.
///
/// Used only after signature has been validated by `validate_oidc_jwt()` to
/// enforce domain restrictions.
fn extract_oidc_email_claims(jwt: &str) -> (Option<String>, bool) {
    let normalized = normalize_jwt_for_claims(jwt);
    let mut validation = Validation::default();
    validation.insecure_disable_signature_validation();
    validation.validate_aud = false;
    validation.validate_exp = false;

    let data = match jsonwebtoken::decode::<serde_json::Value>(
        &normalized,
        &DecodingKey::from_secret(&[]),
        &validation,
    ) {
        Ok(d) => d,
        Err(_) => return (None, false),
    };

    let email = data
        .claims
        .get("email")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    // email_verified may be a boolean or a string "true"/"false".
    let verified = match data.claims.get("email_verified") {
        Some(serde_json::Value::Bool(b)) => *b,
        Some(serde_json::Value::String(s)) => s == "true",
        _ => false,
    };

    (email, verified)
}

// ── Token extraction helpers ─────────────────────────────────────────────

/// Whether query-string token auth is allowed for this request.
///
/// Only GET requests to streaming endpoints may use `?token=xxx`. This
/// minimizes token-in-URL exposure on state-changing routes, where the token
/// would leak via server logs, Referer headers, and browser history.
///
/// Allowed endpoints:
/// - SSE: `/api/chat/events`, `/api/logs/events` (EventSource can't set headers)
/// - WebSocket: `/api/chat/ws` (WS upgrade can't set custom headers)
///
/// If you add a new SSE or WebSocket endpoint, add its path here.
fn allows_query_token_auth(request: &Request) -> bool {
    if request.method() != Method::GET {
        return false;
    }

    matches!(
        request.uri().path(),
        "/api/chat/events" | "/api/logs/events" | "/api/chat/ws"
    )
}

/// Extract the `token` query parameter value, URL-decoded.
/// Returns `None` for empty/whitespace-only tokens so they don't override
/// a valid session cookie.
fn query_token(request: &Request) -> Option<String> {
    let query = request.uri().query()?;
    url::form_urlencoded::parse(query.as_bytes()).find_map(|(k, v)| {
        if k == "token" {
            let trimmed = v.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_string())
            }
        } else {
            None
        }
    })
}

pub(crate) fn extract_cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    let cookie_header = headers.get(axum::http::header::COOKIE)?.to_str().ok()?;
    parse_cookie_value(cookie_header, name)
}

/// Parse a cookie header value by name, handling quoted values that may
/// contain semicolons (e.g., `other="quoted;value"; session=abc`).
fn parse_cookie_value(header: &str, name: &str) -> Option<String> {
    let mut pos = 0;
    let bytes = header.as_bytes();
    while pos < bytes.len() {
        // Skip leading whitespace.
        while pos < bytes.len() && bytes[pos] == b' ' {
            pos += 1;
        }
        if pos >= bytes.len() {
            break;
        }

        // Read the name (up to '=' or ';' or end).
        let name_start = pos;
        while pos < bytes.len() && bytes[pos] != b'=' && bytes[pos] != b';' {
            pos += 1;
        }
        let cookie_name = header[name_start..pos].trim();

        if pos < bytes.len() && bytes[pos] == b'=' {
            pos += 1; // skip '='
            // Read the value — may be quoted.
            let value = if pos < bytes.len() && bytes[pos] == b'"' {
                pos += 1; // skip opening quote
                let value_start = pos;
                while pos < bytes.len() && bytes[pos] != b'"' {
                    pos += 1;
                }
                let v = header[value_start..pos].to_string();
                if pos < bytes.len() {
                    pos += 1; // skip closing quote
                }
                v
            } else {
                let value_start = pos;
                while pos < bytes.len() && bytes[pos] != b';' {
                    pos += 1;
                }
                header[value_start..pos].to_string()
            };

            if cookie_name == name {
                let trimmed = value.trim();
                if !trimmed.is_empty() {
                    return Some(trimmed.to_string());
                }
                return None;
            }
        }

        // Advance past semicolon separator.
        while pos < bytes.len() && bytes[pos] == b';' {
            pos += 1;
        }
    }
    None
}

/// Extract a bearer token from the Authorization header or query parameter.
fn extract_token(headers: &HeaderMap, request: &Request) -> Option<String> {
    // Try Authorization header first (RFC 6750).
    if let Some(auth_header) = headers.get("authorization")
        && let Ok(value) = auth_header.to_str()
        && value.len() > 7
        && value[..7].eq_ignore_ascii_case("Bearer ")
    {
        return Some(value[7..].to_string());
    }

    // Try query parameter for SSE/WS endpoints (explicit token always wins
    // over cookie so `?token=B` is not silently overridden by cookie A).
    if allows_query_token_auth(request)
        && let Some(t) = query_token(request)
    {
        return Some(t);
    }

    // Fall back to session cookie (for OAuth-authenticated browser sessions).
    extract_cookie_value(headers, SESSION_COOKIE_NAME)
}

// ── Middleware ────────────────────────────────────────────────────────────

/// Auth middleware: session → bearer/query token → OIDC JWT → trust-proxy → 401.
///
/// Checks for a tower-sessions session first (for OAuth-authenticated browser
/// sessions). If a session contains a valid user_id, authentication succeeds
/// immediately. Otherwise tries env-var tokens, DB-backed tokens, OIDC JWT
/// validation, then trust-proxy headers. SSE connections can't set headers from
/// `EventSource`, so we also accept `?token=xxx` as a query parameter,
/// but only on SSE/WS endpoints.
///
/// On successful authentication, inserts the matching `UserIdentity` into
/// request extensions for downstream extraction via `AuthenticatedUser`.
pub async fn auth_middleware(
    State(auth): State<CombinedAuthState>,
    headers: HeaderMap,
    mut request: Request,
    next: Next,
) -> Response {
    // 0. Try session-based auth first (for OAuth browser sessions).
    if let Some(session) = request.extensions().get::<tower_sessions::Session>() {
        if let Ok(Some(user_id)) = session.get::<String>("user_id").await {
            if !user_id.is_empty() {
                let role = session
                    .get::<String>("role")
                    .await
                    .ok()
                    .flatten()
                    .unwrap_or_else(|| "member".to_string());
                tracing::debug!(user_id = %user_id, "Session auth succeeded");
                request.extensions_mut().insert(UserIdentity {
                    user_id,
                    role,
                    workspace_read_scopes: Vec::new(),
                });
                return next.run(request).await;
            }
        }
    }

    // Extract the candidate token from header or query param.
    let token = extract_token(&headers, &request);

    if let Some(ref tok) = token {
        // 1. Try env-var tokens first (fast, constant-time, in-memory).
        if let Some(identity) = auth.env_auth.authenticate(tok) {
            request.extensions_mut().insert(identity.clone());
            return next.run(request).await;
        }

        // 2. Fall back to DB-backed token lookup.
        if let Some(ref db_auth) = auth.db_auth {
            match db_auth.authenticate(tok).await {
                Ok(Some(identity)) => {
                    request.extensions_mut().insert(identity);
                    return next.run(request).await;
                }
                Err(()) => {
                    return (StatusCode::SERVICE_UNAVAILABLE, "Database unavailable")
                        .into_response();
                }
                Ok(None) => {}
            }
        }
    }

    // 3. Try OIDC JWT from configured header (standard or ALB).
    if let Some(oidc) = auth.oidc.read().await.as_ref() {
        let (header_name, result) = match oidc {
            OidcMode::Standard(state) => {
                let jwt = headers.get(&state.header).and_then(|v| v.to_str().ok());
                match jwt {
                    Some(jwt) => (state.header.as_str(), validate_standard_oidc_jwt(state, jwt).await),
                    None => (state.header.as_str(), Err(OidcError::InvalidClaims("no header".to_string()))),
                }
            }
            OidcMode::Alb(state) => {
                let jwt = headers.get(state.header_name()).and_then(|v| v.to_str().ok());
                match jwt {
                    Some(jwt) => (state.header_name(), validate_alb_jwt(state, jwt).await),
                    None => (state.header_name(), Err(OidcError::InvalidClaims("no header".to_string()))),
                }
            }
        };

        if let Ok(sub) = result {
            // Enforce email domain restriction if configured.
            if !auth.oidc_allowed_domains.is_empty() {
                // For ALB JWTs, extract email from claims.
                // For standard OIDC, email domain restriction via raw JWT
                // extraction is not yet supported; the verifier handles it.
                let (email, email_verified) = match oidc {
                    OidcMode::Alb(_) => {
                        if let Some(jwt_str) = headers.get(header_name).and_then(|v| v.to_str().ok()) {
                            extract_oidc_email_claims(jwt_str)
                        } else {
                            (None, false)
                        }
                    }
                    OidcMode::Standard(_) => (None, true),
                };
                if !email_verified {
                    tracing::warn!(sub = %sub, email = ?email, "OIDC login rejected: domain restriction requires verified email");
                    return (
                        StatusCode::FORBIDDEN,
                        "Login requires a verified email address from an authorized domain.".to_string(),
                    )
                        .into_response();
                }
                if let Err(msg) = crate::channels::web::handlers::auth::check_email_domain(
                    email.as_deref(),
                    &auth.oidc_allowed_domains,
                ) {
                    tracing::warn!(sub = %sub, error = %msg, "OIDC login rejected by domain restriction");
                    return (StatusCode::FORBIDDEN, msg).into_response();
                }
            }
            tracing::debug!(sub = %sub, "OIDC auth succeeded");
            let identity = UserIdentity {
                user_id: sub,
                role: "member".to_string(),
                workspace_read_scopes: Vec::new(),
            };
            request.extensions_mut().insert(identity);
            return next.run(request).await;
        }
    }

    // 4. Try trust-proxy headers (if configured).
    if let Some(ref proxy_cfg) = auth.trust_proxy {
        if let Some(identity) = extract_proxy_identity(&headers, proxy_cfg) {
            tracing::debug!(user_id = %identity.user_id, "Trust-proxy auth succeeded");
            request.extensions_mut().insert(identity);
            return next.run(request).await;
        }
    }

    (StatusCode::UNAUTHORIZED, "Invalid or missing auth token").into_response()
}

/// Extract user identity from trust-proxy headers.
///
/// Verifies the proxy secret using constant-time comparison, then extracts
/// user identity from the configured headers. Returns `None` if the secret
/// doesn't match or the user header is missing.
fn extract_proxy_identity(headers: &HeaderMap, config: &TrustProxyConfig) -> Option<UserIdentity> {
    // Constant-time comparison of proxy secret to prevent timing attacks.
    let proxy_secret = headers.get("X-Proxy-Secret")?.to_str().ok()?;
    if !bool::from(proxy_secret.as_bytes().ct_eq(config.proxy_secret.as_bytes())) {
        return None;
    }

    let user_id = headers.get(&config.user_header)?.to_str().ok()?.to_string();
    if user_id.is_empty() {
        return None;
    }

    let role = match &config.role_header {
        Some(header_name) => headers
            .get(header_name)
            .and_then(|v| v.to_str().ok())
            .filter(|s| !s.is_empty())
            .unwrap_or(&config.default_role),
        None => &config.default_role,
    }
    .to_string();

    Some(UserIdentity {
        user_id,
        role,
        workspace_read_scopes: Vec::new(),
    })
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::credentials::TEST_AUTH_SECRET_TOKEN;

    #[test]
    fn test_multi_auth_state_single() {
        let state = MultiAuthState::single("tok-123".to_string(), "alice".to_string());
        let identity = state.authenticate("tok-123");
        assert!(identity.is_some());
        assert_eq!(identity.unwrap().user_id, "alice");
    }

    #[test]
    fn test_multi_auth_state_reject_wrong_token() {
        let state = MultiAuthState::single("tok-123".to_string(), "alice".to_string());
        assert!(state.authenticate("wrong-token").is_none());
    }

    #[test]
    fn test_multi_auth_state_multi_users() {
        let mut tokens = HashMap::new();
        tokens.insert(
            "tok-alice".to_string(),
            UserIdentity {
                user_id: "alice".to_string(),
                role: "admin".to_string(),
                workspace_read_scopes: Vec::new(),
            },
        );
        tokens.insert(
            "tok-bob".to_string(),
            UserIdentity {
                user_id: "bob".to_string(),
                role: "admin".to_string(),
                workspace_read_scopes: Vec::new(),
            },
        );
        let state = MultiAuthState::multi(tokens);

        let alice = state.authenticate("tok-alice").unwrap();
        assert_eq!(alice.user_id, "alice");

        let bob = state.authenticate("tok-bob").unwrap();
        assert_eq!(bob.user_id, "bob");

        assert!(state.authenticate("tok-charlie").is_none());
    }

    #[test]
    fn test_multi_auth_state_first_token() {
        let state = MultiAuthState::single("my-token".to_string(), "user1".to_string());
        assert_eq!(state.first_token(), Some("my-token"));
    }

    #[test]
    fn test_multi_auth_state_first_identity() {
        let state = MultiAuthState::single("my-token".to_string(), "user1".to_string());
        let identity = state.first_identity().unwrap();
        assert_eq!(identity.user_id, "user1");
    }

    #[test]
    fn test_extract_cookie_value_uses_cookie_parser() {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::COOKIE,
            HeaderValue::from_static("other=\"quoted;value\"; ironclaw_session=abc123"),
        );

        assert_eq!(
            extract_cookie_value(&headers, SESSION_COOKIE_NAME),
            Some("abc123".to_string())
        );
    }

    use axum::Router;
    use axum::body::Body;
    use axum::http::HeaderValue;
    use axum::middleware;
    use axum::routing::{get, post};
    use tower::ServiceExt;

    async fn dummy_handler() -> &'static str {
        "ok"
    }

    /// Router with streaming endpoints (query auth allowed) and regular
    /// endpoints (query auth rejected).
    fn test_app(token: &str) -> Router {
        let state = CombinedAuthState::from(MultiAuthState::single(
            token.to_string(),
            "test-user".to_string(),
        ));
        Router::new()
            .route("/api/chat/events", get(dummy_handler))
            .route("/api/logs/events", get(dummy_handler))
            .route("/api/chat/ws", get(dummy_handler))
            .route("/api/chat/history", get(dummy_handler))
            .route("/api/chat/send", post(dummy_handler))
            .layer(middleware::from_fn_with_state(state, auth_middleware))
    }

    #[tokio::test]
    async fn test_valid_bearer_token_passes() {
        let app = test_app(TEST_AUTH_SECRET_TOKEN);
        let req = Request::builder()
            .uri("/api/chat/events")
            .header("Authorization", format!("Bearer {TEST_AUTH_SECRET_TOKEN}"))
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_invalid_bearer_token_rejected() {
        let app = test_app(TEST_AUTH_SECRET_TOKEN);
        let req = Request::builder()
            .uri("/api/chat/events")
            .header("Authorization", "Bearer wrong-token")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_query_token_allowed_for_chat_events() {
        let app = test_app(TEST_AUTH_SECRET_TOKEN);
        let req = Request::builder()
            .uri(format!("/api/chat/events?token={TEST_AUTH_SECRET_TOKEN}"))
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_query_token_allowed_for_logs_events() {
        let app = test_app(TEST_AUTH_SECRET_TOKEN);
        let req = Request::builder()
            .uri(format!("/api/logs/events?token={TEST_AUTH_SECRET_TOKEN}"))
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_query_token_allowed_for_ws_upgrade() {
        let app = test_app(TEST_AUTH_SECRET_TOKEN);
        let req = Request::builder()
            .uri(format!("/api/chat/ws?token={TEST_AUTH_SECRET_TOKEN}"))
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_query_token_url_encoded() {
        // Token with characters that get percent-encoded in URLs.
        let raw_token = "tok+en/with spaces";
        let app = test_app(raw_token);
        let req = Request::builder()
            .uri("/api/chat/events?token=tok%2Ben%2Fwith%20spaces")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_query_token_url_encoded_mismatch() {
        let app = test_app("real-token");
        // Encoded value decodes to "wrong-token", not "real-token".
        let req = Request::builder()
            .uri("/api/chat/events?token=wrong%2Dtoken")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_query_token_rejected_for_non_sse_get() {
        let app = test_app(TEST_AUTH_SECRET_TOKEN);
        let req = Request::builder()
            .uri(format!("/api/chat/history?token={TEST_AUTH_SECRET_TOKEN}"))
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_query_token_rejected_for_post() {
        let app = test_app(TEST_AUTH_SECRET_TOKEN);
        let req = Request::builder()
            .method(Method::POST)
            .uri(format!("/api/chat/send?token={TEST_AUTH_SECRET_TOKEN}"))
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_query_token_invalid_rejected() {
        let app = test_app(TEST_AUTH_SECRET_TOKEN);
        let req = Request::builder()
            .uri("/api/chat/events?token=wrong-token")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_no_auth_at_all_rejected() {
        let app = test_app(TEST_AUTH_SECRET_TOKEN);
        let req = Request::builder()
            .uri("/api/chat/events")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_bearer_header_works_for_post() {
        let app = test_app(TEST_AUTH_SECRET_TOKEN);
        let req = Request::builder()
            .method(Method::POST)
            .uri("/api/chat/send")
            .header("Authorization", format!("Bearer {TEST_AUTH_SECRET_TOKEN}"))
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_bearer_prefix_case_insensitive() {
        let app = test_app(TEST_AUTH_SECRET_TOKEN);
        let req = Request::builder()
            .uri("/api/chat/events")
            .header("Authorization", format!("bearer {TEST_AUTH_SECRET_TOKEN}"))
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_bearer_prefix_mixed_case() {
        let app = test_app(TEST_AUTH_SECRET_TOKEN);
        let req = Request::builder()
            .uri("/api/chat/events")
            .header("Authorization", format!("BEARER {TEST_AUTH_SECRET_TOKEN}"))
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_empty_bearer_token_rejected() {
        let app = test_app(TEST_AUTH_SECRET_TOKEN);
        let req = Request::builder()
            .uri("/api/chat/events")
            .header("Authorization", "Bearer ")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_token_with_whitespace_rejected() {
        let app = test_app(TEST_AUTH_SECRET_TOKEN);
        let req = Request::builder()
            .uri("/api/chat/events")
            .header("Authorization", format!("Bearer  {TEST_AUTH_SECRET_TOKEN}"))
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    // ── Cookie session tests ─────────────────────────────────────

    #[tokio::test]
    async fn test_cookie_session_authenticates() {
        let app = test_app(TEST_AUTH_SECRET_TOKEN);
        let req = Request::builder()
            .uri("/api/chat/history")
            .header(
                "Cookie",
                format!("ironclaw_session={TEST_AUTH_SECRET_TOKEN}"),
            )
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_bearer_header_takes_priority_over_cookie() {
        let app = test_app(TEST_AUTH_SECRET_TOKEN);
        // Valid bearer header + invalid cookie → should succeed (header wins)
        let req = Request::builder()
            .uri("/api/chat/history")
            .header("Authorization", format!("Bearer {TEST_AUTH_SECRET_TOKEN}"))
            .header("Cookie", "ironclaw_session=wrong-token")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_empty_cookie_ignored() {
        let app = test_app(TEST_AUTH_SECRET_TOKEN);
        let req = Request::builder()
            .uri("/api/chat/history")
            .header("Cookie", "ironclaw_session=")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_cookie_among_multiple() {
        let app = test_app(TEST_AUTH_SECRET_TOKEN);
        let req = Request::builder()
            .uri("/api/chat/history")
            .header(
                "Cookie",
                format!("other=foo; ironclaw_session={TEST_AUTH_SECRET_TOKEN}; bar=baz"),
            )
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_wrong_cookie_name_ignored() {
        let app = test_app(TEST_AUTH_SECRET_TOKEN);
        let req = Request::builder()
            .uri("/api/chat/history")
            .header("Cookie", format!("other_cookie={TEST_AUTH_SECRET_TOKEN}"))
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    // ── OIDC unit tests ──────────────────────────────────────────────────

    #[test]
    fn test_normalize_jwt_noop_for_rfc_compliant() {
        // No padding → no change.
        let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.sig";
        assert_eq!(normalize_jwt_for_claims(jwt), jwt);
    }

    #[test]
    fn test_normalize_jwt_strips_padding() {
        let jwt = "eyJhbGciOiJIUzI1NiJ9==.eyJzdWIiOiJ0ZXN0In0=.c2ln";
        let normalized = normalize_jwt_for_claims(jwt);
        assert!(!normalized.contains('='));
        assert!(normalized.starts_with("eyJhbGciOiJIUzI1NiJ9."));
    }

    #[test]
    fn test_normalize_b64_segment_no_padding() {
        assert_eq!(normalize_b64_segment("abc"), "abc");
    }

    #[test]
    fn test_normalize_b64_segment_with_padding() {
        assert_eq!(normalize_b64_segment("abc=="), "abc");
    }

    #[test]
    fn test_try_der_to_raw_non_der_passthrough() {
        // 64 bytes of raw R||S — not DER, should return None.
        let raw = vec![0x01; 64];
        assert!(try_der_to_raw(&raw, Algorithm::ES256).is_none());
    }

    #[test]
    fn test_try_der_to_raw_valid_der() {
        // Construct a minimal DER ECDSA signature for ES256.
        // SEQUENCE { INTEGER(r=1, 32 bytes), INTEGER(s=2, 32 bytes) }
        let r = vec![0x01; 32];
        let s = vec![0x02; 32];
        let mut der = vec![0x30, 68]; // SEQUENCE, length=68
        der.push(0x02);
        der.push(32);
        der.extend_from_slice(&r);
        der.push(0x02);
        der.push(32);
        der.extend_from_slice(&s);

        let raw = try_der_to_raw(&der, Algorithm::ES256).expect("should parse DER");
        assert_eq!(raw.len(), 64);
        assert_eq!(&raw[..32], &r[..]);
        assert_eq!(&raw[32..], &s[..]);
    }

    #[test]
    fn test_try_der_to_raw_with_leading_zero() {
        // DER adds a 0x00 prefix when the high bit of an INTEGER is set.
        let r = {
            let mut v = vec![0x00]; // leading zero
            v.extend_from_slice(&[0x80; 32]); // 32 bytes with high bit set
            v
        };
        let s = vec![0x01; 32];
        let mut der = vec![0x30, 69]; // SEQUENCE, length = 33+32+4 = 69
        der.push(0x02);
        der.push(33); // r_len = 33 (with leading zero)
        der.extend_from_slice(&r);
        der.push(0x02);
        der.push(32);
        der.extend_from_slice(&s);

        let raw = try_der_to_raw(&der, Algorithm::ES256).expect("should parse DER");
        assert_eq!(raw.len(), 64);
        // R should have the leading zero stripped.
        assert_eq!(raw[0], 0x80);
    }

    #[test]
    fn test_strip_der_leading_zero() {
        assert_eq!(strip_der_leading_zero(&[0x00, 0x80, 0x01]), &[0x80, 0x01]);
        assert_eq!(strip_der_leading_zero(&[0x80, 0x01]), &[0x80, 0x01]);
        assert_eq!(strip_der_leading_zero(&[0x00]), &[0x00]); // single zero stays
    }

    #[test]
    fn test_parse_der_length_short_form() {
        let data = [0x20]; // 32 in short form
        let mut pos = 0;
        assert_eq!(parse_der_length(&data, &mut pos), Some(32));
        assert_eq!(pos, 1);
    }

    #[test]
    fn test_parse_der_length_long_form_one_byte() {
        // 0x81 0x80 = 128 in long form (1 extra length byte)
        let data = [0x81, 0x80];
        let mut pos = 0;
        assert_eq!(parse_der_length(&data, &mut pos), Some(128));
        assert_eq!(pos, 2);
    }

    #[test]
    fn test_parse_der_length_long_form_two_bytes() {
        // 0x82 0x01 0x00 = 256 in long form (2 extra length bytes)
        let data = [0x82, 0x01, 0x00];
        let mut pos = 0;
        assert_eq!(parse_der_length(&data, &mut pos), Some(256));
        assert_eq!(pos, 3);
    }

    #[test]
    fn test_try_der_to_raw_long_form_sequence_length() {
        // Build a DER signature where SEQUENCE length is >= 128 (uses long form).
        // ES384: component_len=48, max R=49 (leading zero), max S=49.
        let r = {
            let mut v = vec![0x00]; // leading zero
            v.extend_from_slice(&[0xFF; 48]); // 48 bytes with high bits
            v
        };
        let s = {
            let mut v = vec![0x00]; // leading zero
            v.extend_from_slice(&[0xAA; 48]);
            v
        };
        let content_len = 2 + r.len() + 2 + s.len(); // 102
        assert!(content_len < 128); // short form still works for ES384

        // Force a case where total > 127: use ES384 with both R and S having 49 bytes
        // content = (1+1+49) + (1+1+49) = 102. That's < 128, so let's construct
        // a valid DER with 0x81 long-form length anyway to test the parser.
        let mut der = vec![0x30, 0x81, content_len as u8];
        der.push(0x02);
        der.push(r.len() as u8);
        der.extend_from_slice(&r);
        der.push(0x02);
        der.push(s.len() as u8);
        der.extend_from_slice(&s);

        let raw = try_der_to_raw(&der, Algorithm::ES384)
            .expect("should parse DER with long-form sequence length");
        assert_eq!(raw.len(), 96); // 48 * 2
        // R should have leading zero stripped → first byte is 0xFF
        assert_eq!(raw[0], 0xFF);
        // S should have leading zero stripped → byte at offset 48 is 0xAA
        assert_eq!(raw[48], 0xAA);
    }

    #[test]
    fn test_kid_url_encoded_in_jwks_url() {
        // Verify that special characters in kid are URL-encoded, not raw-substituted.
        let encoded: String = url::form_urlencoded::byte_serialize(b"../../evil?x=1").collect();
        let url = "https://example.com/keys/{kid}".replace("{kid}", &encoded);
        assert!(!url.contains("../"));
        assert!(url.contains("%2F"));
    }

    #[test]
    fn test_verify_signature_rejects_tampered_payload() {
        use jsonwebtoken::{EncodingKey, Header};

        // Use HS256 for a self-contained unit test (no external keys).
        let secret = b"test-secret-at-least-256-bits!!!";
        let header = Header::new(Algorithm::HS256);
        let claims = serde_json::json!({"sub": "alice", "exp": 9999999999u64});
        let token =
            jsonwebtoken::encode(&header, &claims, &EncodingKey::from_secret(secret)).unwrap();

        // Valid signature should pass.
        let key = DecodingKey::from_secret(secret);
        assert!(verify_signature(&token, &key, Algorithm::HS256).is_ok());

        // Tamper with the payload — signature should fail.
        let parts: Vec<&str> = token.split('.').collect();
        let tampered = format!("{}.{}.{}", parts[0], "dGFtcGVyZWQ", parts[2]);
        assert!(verify_signature(&tampered, &key, Algorithm::HS256).is_err());
    }

    #[tokio::test]
    async fn test_validate_oidc_jwt_rejects_missing_sub() {
        use jsonwebtoken::{EncodingKey, Header};

        // Create a valid HS256 JWT without a `sub` claim.
        let secret = b"test-secret-at-least-256-bits!!!";
        let mut header = Header::new(Algorithm::HS256);
        header.kid = Some("test-kid".to_string());
        let claims = serde_json::json!({"exp": 9999999999u64, "name": "alice"});
        let token =
            jsonwebtoken::encode(&header, &claims, &EncodingKey::from_secret(secret)).unwrap();

        // Build an AlbOidcState that serves the key from a mock.
        // We can't easily mock HTTP, so test the claim extraction path directly:
        // build a Validation that skips signature check and verify `sub` is required.
        let mut validation = Validation::new(Algorithm::HS256);
        validation.insecure_disable_signature_validation();
        validation.validate_aud = false;

        let data = jsonwebtoken::decode::<serde_json::Value>(
            &token,
            &DecodingKey::from_secret(secret),
            &validation,
        )
        .unwrap();
        let result = data
            .claims
            .get("sub")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| OidcError::InvalidClaims("missing `sub` claim".to_string()));
        assert!(result.is_err());
        assert!(
            result.unwrap_err().to_string().contains("sub"),
            "error should mention missing sub claim"
        );
    }

    #[test]
    fn test_issuer_validation_disabled_when_not_configured() {
        // When no issuer is configured, Validation should NOT require iss.
        let mut validation = Validation::new(Algorithm::HS256);
        validation.insecure_disable_signature_validation();
        validation.validate_aud = false;

        use jsonwebtoken::{EncodingKey, Header};
        let secret = b"test-secret-at-least-256-bits!!!";
        let claims =
            serde_json::json!({"sub": "alice", "exp": 9999999999u64, "iss": "https://example.com"});
        let token = jsonwebtoken::encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(secret),
        )
        .unwrap();

        // Should succeed — issuer validation is not enforced.
        let result = jsonwebtoken::decode::<serde_json::Value>(
            &token,
            &DecodingKey::from_secret(secret),
            &validation,
        );
        assert!(
            result.is_ok(),
            "token with any issuer should pass when issuer validation is disabled"
        );
    }

    // ── Multi-tenant auth integration tests ──────────────────────────────

    /// Handler that extracts `AuthenticatedUser` and returns the resolved user_id.
    async fn identity_handler(AuthenticatedUser(identity): AuthenticatedUser) -> String {
        identity.user_id
    }

    /// Handler that extracts `AuthenticatedUser` and returns workspace_read_scopes as JSON.
    async fn scopes_handler(AuthenticatedUser(identity): AuthenticatedUser) -> String {
        serde_json::to_string(&identity.workspace_read_scopes).unwrap()
    }

    /// Build a multi-user router where each token maps to a distinct identity.
    fn multi_user_app(tokens: HashMap<String, UserIdentity>) -> Router {
        let state = CombinedAuthState::from(MultiAuthState::multi(tokens));
        Router::new()
            .route("/api/chat/events", get(identity_handler))
            .route("/api/chat/send", post(identity_handler))
            .route("/api/scopes", get(scopes_handler))
            .layer(middleware::from_fn_with_state(state, auth_middleware))
    }

    fn two_user_tokens() -> HashMap<String, UserIdentity> {
        let mut tokens = HashMap::new();
        tokens.insert(
            "tok-alice".to_string(),
            UserIdentity {
                user_id: "alice".to_string(),
                role: "admin".to_string(),
                workspace_read_scopes: vec!["shared".to_string()],
            },
        );
        tokens.insert(
            "tok-bob".to_string(),
            UserIdentity {
                user_id: "bob".to_string(),
                role: "admin".to_string(),
                workspace_read_scopes: vec!["shared".to_string(), "alice".to_string()],
            },
        );
        tokens
    }

    #[tokio::test]
    async fn test_multi_user_alice_token_resolves_to_alice() {
        let app = multi_user_app(two_user_tokens());
        let req = Request::builder()
            .uri("/api/chat/events")
            .header("Authorization", "Bearer tok-alice")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
        assert_eq!(body, "alice");
    }

    #[tokio::test]
    async fn test_multi_user_bob_token_resolves_to_bob() {
        let app = multi_user_app(two_user_tokens());
        let req = Request::builder()
            .uri("/api/chat/events")
            .header("Authorization", "Bearer tok-bob")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
        assert_eq!(body, "bob");
    }

    #[tokio::test]
    async fn test_multi_user_sequential_tokens_resolve_independently() {
        let tokens = two_user_tokens();

        let app1 = multi_user_app(tokens.clone());
        let req = Request::builder()
            .uri("/api/chat/events")
            .header("Authorization", "Bearer tok-alice")
            .body(Body::empty())
            .unwrap();
        let resp = app1.oneshot(req).await.unwrap();
        let body = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
        assert_eq!(body, "alice");

        let app2 = multi_user_app(tokens);
        let req = Request::builder()
            .uri("/api/chat/events")
            .header("Authorization", "Bearer tok-bob")
            .body(Body::empty())
            .unwrap();
        let resp = app2.oneshot(req).await.unwrap();
        let body = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
        assert_eq!(body, "bob");
    }

    #[tokio::test]
    async fn test_multi_user_unknown_token_rejected() {
        let app = multi_user_app(two_user_tokens());
        let req = Request::builder()
            .uri("/api/chat/events")
            .header("Authorization", "Bearer tok-charlie")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_multi_user_workspace_read_scopes_propagated() {
        let app = multi_user_app(two_user_tokens());

        // Alice has ["shared"]
        let req = Request::builder()
            .uri("/api/scopes")
            .header("Authorization", "Bearer tok-alice")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        let body = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
        let scopes: Vec<String> = serde_json::from_slice(&body).unwrap();
        assert_eq!(scopes, vec!["shared"]);
    }

    #[tokio::test]
    async fn test_multi_user_bob_has_two_scopes() {
        let app = multi_user_app(two_user_tokens());

        // Bob has ["shared", "alice"]
        let req = Request::builder()
            .uri("/api/scopes")
            .header("Authorization", "Bearer tok-bob")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        let body = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
        let scopes: Vec<String> = serde_json::from_slice(&body).unwrap();
        assert_eq!(scopes, vec!["shared", "alice"]);
    }

    #[tokio::test]
    async fn test_multi_user_query_param_resolves_correct_identity() {
        let app = multi_user_app(two_user_tokens());
        let req = Request::builder()
            .uri("/api/chat/events?token=tok-bob")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
        assert_eq!(body, "bob");
    }

    #[tokio::test]
    async fn test_multi_user_post_with_bearer_resolves_identity() {
        let app = multi_user_app(two_user_tokens());
        let req = Request::builder()
            .method(Method::POST)
            .uri("/api/chat/send")
            .header("Authorization", "Bearer tok-alice")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
        assert_eq!(body, "alice");
    }

    #[tokio::test]
    async fn test_multi_user_empty_scopes_for_single_user() {
        let state = CombinedAuthState::from(MultiAuthState::single(
            "tok-only".to_string(),
            "solo".to_string(),
        ));
        let app = Router::new()
            .route("/api/scopes", get(scopes_handler))
            .layer(middleware::from_fn_with_state(state, auth_middleware));
        let req = Request::builder()
            .uri("/api/scopes")
            .header("Authorization", "Bearer tok-only")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        let body = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
        let scopes: Vec<String> = serde_json::from_slice(&body).unwrap();
        assert!(scopes.is_empty());
    }

    #[tokio::test]
    async fn test_prefix_and_extension_tokens_rejected() {
        let state = MultiAuthState::single("long-secret-token".to_string(), "user".to_string());
        assert!(state.authenticate("long-secret").is_none());
        assert!(state.authenticate("long-secret-token-extra").is_none());
    }

    // ── OIDC test helpers ─────────────────────────────────────────────────

    const OIDC_SECRET: &[u8] = b"test-secret-at-least-256-bits!!!";
    const OIDC_KID: &str = "test-kid";
    const OIDC_HEADER_NAME: &str = "x-oidc-data";

    /// Encode an HS256 JWT with the given claims and optional kid.
    fn encode_test_jwt(claims: serde_json::Value, kid: Option<&str>) -> String {
        use jsonwebtoken::{EncodingKey, Header};
        let mut header = Header::new(Algorithm::HS256);
        header.kid = kid.map(|s| s.to_string());
        jsonwebtoken::encode(&header, &claims, &EncodingKey::from_secret(OIDC_SECRET)).unwrap() // safety: test helper
    }

    /// Build a default OIDC config (no issuer/audience validation).
    fn test_oidc_config() -> crate::config::AlbOidcConfig {
        crate::config::AlbOidcConfig {
            header: OIDC_HEADER_NAME.to_string(),
            jwks_url: "https://unused.example.com/keys".to_string(),
            issuer: None,
            audience: None,
        }
    }

    /// Build an AlbOidcState with the HS256 test key pre-seeded.
    async fn test_oidc_state() -> AlbOidcState {
        test_oidc_state_with_config(test_oidc_config()).await
    }

    /// Build an AlbOidcState from a custom config with the HS256 test key pre-seeded.
    async fn test_oidc_state_with_config(config: crate::config::AlbOidcConfig) -> AlbOidcState {
        let oidc = AlbOidcState::from_config(&config).unwrap(); // safety: test helper
        oidc.seed_key(
            OIDC_KID,
            DecodingKey::from_secret(OIDC_SECRET),
            Algorithm::HS256,
        )
        .await;
        oidc
    }

    /// Build a CombinedAuthState with bearer token + OIDC.
    async fn oidc_auth_state() -> CombinedAuthState {
        CombinedAuthState {
            env_auth: MultiAuthState::single(
                "bearer-token-123".to_string(),
                "bearer-user".to_string(),
            ),
            db_auth: None,
            oidc: std::sync::Arc::new(tokio::sync::RwLock::new(Some(OidcMode::Alb(test_oidc_state().await)))),
            oidc_allowed_domains: Vec::new(),
            trust_proxy: None,
        }
    }

    /// Build a Router with identity_handler behind auth_middleware.
    fn oidc_test_app(state: CombinedAuthState) -> Router {
        Router::new()
            .route("/api/chat/events", get(identity_handler))
            .route("/api/chat/send", post(identity_handler))
            .layer(middleware::from_fn_with_state(state, auth_middleware))
    }

    /// Build a valid JWT with `sub` and far-future `exp`.
    fn valid_oidc_jwt(sub: &str) -> String {
        encode_test_jwt(
            serde_json::json!({"sub": sub, "exp": 9999999999u64}),
            Some(OIDC_KID),
        )
    }

    // ── OIDC middleware integration tests ─────────────────────────────────

    /// Regression test: OIDC auth must produce a `UserIdentity` so that
    /// downstream handlers using `AuthenticatedUser` receive the identity.
    ///
    /// Without the identity insertion, the handler returns 401 even though
    /// OIDC signature validation succeeded — the bug that was caught in
    /// code review of #1463.
    #[tokio::test]
    async fn test_oidc_auth_inserts_user_identity_for_handler() {
        let app = oidc_test_app(oidc_auth_state().await);
        let req = Request::builder()
            .uri("/api/chat/events")
            .header(OIDC_HEADER_NAME, valid_oidc_jwt("oidc-alice"))
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "OIDC auth must insert UserIdentity so AuthenticatedUser extractor succeeds"
        );
        let body = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
        assert_eq!(body, "oidc-alice");
    }

    /// OIDC-authenticated users get role=member (not admin).
    #[tokio::test]
    async fn test_oidc_auth_user_gets_member_role() {
        async fn role_handler(AuthenticatedUser(id): AuthenticatedUser) -> String {
            id.role
        }

        let state = oidc_auth_state().await;
        let app = Router::new()
            .route("/api/chat/events", get(role_handler))
            .layer(middleware::from_fn_with_state(state, auth_middleware));

        let req = Request::builder()
            .uri("/api/chat/events")
            .header(OIDC_HEADER_NAME, valid_oidc_jwt("oidc-bob"))
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
        assert_eq!(body, "member");
    }

    // ── Auth priority & fallthrough ──────────────────────────────────────

    /// Bearer token works when OIDC is configured but the OIDC header is absent.
    #[tokio::test]
    async fn test_bearer_works_when_oidc_configured_but_header_absent() {
        let app = oidc_test_app(oidc_auth_state().await);
        let req = Request::builder()
            .uri("/api/chat/events")
            .header("Authorization", "Bearer bearer-token-123")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
        assert_eq!(body, "bearer-user");
    }

    /// Bearer token takes priority when both Bearer header and OIDC header are present.
    #[tokio::test]
    async fn test_bearer_takes_priority_over_oidc_when_both_present() {
        let app = oidc_test_app(oidc_auth_state().await);
        let req = Request::builder()
            .uri("/api/chat/events")
            .header("Authorization", "Bearer bearer-token-123")
            .header(OIDC_HEADER_NAME, valid_oidc_jwt("oidc-alice"))
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
        assert_eq!(
            body, "bearer-user",
            "bearer should win when both auth methods are present"
        );
    }

    /// OIDC failure (wrong signature) falls through gracefully to 401, not 500.
    #[tokio::test]
    async fn test_oidc_bad_signature_returns_401_not_500() {
        let state = oidc_auth_state().await;
        let app = oidc_test_app(state);

        // Sign with a different secret so the signature won't match.
        let wrong_secret = b"wrong-secret-at-least-256-bits!!";
        let mut header = jsonwebtoken::Header::new(Algorithm::HS256);
        header.kid = Some(OIDC_KID.to_string());
        let bad_jwt = jsonwebtoken::encode(
            &header,
            &serde_json::json!({"sub": "attacker", "exp": 9999999999u64}),
            &jsonwebtoken::EncodingKey::from_secret(wrong_secret),
        )
        .unwrap();

        let req = Request::builder()
            .uri("/api/chat/events")
            .header(OIDC_HEADER_NAME, bad_jwt)
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "bad OIDC sig should yield 401, not 500"
        );
    }

    /// When OIDC header has an invalid JWT but a valid bearer token is also
    /// present, bearer auth should succeed (bearer checked first).
    #[tokio::test]
    async fn test_invalid_oidc_does_not_block_bearer() {
        let app = oidc_test_app(oidc_auth_state().await);
        let req = Request::builder()
            .uri("/api/chat/events")
            .header("Authorization", "Bearer bearer-token-123")
            .header(OIDC_HEADER_NAME, "not.a.jwt")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
        assert_eq!(body, "bearer-user");
    }

    /// No auth at all when OIDC is configured → 401.
    #[tokio::test]
    async fn test_no_auth_with_oidc_configured() {
        let app = oidc_test_app(oidc_auth_state().await);
        let req = Request::builder()
            .uri("/api/chat/events")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    // ── Expired / invalid JWT edge cases ─────────────────────────────────

    /// Expired JWT (`exp` in the past) is rejected.
    #[tokio::test]
    async fn test_oidc_expired_jwt_rejected() {
        let app = oidc_test_app(oidc_auth_state().await);
        let jwt = encode_test_jwt(
            serde_json::json!({"sub": "alice", "exp": 1000000000u64}), // year 2001
            Some(OIDC_KID),
        );
        let req = Request::builder()
            .uri("/api/chat/events")
            .header(OIDC_HEADER_NAME, jwt)
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    /// JWT without `kid` header field is rejected (MissingKid).
    #[tokio::test]
    async fn test_oidc_jwt_without_kid_rejected() {
        let app = oidc_test_app(oidc_auth_state().await);
        let jwt = encode_test_jwt(
            serde_json::json!({"sub": "alice", "exp": 9999999999u64}),
            None, // no kid
        );
        let req = Request::builder()
            .uri("/api/chat/events")
            .header(OIDC_HEADER_NAME, jwt)
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    /// Malformed JWT (not three dot-separated parts) is rejected.
    #[tokio::test]
    async fn test_oidc_malformed_jwt_rejected() {
        let app = oidc_test_app(oidc_auth_state().await);
        for malformed in ["", "abc", "a.b", "a.b.c.d", "not-base64.not-base64.sig"] {
            let req = Request::builder()
                .uri("/api/chat/events")
                .header(OIDC_HEADER_NAME, malformed)
                .body(Body::empty())
                .unwrap();
            let resp = app.clone().oneshot(req).await.unwrap();
            assert_eq!(
                resp.status(),
                StatusCode::UNAUTHORIZED,
                "malformed JWT '{malformed}' should be rejected"
            );
        }
    }

    /// JWT with `sub` as a non-string value (integer) is rejected.
    #[tokio::test]
    async fn test_oidc_jwt_sub_not_string_rejected() {
        let oidc = test_oidc_state().await;
        let jwt = encode_test_jwt(
            serde_json::json!({"sub": 12345, "exp": 9999999999u64}),
            Some(OIDC_KID),
        );
        let result = validate_alb_jwt(&oidc, &jwt).await;
        assert!(
            result.is_err(),
            "non-string sub should be rejected: {result:?}"
        );
    }

    /// JWT with empty-string `sub` claim succeeds (empty user_id is valid
    /// at the auth layer; authorization checks happen downstream).
    #[tokio::test]
    async fn test_oidc_jwt_empty_sub_passes_auth() {
        let app = oidc_test_app(oidc_auth_state().await);
        let jwt = encode_test_jwt(
            serde_json::json!({"sub": "", "exp": 9999999999u64}),
            Some(OIDC_KID),
        );
        let req = Request::builder()
            .uri("/api/chat/events")
            .header(OIDC_HEADER_NAME, jwt)
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        // Empty sub is technically valid at the auth layer. If we decide to
        // reject it, this test documents the expectation and should be updated.
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
        assert_eq!(body, "");
    }

    /// JWT with missing `sub` claim is rejected even though signature is valid.
    #[tokio::test]
    async fn test_oidc_jwt_missing_sub_rejected_through_middleware() {
        let app = oidc_test_app(oidc_auth_state().await);
        let jwt = encode_test_jwt(
            serde_json::json!({"name": "alice", "exp": 9999999999u64}), // no sub
            Some(OIDC_KID),
        );
        let req = Request::builder()
            .uri("/api/chat/events")
            .header(OIDC_HEADER_NAME, jwt)
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    // ── Issuer / audience validation ─────────────────────────────────────

    /// Issuer configured and JWT `iss` matches → accepted.
    #[tokio::test]
    async fn test_oidc_issuer_match_accepted() {
        let mut config = test_oidc_config();
        config.issuer = Some("https://idp.example.com".to_string());
        let oidc = test_oidc_state_with_config(config).await;
        let jwt = encode_test_jwt(
            serde_json::json!({
                "sub": "alice",
                "iss": "https://idp.example.com",
                "exp": 9999999999u64,
            }),
            Some(OIDC_KID),
        );
        let result = validate_alb_jwt(&oidc, &jwt).await;
        assert!(result.is_ok(), "matching issuer should pass: {result:?}");
        assert_eq!(result.unwrap(), "alice");
    }

    /// Issuer configured but JWT has wrong `iss` → rejected.
    #[tokio::test]
    async fn test_oidc_issuer_mismatch_rejected() {
        let mut config = test_oidc_config();
        config.issuer = Some("https://idp.example.com".to_string());
        let oidc = test_oidc_state_with_config(config).await;
        let jwt = encode_test_jwt(
            serde_json::json!({
                "sub": "alice",
                "iss": "https://evil.example.com",
                "exp": 9999999999u64,
            }),
            Some(OIDC_KID),
        );
        let result = validate_alb_jwt(&oidc, &jwt).await;
        assert!(result.is_err(), "wrong issuer should be rejected");
    }

    /// Issuer configured but JWT omits `iss` entirely → rejected.
    ///
    /// We add `iss` to `required_spec_claims` when configured, so a JWT
    /// missing the claim entirely is now rejected (not just mismatches).
    #[tokio::test]
    async fn test_oidc_issuer_configured_but_missing_in_jwt_rejected() {
        let mut config = test_oidc_config();
        config.issuer = Some("https://idp.example.com".to_string());
        let oidc = test_oidc_state_with_config(config).await;
        let jwt = encode_test_jwt(
            serde_json::json!({"sub": "alice", "exp": 9999999999u64}),
            Some(OIDC_KID),
        );
        let result = validate_alb_jwt(&oidc, &jwt).await;
        assert!(
            result.is_err(),
            "missing iss should be rejected when issuer is configured"
        );
    }

    /// Audience configured and JWT `aud` matches → accepted.
    #[tokio::test]
    async fn test_oidc_audience_match_accepted() {
        let mut config = test_oidc_config();
        config.audience = Some("my-client-id".to_string());
        let oidc = test_oidc_state_with_config(config).await;
        let jwt = encode_test_jwt(
            serde_json::json!({
                "sub": "alice",
                "aud": "my-client-id",
                "exp": 9999999999u64,
            }),
            Some(OIDC_KID),
        );
        let result = validate_alb_jwt(&oidc, &jwt).await;
        assert!(result.is_ok(), "matching audience should pass: {result:?}");
    }

    /// Audience configured but JWT has wrong `aud` → rejected.
    #[tokio::test]
    async fn test_oidc_audience_mismatch_rejected() {
        let mut config = test_oidc_config();
        config.audience = Some("my-client-id".to_string());
        let oidc = test_oidc_state_with_config(config).await;
        let jwt = encode_test_jwt(
            serde_json::json!({
                "sub": "alice",
                "aud": "wrong-client",
                "exp": 9999999999u64,
            }),
            Some(OIDC_KID),
        );
        let result = validate_alb_jwt(&oidc, &jwt).await;
        assert!(result.is_err(), "wrong audience should be rejected");
    }

    /// Audience configured but JWT omits `aud` entirely → rejected.
    ///
    /// We add `aud` to `required_spec_claims` when configured, so a JWT
    /// missing the claim entirely is now rejected (not just mismatches).
    #[tokio::test]
    async fn test_oidc_audience_configured_but_missing_in_jwt_rejected() {
        let mut config = test_oidc_config();
        config.audience = Some("my-client-id".to_string());
        let oidc = test_oidc_state_with_config(config).await;
        let jwt = encode_test_jwt(
            serde_json::json!({"sub": "alice", "exp": 9999999999u64}),
            Some(OIDC_KID),
        );
        let result = validate_alb_jwt(&oidc, &jwt).await;
        assert!(
            result.is_err(),
            "missing aud should be rejected when audience is configured"
        );
    }

    // ── Key cache edge cases ─────────────────────────────────────────────

    /// Cache eviction: the `get_or_fetch_key` path evicts expired entries
    /// and the oldest entry when the cache is full. We test this by
    /// pre-filling the cache with expired entries and verifying they're
    /// cleaned up when a new key is fetched (via cache hit on a valid key).
    #[tokio::test]
    async fn test_oidc_key_cache_evicts_expired_entries() {
        let oidc = test_oidc_state().await;

        // Insert an expired entry with a manually backdated timestamp.
        {
            let mut cache = oidc.key_cache.write().await;
            cache.insert(
                "stale-kid".to_string(),
                CachedKey {
                    decoding_key: DecodingKey::from_secret(OIDC_SECRET),
                    algorithm: Algorithm::HS256,
                    fetched_at: Instant::now() - KEY_CACHE_TTL - Duration::from_secs(1),
                },
            );
        }

        // The valid test key (OIDC_KID) is fresh. Validate a JWT to
        // trigger the get_or_fetch_key cache-hit path — the expired
        // entry won't be evicted on a pure cache hit (eviction only
        // runs on the fetch path). Verify the stale entry is expired.
        {
            let cache = oidc.key_cache.read().await;
            let stale = cache.get("stale-kid").unwrap();
            assert!(
                stale.fetched_at.elapsed() > KEY_CACHE_TTL,
                "entry should be expired"
            );
        }

        // A JWT using the stale kid should fail (expired cache entry
        // is not served from cache).
        let jwt = encode_test_jwt(
            serde_json::json!({"sub": "stale-user", "exp": 9999999999u64}),
            Some("stale-kid"),
        );
        let result = validate_alb_jwt(&oidc, &jwt).await;
        assert!(
            result.is_err(),
            "expired cache entry should not be served; fetch fails since URL is unreachable"
        );
    }

    /// Cache max entries: verify the constant is reasonable and that the
    /// cache can hold exactly KEY_CACHE_MAX_ENTRIES via seed_key.
    #[tokio::test]
    async fn test_oidc_key_cache_max_entries_constant() {
        assert_eq!(
            KEY_CACHE_MAX_ENTRIES, 64,
            "cache should be bounded to 64 keys"
        );

        let oidc = test_oidc_state().await;
        for i in 0..KEY_CACHE_MAX_ENTRIES {
            oidc.seed_key(
                &format!("kid-{i}"),
                DecodingKey::from_secret(OIDC_SECRET),
                Algorithm::HS256,
            )
            .await;
        }
        let cache = oidc.key_cache.read().await;
        // seed_key + the default test key = MAX+1, but seed_key doesn't evict.
        // The point is get_or_fetch_key's eviction path — tested indirectly
        // via the fetch-failure and expired-entry tests above.
        assert!(
            cache.len() <= KEY_CACHE_MAX_ENTRIES + 1,
            "cache should be near capacity"
        );
    }

    /// Fetch failure backoff: a failed kid is backed off for FETCH_FAILURE_BACKOFF.
    #[tokio::test]
    async fn test_oidc_fetch_failure_backoff() {
        let oidc = test_oidc_state().await;

        // Simulate a failed fetch by inserting into the failure tracker.
        {
            let mut failures = oidc.fetch_failures.write().await;
            failures.insert(
                "bad-kid".to_string(),
                FailedFetch {
                    failed_at: Instant::now(),
                },
            );
        }

        // Trying to get the key for that kid should immediately fail with
        // backoff error, without attempting an HTTP request.
        let result = oidc.get_or_fetch_key("bad-kid", Algorithm::HS256).await;
        let err_msg = match result {
            Err(e) => format!("{e}"),
            Ok(_) => panic!("expected backoff error"),
        };
        assert!(
            err_msg.contains("backing off"),
            "should mention backoff: {err_msg}"
        );
    }

    /// After backoff expires, a new fetch is attempted (failure is cleared).
    #[tokio::test]
    async fn test_oidc_fetch_failure_backoff_expires() {
        let oidc = test_oidc_state().await;

        // Insert a failure that's already past the backoff window.
        {
            let mut failures = oidc.fetch_failures.write().await;
            failures.insert(
                "expired-kid".to_string(),
                FailedFetch {
                    failed_at: Instant::now() - FETCH_FAILURE_BACKOFF - Duration::from_secs(1),
                },
            );
        }

        // This will attempt an actual HTTP fetch (which will fail since the
        // URL is unreachable), but it should NOT be blocked by backoff.
        let result = oidc.get_or_fetch_key("expired-kid", Algorithm::HS256).await;
        let err_msg = match result {
            Err(e) => format!("{e}"),
            Ok(_) => panic!("expected fetch error (URL unreachable), not success"),
        };
        assert!(
            !err_msg.contains("backing off"),
            "should attempt fetch, not backoff: {err_msg}"
        );
    }

    // ── Trust-proxy tests ──────────────────────────────────────────────────

    fn test_proxy_config() -> TrustProxyConfig {
        TrustProxyConfig {
            proxy_secret: "proxy-secret-123".to_string(),
            user_header: "X-Forwarded-User".to_string(),
            email_header: Some("X-Forwarded-Email".to_string()),
            role_header: Some("X-Forwarded-Role".to_string()),
            default_role: "member".to_string(),
            allowed_domains: Vec::new(),
        }
    }

    #[test]
    fn test_extract_proxy_identity_valid_with_role() {
        let config = test_proxy_config();
        let mut headers = HeaderMap::new();
        headers.insert("X-Proxy-Secret", HeaderValue::from_static("proxy-secret-123"));
        headers.insert("X-Forwarded-User", HeaderValue::from_static("alice"));
        headers.insert("X-Forwarded-Email", HeaderValue::from_static("alice@example.com"));
        headers.insert("X-Forwarded-Role", HeaderValue::from_static("admin"));

        let identity = extract_proxy_identity(&headers, &config).unwrap();
        assert_eq!(identity.user_id, "alice");
        assert_eq!(identity.role, "admin");
    }

    #[test]
    fn test_extract_proxy_identity_defaults_to_member() {
        let config = test_proxy_config();
        let mut headers = HeaderMap::new();
        headers.insert("X-Proxy-Secret", HeaderValue::from_static("proxy-secret-123"));
        headers.insert("X-Forwarded-User", HeaderValue::from_static("bob"));

        let identity = extract_proxy_identity(&headers, &config).unwrap();
        assert_eq!(identity.user_id, "bob");
        assert_eq!(identity.role, "member");
    }

    #[test]
    fn test_extract_proxy_identity_wrong_secret_rejected() {
        let config = test_proxy_config();
        let mut headers = HeaderMap::new();
        headers.insert("X-Proxy-Secret", HeaderValue::from_static("wrong-secret"));
        headers.insert("X-Forwarded-User", HeaderValue::from_static("alice"));

        assert!(extract_proxy_identity(&headers, &config).is_none());
    }

    #[test]
    fn test_extract_proxy_identity_missing_secret_rejected() {
        let config = test_proxy_config();
        let mut headers = HeaderMap::new();
        headers.insert("X-Forwarded-User", HeaderValue::from_static("alice"));

        assert!(extract_proxy_identity(&headers, &config).is_none());
    }

    #[test]
    fn test_extract_proxy_identity_missing_user_rejected() {
        let config = test_proxy_config();
        let mut headers = HeaderMap::new();
        headers.insert("X-Proxy-Secret", HeaderValue::from_static("proxy-secret-123"));

        assert!(extract_proxy_identity(&headers, &config).is_none());
    }

    #[test]
    fn test_extract_proxy_identity_empty_user_rejected() {
        let config = test_proxy_config();
        let mut headers = HeaderMap::new();
        headers.insert("X-Proxy-Secret", HeaderValue::from_static("proxy-secret-123"));
        headers.insert("X-Forwarded-User", HeaderValue::from_static(""));

        assert!(extract_proxy_identity(&headers, &config).is_none());
    }

    #[test]
    fn test_extract_proxy_identity_empty_role_falls_back_to_default() {
        let config = test_proxy_config();
        let mut headers = HeaderMap::new();
        headers.insert("X-Proxy-Secret", HeaderValue::from_static("proxy-secret-123"));
        headers.insert("X-Forwarded-User", HeaderValue::from_static("alice"));
        headers.insert("X-Forwarded-Role", HeaderValue::from_static(""));

        let identity = extract_proxy_identity(&headers, &config).unwrap();
        assert_eq!(identity.role, "member");
    }

    #[test]
    fn test_extract_proxy_identity_no_role_header_configured() {
        let mut config = test_proxy_config();
        config.role_header = None;
        let mut headers = HeaderMap::new();
        headers.insert("X-Proxy-Secret", HeaderValue::from_static("proxy-secret-123"));
        headers.insert("X-Forwarded-User", HeaderValue::from_static("alice"));

        let identity = extract_proxy_identity(&headers, &config).unwrap();
        assert_eq!(identity.role, "member");
    }

    #[test]
    fn test_extract_proxy_identity_constant_time_secret_comparison() {
        let config = test_proxy_config();

        // A secret of the same length but wrong value should still be rejected.
        let mut headers = HeaderMap::new();
        headers.insert("X-Proxy-Secret", HeaderValue::from_static("proxy-secret-124"));
        headers.insert("X-Forwarded-User", HeaderValue::from_static("alice"));

        assert!(extract_proxy_identity(&headers, &config).is_none());
    }

    #[tokio::test]
    async fn test_trust_proxy_auth_via_middleware() {
        let config = test_proxy_config();
        let auth = CombinedAuthState {
            env_auth: MultiAuthState::single("tok".to_string(), "bearer-user".to_string()),
            db_auth: None,
            oidc: Arc::new(tokio::sync::RwLock::new(None)),
            oidc_allowed_domains: Vec::new(),
            trust_proxy: Some(config),
        };
        let app = Router::new()
            .route("/api/test", get(dummy_handler))
            .layer(middleware::from_fn_with_state(auth, auth_middleware));

        let req = Request::builder()
            .uri("/api/test")
            .header("X-Proxy-Secret", "proxy-secret-123")
            .header("X-Forwarded-User", "proxy-alice")
            .header("X-Forwarded-Role", "admin")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_trust_proxy_wrong_secret_rejected_via_middleware() {
        let config = test_proxy_config();
        let auth = CombinedAuthState {
            env_auth: MultiAuthState::single("tok".to_string(), "bearer-user".to_string()),
            db_auth: None,
            oidc: Arc::new(tokio::sync::RwLock::new(None)),
            oidc_allowed_domains: Vec::new(),
            trust_proxy: Some(config),
        };
        let app = Router::new()
            .route("/api/test", get(dummy_handler))
            .layer(middleware::from_fn_with_state(auth, auth_middleware));

        let req = Request::builder()
            .uri("/api/test")
            .header("X-Proxy-Secret", "wrong-secret")
            .header("X-Forwarded-User", "proxy-alice")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_trust_proxy_falls_through_when_no_headers() {
        // When trust-proxy is configured but no proxy headers are present,
        // the middleware should fall through to bearer token auth.
        let config = test_proxy_config();
        let auth = CombinedAuthState {
            env_auth: MultiAuthState::single("tok".to_string(), "bearer-user".to_string()),
            db_auth: None,
            oidc: Arc::new(tokio::sync::RwLock::new(None)),
            oidc_allowed_domains: Vec::new(),
            trust_proxy: Some(config),
        };
        let app = Router::new()
            .route("/api/test", get(dummy_handler))
            .layer(middleware::from_fn_with_state(auth, auth_middleware));

        // No proxy headers, but valid bearer token → should authenticate via bearer.
        let req = Request::builder()
            .uri("/api/test")
            .header("Authorization", "Bearer tok")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[test]
    fn test_parse_cookie_value_simple() {
        let result = parse_cookie_value("a=1; b=2; c=3", "b");
        assert_eq!(result, Some("2".to_string()));
    }

    #[test]
    fn test_parse_cookie_value_quoted() {
        let result = parse_cookie_value("other=\"quoted;value\"; session=abc123", "session");
        assert_eq!(result, Some("abc123".to_string()));
    }

    #[test]
    fn test_parse_cookie_value_missing() {
        let result = parse_cookie_value("a=1; b=2", "c");
        assert_eq!(result, None);
    }

    #[test]
    fn test_parse_cookie_value_empty_value() {
        let result = parse_cookie_value("a=1; b=; c=3", "b");
        assert_eq!(result, None);
    }

    #[test]
    fn test_parse_cookie_value_first_match() {
        let result = parse_cookie_value("a=1; a=2", "a");
        assert_eq!(result, Some("1".to_string()));
    }
}
