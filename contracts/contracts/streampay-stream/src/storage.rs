//! # Contract storage layout
//!
//! All persistent state for the `StreamPay` contract is keyed by
//! [`DataKey`]. There are two storage tiers in use:
//!
//! - **Instance storage** holds singletons: `Admin`, `Paused`, the
//!   stream counter, and the per-token allowlist. These keys live for
//!   the lifetime of the contract instance and are extended together.
//! - **Persistent storage** holds per-stream rows keyed by stream id,
//!   and per-stream withdrawer allowlists keyed by stream id.
//!   These rows are TTL-extended every time the stream is read or
//!   written so an active stream cannot expire mid-flight.
//!
//! The TTL constants below are tuned for long-running payment streams
//! plus a generous recovery buffer; keep them in sync with the
//! operational runbook.

use soroban_sdk::{contracttype, Address, Env, Vec};

/// Lifecycle status of a [`Stream`] stored on-chain.
///
/// | Variant     | Description                                                        |
/// |-------------|--------------------------------------------------------------------|
/// | `Draft`     | Created but not yet started; no accrual occurs.                    |
/// | `Active`    | Tokens are vesting linearly from `start_time` to `end_time`.       |
/// | `Paused`    | Accrual frozen; `end_time` will be extended on resume.             |
/// | `Settled`   | Fully paid out; terminal state.                                    |
/// | `Ended`     | Time window elapsed, awaiting settle; transitional.                |
/// | `Cancelled` | Cancelled by sender before full vesting; terminal state.           |
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[contracttype]
pub enum StreamStatus {
    Draft,
    Active,
    Paused,
    Settled,
    Ended,
    Cancelled,
}

/// On-chain record for a single payment stream.
///
/// Each stream escrows `total_amount` from `sender` and releases it
/// linearly to `recipient` from `start_time` to `end_time`. The
/// `released_amount` tracks cumulative withdrawals; when it reaches
/// `total_amount` the stream transitions to `Settled`.
///
/// Paused streams record `paused_at` and `total_paused_duration` so
/// that the resumption logic can extend `end_time` by the pause length
/// without over- or under-paying the recipient.
#[derive(Clone, Debug)]
#[contracttype]
pub struct Stream {
    pub id: u64,
    pub sender: Address,
    pub recipient: Address,
    pub token: Address,
    pub total_amount: i128,
    pub released_amount: i128,
    pub start_time: u64,
    pub end_time: u64,
    pub duration: u64,
    pub last_update: u64,
    pub status: StreamStatus,
    pub paused_at: u64,
    pub total_paused_duration: u64,
    /// Per-stream fee in basis points `[0, 10_000]`.
    ///
    /// Set at creation time. Applied to every [`crate::Contract::withdraw`]
    /// call: `fee_amount = floor(amount * fee_bps / 10_000)`. If no fee
    /// collector has been configured, the fee is skipped regardless of this
    /// value.
    pub fee_bps: u32,
}

#[derive(Clone)]
#[contracttype]
pub(crate) enum DataKey {
    Admin,
    Paused,
    StreamCount,
    Stream(u64),
    TokenAllowed(Address),
    /// Protocol-level fee in basis points (0–10 000).
    ///
    /// Absent means no fee (equivalent to `0`). Stored in instance storage so
    /// it lives for the lifetime of the contract.
    FeeBps,
}

/// Threshold and absolute target values are expressed in ledger sequences.
///
/// Stream entries use a 2-week look-ahead threshold and a 3-month extension
/// target, giving active streams a wide safety margin against archival pressure
/// on hot read paths (every `get_stream`, `withdrawable`, and `withdraw` call
/// re-stamps the TTL).
///
/// Instance keys (admin, paused flag, stream counter) use a 1-week threshold
/// and a 1-month target; they are touched on every state-changing call so they
/// stay warm under normal operation.
///
/// Token-allowlist entries share the instance cadence: 1-week threshold,
/// 1-month target. They are re-stamped on every `create_stream` check and on
/// every admin `set_token_allowed` write.
pub const STREAM_TTL_MIN_REMAINING: u32 = 241_920; // ~2 weeks at 5-second ledgers
pub const STREAM_TTL_EXTEND_TO: u32 = 1_555_200; // ~3 months at 5-second ledgers
pub const INSTANCE_TTL_MIN_REMAINING: u32 = 120_960; // ~1 week at 5-second ledgers
pub const INSTANCE_TTL_EXTEND_TO: u32 = 518_400; // ~1 month at 5-second ledgers
/// Per-token allowlist TTL constants.
///
/// Every `is_token_blocked` call (hot path inside `create_stream`) extends
/// the allowlist entry's TTL so a token that is actively being streamed
/// cannot silently archive between stream creation and withdrawal.
pub const TOKEN_TTL_MIN_REMAINING: u32 = 120_960; // ~1 week at 5-second ledgers
pub const TOKEN_TTL_EXTEND_TO: u32 = 518_400; // ~1 month at 5-second ledgers

fn ttl_target(env: &Env, extra_ledgers: u32) -> u32 {
    env.ledger().sequence().saturating_add(extra_ledgers)
}

fn extend_persistent_ttl(env: &Env, key: &DataKey) {
    // In soroban-sdk 23.x, get_ttl is only available via testutils and the
    // extend_ttl call itself short-circuits when the key's TTL is already
    // above the threshold. We therefore call extend_ttl unconditionally
    // with the minimum remaining TTL as the threshold.
    let threshold = env
        .ledger()
        .sequence()
        .saturating_add(STREAM_TTL_MIN_REMAINING);
    let target = ttl_target(env, STREAM_TTL_EXTEND_TO);
    env.storage()
        .persistent()
        .extend_ttl(key, threshold, target);
}

fn extend_instance_ttl(env: &Env, _key: &DataKey) {
    // Instance storage in soroban-sdk 23.x does not accept a key argument
    // to extend_ttl; the host function extends the entire current contract
    // instance. The call short-circuits internally when the instance TTL
    // already exceeds the threshold.
    let threshold = env
        .ledger()
        .sequence()
        .saturating_add(INSTANCE_TTL_MIN_REMAINING);
    let target = ttl_target(env, INSTANCE_TTL_EXTEND_TO);
    env.storage().instance().extend_ttl(threshold, target);
}

fn extend_token_allowed_ttl(env: &Env, token: &Address) {
    let threshold = env
        .ledger()
        .sequence()
        .saturating_add(TOKEN_TTL_MIN_REMAINING);
    let target = ttl_target(env, TOKEN_TTL_EXTEND_TO);
    env.storage()
        .persistent()
        .extend_ttl(&DataKey::TokenAllowed(token.clone()), threshold, target);
}

fn extend_stream_ttl(env: &Env, stream_id: u64) {
    extend_persistent_ttl(env, &DataKey::Stream(stream_id));
}

fn extend_withdrawer_allowlist_ttl(env: &Env, stream_id: u64) {
    extend_persistent_ttl(env, &DataKey::WithdrawerAllowlist(stream_id));
}

fn extend_admin_key_ttl(env: &Env) {
    extend_instance_ttl(env, &DataKey::Admin);
}

fn extend_pause_key_ttl(env: &Env) {
    extend_instance_ttl(env, &DataKey::Paused);
}

fn extend_next_stream_id_ttl(env: &Env) {
    extend_instance_ttl(env, &DataKey::StreamCount);
}

/// Returns whether an admin key is present in instance storage.
///
/// If the admin key exists, this helper extends its TTL to ensure the
/// governance address does not expire mid-flight.
///
/// # Returns
/// - `true` if [`DataKey::Admin`] exists.
/// - `false` otherwise.
///
/// # Errors
/// This helper does not return errors.
pub fn has_admin(env: &Env) -> bool {
    let exists = env.storage().instance().has(&DataKey::Admin);
    if exists {
        extend_admin_key_ttl(env);
    }
    exists
}

/// Sets the contract admin address in instance storage.
///
/// This helper also extends the admin key TTL.
///
/// # Returns
/// This helper does not return a value.
///
/// # Errors
/// This helper does not return errors.
pub fn set_admin(env: &Env, admin: &Address) {
    env.storage().instance().set(&DataKey::Admin, admin);
    extend_admin_key_ttl(env);
}

/// Returns the stored admin address, if any.
///
/// If an admin value exists, this helper extends its TTL.
///
/// # Returns
/// - `Some(Address)` if [`DataKey::Admin`] exists.
/// - `None` otherwise.
///
/// # Errors
/// This helper does not return errors.
pub fn get_admin(env: &Env) -> Option<Address> {
    let admin = env.storage().instance().get(&DataKey::Admin);
    if admin.is_some() {
        extend_admin_key_ttl(env);
    }
    admin
}

/// Sets the global paused flag in instance storage.
///
/// This helper also extends the paused key TTL.
///
/// # Returns
/// This helper does not return a value.
///
/// # Errors
/// This helper does not return errors.
pub fn set_paused(env: &Env, paused: bool) {
    env.storage().instance().set(&DataKey::Paused, &paused);
    extend_pause_key_ttl(env);
}

/// Returns whether the contract is currently paused.
///
/// Uses a single storage read to check and retrieve the flag; extends the
/// instance TTL on the hot read path so the paused flag never archives while
/// the contract is actively receiving calls.
///
/// # Returns
/// - `true` if paused is set to `true`.
/// - `false` if paused is unset or set to `false`.
///
/// # Errors
/// This helper does not return errors.
pub fn is_paused(env: &Env) -> bool {
    let result: Option<bool> = env.storage().instance().get(&DataKey::Paused);
    if result.is_some() {
        extend_pause_key_ttl(env);
    }
    result.unwrap_or(false)
}

/// Sets whether a given token is allowed for future stream creation.
///
/// Tokens are allowed by default when there is no entry for the token. When
/// `allowed = false`, the function writes a deny entry that makes the token
/// "blocked" for future stream creation. The entry's TTL is extended on
/// every write so allowlist state does not archive under active use.
///
/// # Returns
/// This helper does not return a value.
///
/// # Errors
/// This helper does not return errors.
pub fn set_token_allowed(env: &Env, token: &Address, allowed: bool) {
    env.storage()
        .persistent()
        .set(&DataKey::TokenAllowed(token.clone()), &allowed);
    extend_token_allowed_ttl(env, token);
}

/// Returns whether a given token is blocked.
///
/// This is the logical negation of `set_token_allowed(..., allowed = true)`.
/// If no allow entry exists, the token is treated as allowed (therefore not
/// blocked). When an entry exists, its TTL is extended so that a token used
/// in a long-running stream does not archive between `create_stream` and the
/// final `withdraw`.
///
/// # Returns
/// - `true` if the token is explicitly blocked.
/// - `false` if explicitly allowed or unset.
///
/// # Errors
/// This helper does not return errors.
pub fn is_token_blocked(env: &Env, token: &Address) -> bool {
    match env
        .storage()
        .persistent()
        .get::<DataKey, bool>(&DataKey::TokenAllowed(token.clone()))
    {
        Some(allowed) => {
            extend_token_allowed_ttl(env, token);
            !allowed
        }
        None => false,
    }
}

/// Returns the next stream id and increments the stored counter.
///
/// Stream ids start at `1` when the counter is unset. This helper extends the
/// TTL of the stream id counter key.
///
/// # Returns
/// The stream id that should be assigned to the next created stream.
///
/// # Errors
/// This helper does not return errors.
pub fn next_stream_id(env: &Env) -> u64 {
    let storage = env.storage().instance();
    let id = storage.get(&DataKey::StreamCount).unwrap_or(1u64);
    storage.set(&DataKey::StreamCount, &id.saturating_add(1));
    extend_next_stream_id_ttl(env);
    id
}

/// Returns the next stream id **without** incrementing the counter.
///
/// This is a read-only helper used by paginated list views to determine the
/// upper bound of stream IDs to scan. It does not consume a stream ID or
/// modify any storage state.
///
/// # Returns
/// The value of the next-stream-ID counter (i.e. the ID that *would* be
/// assigned to the next `create_stream` call). Returns `1` if no streams
/// have ever been created.
pub fn peek_next_stream_id(env: &Env) -> u64 {
    let storage = env.storage().instance();
    let id: u64 = storage.get(&DataKey::StreamCount).unwrap_or(1u64);
    id
}

/// Test-only helper: directly sets the stream-ID counter to `id`.
///
/// Allows unit tests to seed the counter to a known value without having to
/// create actual streams. Not available in production builds.
#[cfg(test)]
pub fn set_next_stream_id_for_test(env: &Env, id: u64) {
    env.storage().instance().set(&DataKey::StreamCount, &id);
}

pub fn set_stream(env: &Env, stream_id: u64, stream: &Stream) {
    env.storage()
        .persistent()
        .set(&DataKey::Stream(stream_id), stream);
    extend_stream_ttl(env, stream_id);
}

/// Reads a stream record from persistent storage.
///
/// If the stream exists, this helper extends the TTL for the corresponding
/// per-stream entry so a frequently queried stream stays live on the hot
/// read path.
///
/// # Returns
/// - `Some(Stream)` if the stream exists.
/// - `None` otherwise.
///
/// # Errors
/// This helper does not return errors.
pub fn get_stream(env: &Env, stream_id: u64) -> Option<Stream> {
    let stream = env.storage().persistent().get(&DataKey::Stream(stream_id));
    if stream.is_some() {
        extend_stream_ttl(env, stream_id);
    }
    stream
}

/// Sets the protocol-level fee in basis points (0–10 000).
///
/// Stored in instance storage so it lives for the contract lifetime. Extends
/// instance TTL on every write to keep the fee configuration alive.
///
/// A value of `0` means no fee is charged; `10_000` means 100 % (full amount).
///
/// # Returns
/// This helper does not return a value.
pub fn set_fee_bps(env: &Env, fee_bps: u32) {
    env.storage().instance().set(&DataKey::FeeBps, &fee_bps);
    extend_instance_ttl(env, &DataKey::FeeBps);
}

/// Returns the current protocol-level fee in basis points.
///
/// Returns `0` if no fee has been configured (absent key). Extends instance
/// TTL on the hot path so the fee configuration stays live under normal use.
///
/// # Returns
/// Fee in basis points, in the range `[0, 10_000]`.
pub fn get_fee_bps(env: &Env) -> u32 {
    let fee: Option<u32> = env.storage().instance().get(&DataKey::FeeBps);
    if fee.is_some() {
        extend_instance_ttl(env, &DataKey::FeeBps);
    }
    fee.unwrap_or(0)
}