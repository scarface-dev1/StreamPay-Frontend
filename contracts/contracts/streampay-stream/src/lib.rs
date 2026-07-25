//! # `StreamPay` Stream Contract
//!
//! Soroban smart contract that manages linear payment streams on Stellar.
//! Each stream locks a fixed token amount in escrow and releases it linearly
//! to a recipient over a configurable duration.
//!
//! ## Lifecycle
//!
//! ```text
//! Draft ──start_stream──► Active ──withdraw (full)──► Settled
//! ```
//!
//! ## Administrative controls
//!
//! A single admin address (set at [`Contract::initialize`]) may:
//! - Toggle the global emergency pause ([`Contract::set_paused`]).
//! - Allow or block individual token contracts ([`Contract::set_token_allowed`]).
#![no_std]

mod allowlist;
mod error;
mod events;
mod fees;
mod limits;
mod migrate;
mod multi;
mod release;
mod snapshot_diff;
mod storage;
mod views;
pub mod admin;
mod withdrawer;

pub use error::Error;
use soroban_sdk::contracttype;
use soroban_sdk::{contract, contractimpl, token, Address, BytesN, Env};
pub use multi::{RecipientAllocation, SplitStream};
pub use snapshot_diff::{SnapshotDiff, StreamSnapshot};
pub use storage::{Stream, StreamStatus};
pub(crate) use storage::DataKey;

/// The `StreamPay` contract entry point registered with the Soroban host.
#[contract]
pub struct Contract;

/// Ledger storage keys used internally by this contract.
///
/// Not exposed to callers; listed here for auditability.
#[derive(Clone)]
#[contracttype]
enum DataKey {
    /// The privileged admin [`Address`].
    Admin,
    /// Global emergency pause flag (`bool`).
    Paused,
    /// Monotonic counter; value is the **next** stream ID to assign.
    NextStreamId,
    /// Per-stream record keyed by numeric ID.
    Stream(u64),
    /// Per-token allowlist entry. Absent or `true` → allowed; `false` → blocked.
    TokenAllowed(Address),
}

#[allow(clippy::needless_pass_by_value, clippy::must_use_candidate)]
#[contractimpl]
impl Contract {
    /// One-time contract initialisation.
    ///
    /// Records `admin` as the privileged address for [`Contract::set_paused`]
    /// and [`Contract::set_token_allowed`]. Sets the global pause flag to
    /// `false`.
    ///
    /// # Parameters
    /// - `admin` — Address that will have admin privileges over this contract.
    /// Records `admin` as the privileged address for `set_paused` and
    /// `set_token_allowed`. Sets the global pause flag to `false`.
    ///
    /// # Errors
    /// - [`Error::AlreadyInitialized`] if the contract has already been initialised.
    ///
    /// # Auth
    /// Requires authorisation from `admin`.
    pub fn initialize(env: Env, admin: Address) -> Result<(), Error> {
        if storage::has_admin(&env) {
            return Err(Error::AlreadyInitialized);
        }

        admin.require_auth();
        storage::set_admin(&env, &admin);
        storage::set_paused(&env, false);
        // Emit a deprecated-entrypoint event so indexers and off-chain tooling
        // can detect legacy initialisation calls.
        events::deprecated_entrypoint(
            &env,
            &admin,
            soroban_sdk::symbol_short!("initialize"),
            env.ledger().timestamp(),
        );
        Ok(())
    }

    /// Atomic initialisation + token allowlist.
    ///
    /// Performs the work of `initialize` and then marks each
    /// address in `tokens` as `allowed = true` in the per-token
    /// allowlist, all within a single transaction.
    ///
    /// Use this from deployment scripts so that the admin and the
    /// initial allowlist are committed together: either the whole
    /// configuration lands atomically or nothing does. Because
    /// Soroban rolls back all storage writes on failure, calling
    /// this on a contract that is already initialised (or with a
    /// caller that fails auth) leaves zero partial state.
    ///
    /// Tokens are allowed by default; explicitly writing
    /// `allowed = true` here is idempotent for tokens that are
    /// already allowed and has no effect on tokens that are
    /// subsequently blocked via `set_token_allowed`.
    ///
    /// # Arguments
    ///
    /// * `admin`  - The privileged address authorised to call
    ///   admin entrypoints (`set_paused`, `set_admin`,
    ///   `set_token_allowed`).
    /// * `tokens` - The list of token contract addresses to
    ///   register in the allowlist. May be empty if the contract
    ///   intends to stream the native asset or add tokens lazily
    ///   via `set_token_allowed` later.
    ///
    /// # Errors
    ///
    /// - `Error::AlreadyInitialized` if the contract has already been
    ///   initialised. The allowlist is *not* partially written.
    ///
    /// # Auth
    ///
    /// Requires authorisation from `admin`. Auth is consumed
    /// before any state mutation so that an auth failure cannot
    /// leave the contract half-configured.
    ///
    /// # See also
    ///
    /// - `initialize` - the legacy two-step path; still supported
    ///   for backward compatibility.
    /// - `set_token_allowed` - the per-token toggle used after
    ///   initialisation.
    pub fn init_with_token_allowlist(
        env: Env,
        admin: Address,
        tokens: soroban_sdk::Vec<Address>,
    ) -> Result<(), Error> {
        // Guard against double initialisation. We check *before* any
        // writes so that a previously-initialised contract cannot have
        // its allowlist silently mutated.
        if storage::has_admin(&env) {
            return Err(Error::AlreadyInitialized);
        }

        // Authorise the caller up-front. Soroban rolls back all
        // storage writes on auth failure, but collecting auth first
        // makes the atomicity guarantee obvious to reviewers and
        // mirrors the pattern used by `initialize`.
        admin.require_auth();

        // From this point on the transaction either commits all
        // writes or none of them - the host aborts and reverts on
        // any panic, so any failure below (none expected under
        // normal conditions) leaves the contract uninitialised.
        storage::set_admin(&env, &admin);
        storage::set_paused(&env, false);

        // Iterate the allowlist. `Vec::iter` returns an iterator
        // over the on-chain vector; each `set_token_allowed` call
        // writes a single persistent-storage entry.
        for token in tokens.iter() {
            storage::set_token_allowed(&env, &token, true);
        }

        Ok(())
    }

    /// Atomic initialisation + global + per-org token allowlist.
    ///
    /// Performs the work of `initialize`, configures the global allowlist,
    /// and configures a per-org allowlist for the given `org`, all within
    /// a single transaction.
    ///
    /// Use this from deployment scripts to atomically set up the contract
    /// with both global and per-org configurations.
    ///
    /// # Arguments
    ///
    /// * `admin` - The privileged address authorised to call admin entrypoints.
    /// * `tokens` - The list of token contract addresses to register in the global allowlist.
    /// * `org` - The organisation to configure a per-org allowlist for.
    /// * `org_tokens` - The list of token contract addresses to allow for `org`.
    ///
    /// # Errors
    ///
    /// - `Error::AlreadyInitialized` if the contract has already been initialised.
    ///
    /// # Auth
    ///
    /// Requires authorisation from `admin`.
    pub fn init_with_token_allowlist_for_org(
        env: Env,
        admin: Address,
        tokens: soroban_sdk::Vec<Address>,
        org: Address,
        org_tokens: soroban_sdk::Vec<Address>,
    ) -> Result<(), Error> {
        if storage::has_admin(&env) {
            return Err(Error::AlreadyInitialized);
        }

        admin.require_auth();

        storage::set_admin(&env, &admin);
        storage::set_paused(&env, false);

        for token in tokens.iter() {
            storage::set_token_allowed(&env, &token, true);
        }

        for token in org_tokens.iter() {
            allowlist::set_org_token_allowed(&env, &org, &token, true);
        }

        Ok(())
    }

    /// Sets the global emergency pause flag.
    ///
    /// When `paused` is `true`, `create_stream`, `start_stream`, and `withdraw`
    /// all return [`Error::ContractPaused`]. Read-only calls (`get_stream`,
    /// `withdrawable`) are unaffected.
    ///
    /// # Errors
    /// - [`Error::Unauthorized`] if `admin` is not the initialised admin.
    /// - [`Error::NotFound`] if the contract has not been initialised.
    ///
    /// # Auth
    /// Requires authorisation from `admin`.
    pub fn set_paused(env: Env, admin: Address, paused: bool) -> Result<(), Error> {
        require_admin(&env, &admin)?;
        storage::set_paused(&env, paused);
        events::paused_set(&env, &admin, paused, env.ledger().timestamp());
        Ok(())
    }

    /// Transfers the admin role to a new address.
    ///
    /// # Errors
    /// - [`Error::Unauthorized`] if `admin` is not the initialised admin.
    ///
    /// # Auth
    /// Requires authorisation from current `admin`.
    pub fn set_admin(env: Env, admin: Address, new_admin: Address) -> Result<(), Error> {
        require_admin(&env, &admin)?;
        storage::set_admin(&env, &new_admin);
        events::admin_changed(&env, &admin, &new_admin, env.ledger().timestamp());
        Ok(())
    }

    /// Allows or blocks a token for future stream creation.
    ///
    /// Tokens are allowed by default (no entry in storage). Setting
    /// `allowed = false` blocks the token; `allowed = true` re-enables it.
    /// Existing streams using a subsequently blocked token are unaffected.
    ///
    /// # Parameters
    /// - `admin`   — Must match the admin set at initialisation.
    /// - `token`   — Stellar asset contract address to configure.
    /// - `allowed` — `true` to allow; `false` to block.
    ///
    /// # Errors
    /// - [`Error::Unauthorized`] if `admin` is not the initialised admin.
    /// - [`Error::NotFound`] if the contract has not been initialised.
    ///
    /// # Auth
    /// Requires authorisation from `admin`.
    pub fn set_token_allowed(
        env: Env,
        admin: Address,
        token: Address,
        allowed: bool,
    ) -> Result<(), Error> {
        require_admin(&env, &admin)?;
        storage::set_token_allowed(&env, &token, allowed);
        events::token_allowed_set(&env, &admin, &token, allowed, env.ledger().timestamp());
        Ok(())
    }

    // ── Fee configuration entrypoints ─────────────────────────────────────────

    /// Sets the address that receives protocol fees on every withdrawal.
    ///
    /// When no fee collector is set (default), the full withdrawal amount goes
    /// to the recipient regardless of `fee_bps`. Setting a non-`None` collector
    /// activates fee collection on all streams whose `fee_bps > 0`.
    ///
    /// # Parameters
    /// - `admin`     — Must match the admin set at initialisation.
    /// - `collector` — Address that will receive future fee transfers.
    ///
    /// # Errors
    /// - [`Error::Unauthorized`] if `admin` is not the initialised admin.
    ///
    /// # Auth
    /// Requires authorisation from `admin`.
    pub fn set_fee_collector(env: Env, admin: Address, collector: Address) -> Result<(), Error> {
        require_admin(&env, &admin)?;
        fees::set_fee_collector(&env, &collector);
        events::fee_collector_set(&env, &admin, &collector, env.ledger().timestamp());
        Ok(())
    }

    /// Returns the current fee collector address, or `None` if unset.
    ///
    /// When no fee collector is set, the full withdrawal amount (including
    /// any per-stream fee) goes to the recipient. See [`Contract::set_fee_collector`]
    /// for how to configure the collector.
    ///
    /// # Returns
    /// - `Some(Address)` — the configured fee collector address.
    /// - `None` — no fee collector has been set; fees are not deducted.
    ///
    /// # Errors
    /// This entrypoint is read-only and never returns an error.
    pub fn get_fee_collector(env: Env) -> Option<Address> {
        fees::get_fee_collector(&env)
    }

    /// Sets the global default `fee_bps` applied to streams that do not supply
    /// an explicit per-stream override.
    ///
    /// The value must be in `[0, 10_000]` (0 % – 100 %).
    ///
    /// # Parameters
    /// - `admin`   — Must match the admin set at initialisation.
    /// - `fee_bps` — Default fee in basis points.
    ///
    /// # Errors
    /// - [`Error::Unauthorized`] if `admin` is not the initialised admin.
    /// - [`Error::InvalidFeeBps`] if `fee_bps > 10_000`.
    ///
    /// # Auth
    /// Requires authorisation from `admin`.
    pub fn set_default_fee_bps(env: Env, admin: Address, fee_bps: u32) -> Result<(), Error> {
        require_admin(&env, &admin)?;
        fees::validate_fee_bps(fee_bps)?;
        fees::set_default_fee_bps(&env, fee_bps);
        events::default_fee_bps_set(&env, &admin, fee_bps, env.ledger().timestamp());
        Ok(())
    }

    /// Returns the global default `fee_bps` (0 if never set).
    ///
    /// This is the fee basis points applied to streams that do not supply
    /// an explicit per-stream override at creation time. The default is `0`
    /// unless modified via [`Contract::set_default_fee_bps`].
    ///
    /// # Returns
    /// The default fee in basis points `[0, 10_000]`.
    ///
    /// # Errors
    /// This entrypoint is read-only and never returns an error.
    pub fn get_default_fee_bps(env: Env) -> u32 {
        fees::get_default_fee_bps(&env)
    }

    /// Returns the effective `fee_bps` for `stream_id`.
    ///
    /// This is the per-stream override if one was supplied at creation time,
    /// otherwise it falls back to the global default (which is `0` by default).
    ///
    /// # Errors
    /// - [`Error::NotFound`] if `stream_id` does not exist.
    pub fn get_stream_fee_bps(env: Env, stream_id: u64) -> Result<u32, Error> {
        // Verify the stream actually exists before returning a fee value.
        get_existing_stream(&env, stream_id)?;
        Ok(fees::get_stream_fee_bps(&env, stream_id))
    }

    /// Configures the **per-organisation** token allowlist for `org`.
    ///
    /// This layers on top of the global allowlist ([`Contract::set_token_allowed`]):
    /// the first time an org is granted a token (`allowed = true`) the org
    /// switches to whitelist mode, after which any token the org has not
    /// explicitly allowed is blocked for that org's streams created via
    /// [`Contract::create_stream_for_org`]. Setting `allowed = false` records an
    /// explicit per-org block.
    ///
    /// # Parameters
    /// - `admin`   — Must match the admin set at initialisation.
    /// - `org`     — Organisation address the rule applies to.
    /// - `token`   — Token contract address being configured.
    /// - `allowed` — `true` to allow for this org; `false` to block.
    ///
    /// # Errors
    /// - [`Error::Unauthorized`] if `admin` is not the initialised admin.
    /// - [`Error::NotFound`] if the contract has not been initialised.
    ///
    /// # Auth
    /// Requires authorisation from `admin`.
    pub fn set_org_token_allowed(
        env: Env,
        admin: Address,
        org: Address,
        token: Address,
        allowed: bool,
    ) -> Result<(), Error> {
        require_admin(&env, &admin)?;
        allowlist::set_org_token_allowed(&env, &org, &token, allowed);
        Ok(())
    }

    /// Returns `true` if `token` is allowed for `org` under the per-org
    /// allowlist (read-only; also honours the global allowlist).
    ///
    /// A token is allowed when both the global allowlist and the per-org
    /// allowlist permit it. See [`Contract::set_org_token_allowed`] for
    /// the per-org allowlist semantics.
    ///
    /// This is a read-only view that never mutates state or requires auth.
    ///
    /// # Returns
    /// - `true` — `token` is allowed for `org` (neither global nor per-org
    ///   allowlist blocks it).
    /// - `false` — `token` is blocked for `org`.
    pub fn is_org_token_allowed(env: Env, org: Address, token: Address) -> bool {
        !allowlist::is_org_token_blocked(&env, &org, &token)
            && !storage::is_token_blocked(&env, &token)
    }

    /// Creates a funded stream on behalf of `org`, enforcing the per-org token
    /// allowlist in addition to all the checks performed by
    /// [`Contract::create_stream`].
    ///
    /// `org` is the organisation the stream is attributed to; the per-org
    /// allowlist for `(org, token)` is consulted before the stream is created.
    ///
    /// # Errors
    /// In addition to every error of [`Contract::create_stream`]:
    /// - [`Error::TokenNotAllowed`] if `token` is blocked for `org` by the
    ///   per-org allowlist.
    ///
    /// # Auth
    /// Requires authorisation from `sender`.
    #[allow(clippy::too_many_arguments)]
    pub fn create_stream_for_org(
        env: Env,
        org: Address,
        sender: Address,
        recipient: Address,
        token: Address,
        total_amount: i128,
        start_time: u64,
        end_time: u64,
        fee_bps: u32,
    ) -> Result<u64, Error> {
        // Per-org allowlist gate runs first so a blocked token is rejected
        // before any auth/escrow side effects in create_stream.
        if allowlist::is_org_token_blocked(&env, &org, &token) {
            return Err(Error::TokenNotAllowed);
        }

        Self::create_stream(
            env,
            sender,
            recipient,
            token,
            total_amount,
            start_time,
            end_time,
            fee_bps,
        )
    }

    /// Sets the maximum number of active streams a single sender may have
    /// concurrently. This is a per-sender rate limit: once a sender reaches
    /// the limit, [`Contract::create_stream`] returns
    /// [`Error::StreamLimitExceeded`] until an existing stream transitions
    /// to a terminal state (`Settled` or `Cancelled`).
    ///
    /// # Parameters
    /// - `admin` — Must match the admin set at initialisation.
    /// - `limit` — Maximum number of concurrent active streams per sender.
    ///
    /// # Errors
    /// - [`Error::Unauthorized`] if `admin` is not the initialised admin.
    ///
    /// # Auth
    /// Requires authorisation from `admin`.
    pub fn set_max_streams_per_sender(env: Env, admin: Address, limit: u64) -> Result<(), Error> {
        require_admin(&env, &admin)?;
        limits::set_max_streams_per_sender(&env, limit);
        Ok(())
    }

    /// Returns the current per-sender stream limit.
    ///
    /// This is the maximum number of active (non-terminal) streams a single
    /// sender may have concurrently. Defaults to `10` if not explicitly set
    /// via [`Contract::set_max_streams_per_sender`].
    ///
    /// # Returns
    /// The per-sender limit as a `u64`.
    ///
    /// # Errors
    /// This entrypoint is read-only and never returns an error.
    pub fn max_streams_per_sender(env: Env) -> u64 {
        limits::get_max_streams_per_sender(&env)
    }

    /// Returns the number of active streams currently attributed to `sender`.
    ///
    /// # Parameters
    /// - `sender` — Address to query.
    ///
    /// # Returns
    /// The count of non-terminal streams for `sender`. Returns `0` if the
    /// sender has never created a stream or all their streams are settled.
    ///
    /// # Errors
    /// This entrypoint is read-only and never returns an error.
    pub fn sender_stream_count(env: Env, sender: Address) -> u64 {
        limits::get_sender_stream_count(&env, &sender)
    }

    /// Returns how many more streams `sender` may create before reaching the
    /// configured per-sender limit (`0` once the limit is reached).
    ///
    /// # Parameters
    /// - `sender` — Address to query.
    ///
    /// # Returns
    /// The remaining capacity: `limit - current_count`. Returns `0` once the
    /// sender is at or above the limit.
    ///
    /// # Errors
    /// This entrypoint is read-only and never returns an error.
    pub fn remaining_sender_capacity(env: Env, sender: Address) -> u64 {
        limits::remaining_sender_capacity(&env, &sender)
    }

    /// Sets the protocol-level fee in basis points charged on each withdrawal.
    ///
    /// A fee of `0` means no fee is deducted. A fee of `10_000` means 100 % of
    /// the withdrawn amount is taken as a fee (degenerate case; callers that set
    /// `max_fee_bps = 0` will always reject this). The fee is charged at
    /// withdrawal time via [`Contract::withdraw_with_max_fee_bps`]; the plain
    /// [`Contract::withdraw`] entrypoint is never modified and remains
    /// fee-free to preserve backward compatibility.
    ///
    /// # Parameters
    /// - `admin`   — Must match the admin set at initialisation.
    /// - `fee_bps` — New fee in basis points. Must be in the range `[0, 10_000]`.
    ///
    /// # Errors
    /// - [`Error::Unauthorized`] if `admin` is not the initialised admin.
    /// - [`Error::NotFound`] if the contract has not been initialised.
    /// - [`Error::InvalidAmount`] if `fee_bps > 10_000`.
    ///
    /// # Auth
    /// Requires authorisation from `admin`.
    pub fn set_fee_bps(env: Env, admin: Address, fee_bps: u32) -> Result<(), Error> {
        require_admin(&env, &admin)?;
        if fee_bps > 10_000 {
            return Err(Error::InvalidAmount);
        }
        storage::set_fee_bps(&env, fee_bps);
        Ok(())
    }

    /// Returns the current protocol-level fee in basis points.
    ///
    /// This fee is charged on withdrawals made via
    /// [`Contract::withdraw_with_max_fee_bps`]. Returns `0` when no fee
    /// has been configured (the default).
    ///
    /// # Returns
    /// The protocol fee in basis points, in the range `[0, 10_000]`.
    ///
    /// # Errors
    /// This entrypoint is read-only and never returns an error.
    pub fn fee_bps(env: Env) -> u32 {
        storage::get_fee_bps(&env)
    }

    /// Withdraws `amount` of accrued tokens with a per-call slippage guard.
    ///
    /// This is the guarded variant of [`Contract::withdraw`]. Before executing
    /// the withdrawal, the caller specifies the maximum protocol fee (in basis
    /// points) they are willing to accept. If the current protocol fee exceeds
    /// `max_fee_bps`, the call reverts with [`Error::FeeTooHigh`] — no funds
    /// are moved and no state is changed. This prevents an on-chain fee increase
    /// from silently changing the economics of an in-flight transaction.
    ///
    /// ## Fee deduction
    ///
    /// When `fee_bps > 0`, the protocol fee is deducted from the transferred
    /// amount:
    ///
    /// - `fee_amount = amount * fee_bps / 10_000` (rounds down; safe for the
    ///   recipient, never exceeds `amount`)
    /// - `recipient_amount = amount - fee_amount`
    /// - `recipient_amount` is transferred to the stream recipient.
    /// - `fee_amount` is transferred to the contract admin address.
    ///
    /// When `fee_bps == 0` (no fee), the full `amount` goes to the recipient,
    /// identical to the plain [`Contract::withdraw`].
    ///
    /// ## Overflow safety
    ///
    /// All fee arithmetic uses checked or saturating operations. The product
    /// `amount * fee_bps` is computed as `i128 * u32 → i128` via
    /// [`i128::checked_mul`]; if the multiplication overflows
    /// [`Error::Overflow`] is returned rather than panicking.
    ///
    /// ## Backward compatibility
    ///
    /// The plain [`Contract::withdraw`] entrypoint is unmodified. Existing
    /// callers that do not want fee-aware withdrawals continue to work as
    /// before.
    ///
    /// # Parameters
    /// - `stream_id`    — Numeric ID of the stream to withdraw from.
    /// - `amount`       — Token amount (base units) to withdraw. Must be > 0 and
    ///   ≤ the currently accrued withdrawable balance.
    /// - `max_fee_bps`  — Caller's maximum acceptable fee in basis points
    ///   (0–10 000). The call reverts if `current_fee_bps > max_fee_bps`.
    ///
    /// # Returns
    /// The `amount` that was charged against the stream balance on success
    /// (i.e. the gross withdrawal before fee deduction).
    ///
    /// # Errors
    /// - [`Error::FeeTooHigh`] if the current protocol fee exceeds `max_fee_bps`.
    /// - [`Error::ContractPaused`] if the global pause flag is set.
    /// - [`Error::InvalidAmount`] if `amount <= 0`.
    /// - [`Error::NotFound`] if `stream_id` does not exist.
    /// - [`Error::AlreadySettled`] if the stream is already `Settled`.
    /// - [`Error::InvalidState`] if the stream is not `Active` or `Paused`.
    /// - [`Error::OverWithdraw`] if `amount` exceeds the currently accrued
    ///   withdrawable balance.
    /// - [`Error::Overflow`] if the fee arithmetic overflows `i128`.
    ///
    /// # Auth
    /// Requires authorisation from the stream's `recipient`.
    pub fn withdraw_with_max_fee_bps(
        env: Env,
        stream_id: u64,
        amount: i128,
        max_fee_bps: u32,
    ) -> Result<i128, Error> {
        // ── Slippage guard ────────────────────────────────────────────────
        // Read the current protocol fee *before* any state changes so that
        // a fee update racing with this call cannot slip through.
        let current_fee_bps = storage::get_fee_bps(&env);
        if current_fee_bps > max_fee_bps {
            return Err(Error::FeeTooHigh);
        }

        // ── Standard withdraw guards ──────────────────────────────────────
        require_not_paused(&env)?;
        if amount <= 0 {
            return Err(Error::InvalidAmount);
        }

        let mut stream = get_existing_stream(&env, stream_id)?;
        stream.recipient.require_auth();

        if stream.status == StreamStatus::Settled {
            return Err(Error::AlreadySettled);
        }

        // Allow withdrawals from Active or Paused streams.
        if stream.status != StreamStatus::Active && stream.status != StreamStatus::Paused {
            return Err(Error::InvalidState);
        }

        let now = env.ledger().timestamp();
        let available = release::withdrawable(&stream, now)?;
        if amount > available {
            return Err(Error::OverWithdraw);
        }

        // ── Overflow-safe fee calculation ─────────────────────────────────
        //
        // fee_amount = amount * current_fee_bps / 10_000
        //
        // We use checked_mul to guard against overflow on very large `amount`
        // values. The cast `current_fee_bps as i128` is safe because u32::MAX
        // (≈ 4.3 × 10⁹) is well within the positive range of i128.
        //
        // Division by 10_000 cannot overflow (divisor > 0) and cannot panic
        // in checked_div because the divisor is the non-zero constant 10_000.
        let fee_amount: i128 = if current_fee_bps == 0 {
            0
        } else {
            amount
                .checked_mul(i128::from(current_fee_bps))
                .ok_or(Error::Overflow)?
                .checked_div(10_000)
                .ok_or(Error::Overflow)?
        };

        // recipient_amount is always ≤ amount because fee_amount ≥ 0.
        // The subtraction is safe and cannot underflow.
        let recipient_amount = amount.checked_sub(fee_amount).ok_or(Error::Overflow)?;

        // ── State update ──────────────────────────────────────────────────
        stream.released_amount = stream
            .released_amount
            .checked_add(amount)
            .ok_or(Error::Overflow)?;
        stream.last_update = now;

        if stream.released_amount == stream.total_amount {
            stream.status = StreamStatus::Settled;
            limits::decrement_sender_stream_count(&env, &stream.sender);
        }

        let contract = env.current_contract_address();

        // Transfer recipient's net share.
        if recipient_amount > 0 {
            #[allow(clippy::needless_borrows_for_generic_args)]
            token::Client::new(&env, &stream.token).transfer(
                &contract,
                &stream.recipient,
                &recipient_amount,
            );
        }

        // Transfer fee to admin when applicable.
        if fee_amount > 0 {
            // The admin is guaranteed to exist at this point (require_auth on
            // every state-changing entrypoint ensures the contract is
            // initialised). We propagate NotFound in the unlikely case that
            // storage is in an inconsistent state.
            let admin = storage::get_admin(&env).ok_or(Error::NotFound)?;
            #[allow(clippy::needless_borrows_for_generic_args)]
            token::Client::new(&env, &stream.token).transfer(&contract, &admin, &fee_amount);
        }

        storage::set_stream(&env, stream_id, &stream);
        let ts = stream.last_update;
        events::withdrawn(&env, stream_id, &stream.recipient, amount, ts);
        if stream.status == StreamStatus::Settled {
            events::settled(&env, stream_id, &stream.recipient, stream.total_amount, ts);
        }

        Ok(amount)
    }
    /// Creates a funded stream and escrows `total_amount` from `sender`.
    ///
    /// **Token transfer**: `total_amount` is transferred from `sender` to the
    /// contract address immediately.
    ///
    /// If `draft = false` the stream is `Active` immediately with
    /// `start_time = start_time_or_duration` interpreted as `start_time` and
    /// `end_time_or_draft_flag` interpreted as `end_time`.
    ///
    /// If `draft = true` the stream is `Draft`; the second numeric argument is
    /// treated as `duration`. `start_time`, `end_time`, and `last_update` are
    /// all zero until `start_stream` is called.
    ///
    /// Returns the new stream's numeric ID.
    ///
    /// # Errors
    /// - [`Error::ContractPaused`] if the global pause flag is set.
    /// - [`Error::InvalidAmount`] if `total_amount <= 0`.
    /// - [`Error::SelfStream`] if `sender == recipient`.
    /// - [`Error::TokenNotAllowed`] if the token has been blocked by the admin.
    /// - [`Error::InvalidTimeRange`] if `end_time <= start_time` or `start_time < now` (active only).
    ///
    /// # Auth
    /// Requires authorisation from `sender`.
    pub fn create_stream(
        env: Env,
        sender: Address,
        recipient: Address,
        token: Address,
        total_amount: i128,
        start_time: u64,
        end_time: u64,
        fee_bps: u32,
    ) -> Result<u64, Error> {
        require_not_paused(&env)?;
        sender.require_auth();
        limits::check_sender_limit(&env, &sender)?;

        // Validate fee_bps before any side effects.
        fees::validate_fee_bps(fee_bps)?;

        if total_amount <= 0 {
            return Err(Error::InvalidAmount);
        }

        if sender == recipient {
            return Err(Error::SelfStream);
        }

        if storage::is_token_blocked(&env, &token) {
            return Err(Error::TokenNotAllowed);
        }

        // Trustline pre-check: ensure the recipient can actually hold the token
        // before we lock funds in escrow. A recipient that cannot receive the
        // asset would otherwise leave funds stranded in the contract until the
        // stream is cancelled.
        require_recipient_trustline(&env, &token, &recipient)?;

        if end_time <= start_time {
            return Err(Error::InvalidTimeRange);
        }

        let now = env.ledger().timestamp();
        if start_time < now {
            return Err(Error::InvalidTimeRange);
        }

        let duration = end_time
            .checked_sub(start_time)
            .ok_or(Error::InvalidTimeRange)?;
        let id = storage::next_stream_id(&env);
        let contract_address = env.current_contract_address();

        token::Client::new(&env, &token).transfer(&sender, &contract_address, &total_amount);

        let stream = Stream {
            id,
            sender,
            recipient,
            token,
            total_amount,
            released_amount: 0,
            start_time,
            end_time,
            duration,
            last_update: start_time,
            status: StreamStatus::Active,
            paused_at: 0,
            total_paused_duration: 0,
        };

        storage::set_stream(&env, id, &stream);
        events::created(
            &env,
            id,
            &stream.sender,
            &stream.recipient,
            &stream.token,
            stream.total_amount,
            now,
        );

        Ok(id)
    }

    /// Creates a funded draft stream, escrowing `total_amount` from `sender`.
    ///
    /// The stream starts in `Draft` status; `start_time`, `end_time`, and
    /// `last_update` are zero until [`start_stream`] is called, at which point
    /// the stream becomes `Active` with `end_time = now + duration`.
    ///
    /// **Token transfer**: `total_amount` is transferred from `sender` to the
    /// contract address immediately.
    ///
    /// Returns the new stream's numeric ID.
    ///
    /// # Errors
    /// - [`Error::ContractPaused`] if the global pause flag is set.
    /// - [`Error::InvalidAmount`] if `total_amount <= 0`.
    /// - [`Error::InvalidState`] if `sender == recipient`.
    /// - [`Error::TokenNotAllowed`] if the token has been blocked by the admin.
    /// - [`Error::InvalidTimeRange`] if `duration == 0`.
    ///
    /// # Auth
    /// Requires authorisation from `sender`.
    pub fn create_draft_stream(
        env: Env,
        sender: Address,
        recipient: Address,
        token: Address,
        total_amount: i128,
        duration: u64,
    ) -> Result<u64, Error> {
        require_not_paused(&env)?;
        sender.require_auth();

        if total_amount <= 0 {
            return Err(Error::InvalidAmount);
        }

        if sender == recipient {
            return Err(Error::InvalidState);
        }

        if storage::is_token_blocked(&env, &token) {
            return Err(Error::TokenNotAllowed);
        }

        if duration == 0 {
            return Err(Error::InvalidTimeRange);
        }

        let now = env.ledger().timestamp();
        let id = storage::next_stream_id(&env);
        let contract_address = env.current_contract_address();

        token::Client::new(&env, &token).transfer(&sender, &contract_address, &total_amount);

        let stream = Stream {
            id,
            sender,
            recipient,
            token,
            total_amount,
            released_amount: 0,
            start_time: 0,
            end_time: 0,
            duration,
            last_update: 0,
            status: StreamStatus::Draft,
            paused_at: 0,
            total_paused_duration: 0,
            fee_bps,
        };

        storage::set_stream(&env, id, &stream);
        // Persist the per-stream fee_bps so it can be retrieved independently
        // from the stream row for read-only callers.
        fees::set_stream_fee_bps(&env, id, fee_bps);
        limits::increment_sender_stream_count(&env, &stream.sender);
        events::created(
            &env,
            id,
            &stream.sender,
            &stream.recipient,
            &stream.token,
            stream.total_amount,
            now,
        );

        Ok(id)
    }

    /// Activates a `Draft` stream, anchoring its time bounds to the current
    /// ledger timestamp.
    ///
    /// Sets `status = Active`, `start_time = now`, `last_update = now`, and
    /// `end_time = now + duration`. No token transfer occurs.
    ///
    /// # Parameters
    /// - `stream_id` — Numeric ID of the stream to activate.
    ///
    /// # Returns
    /// The updated [`Stream`] record after activation.
    ///
    /// # Errors
    /// - [`Error::ContractPaused`] if the global pause flag is set.
    /// - [`Error::NotFound`] if `stream_id` does not exist.
    /// - [`Error::InvalidState`] if the stream is not in `Draft` status.
    /// - [`Error::InvalidTimeRange`] if `now + duration` overflows `u64`.
    ///
    /// # Auth
    /// Requires authorisation from the stream's `sender`.
    pub fn start_stream(env: Env, stream_id: u64) -> Result<Stream, Error> {
        require_not_paused(&env)?;
        let mut stream = get_existing_stream(&env, stream_id)?;
        stream.sender.require_auth();

        if stream.status != StreamStatus::Draft {
            return Err(Error::InvalidState);
        }

        let now = env.ledger().timestamp();
        stream.status = StreamStatus::Active;
        stream.start_time = now;
        stream.last_update = now;
        stream.end_time = now
            .checked_add(stream.duration)
            .ok_or(Error::InvalidTimeRange)?;

        storage::set_stream(&env, stream_id, &stream);
        events::started(
            &env,
            stream_id,
            stream.start_time,
            stream.end_time,
            stream.start_time,
        );

        Ok(stream)
    }

    /// Returns the stored stream record for `stream_id`.
    ///
    /// This is a read-only call and is never blocked by the pause flag.
    ///
    /// # Parameters
    /// - `stream_id` — Numeric ID of the stream to look up.
    ///
    /// # Returns
    /// The [`Stream`] record stored on-chain.
    ///
    /// # Errors
    /// - [`Error::NotFound`] if `stream_id` does not exist.
    pub fn get_stream(env: Env, stream_id: u64) -> Result<Stream, Error> {
        get_existing_stream(&env, stream_id)
    }

    /// Returns the token amount currently accrued and available for withdrawal.
    ///
    /// This is a read-only view that computes `vested_amount - released_amount`
    /// using overflow-safe linear accrual. It never mutates state or requires
    /// auth, and is unaffected by the global pause flag.
    ///
    /// # Parameters
    /// - `stream_id` — Numeric ID of the stream to query.
    ///
    /// # Returns
    /// The currently withdrawable token amount (base units). Always non-negative.
    ///
    /// # Errors
    /// - [`Error::NotFound`] if `stream_id` does not exist.
    /// - [`Error::Overflow`] if the vested-amount computation overflows.
    pub fn withdrawable(env: Env, stream_id: u64) -> Result<i128, Error> {
        let stream = get_existing_stream(&env, stream_id)?;
        Ok(release::withdrawable(&stream, env.ledger().timestamp()))
    }

    /// Returns the stream balance (total vested amount) at the current ledger
    /// timestamp using overflow-safe linear accrual.
    ///
    /// This is a read-only view that never mutates state or requires auth.
    /// It is unaffected by the global pause flag.
    ///
    /// # Parameters
    /// - `stream_id` — Numeric ID of the stream to query.
    ///
    /// # Returns
    /// The total vested token amount (base units). Always in `[0, total_amount]`.
    ///
    /// # Errors
    /// - [`Error::NotFound`] if `stream_id` does not exist.
    /// - [`Error::Overflow`] if the vested-amount computation overflows.
    pub fn stream_balance(env: Env, stream_id: u64) -> Result<i128, Error> {
        let stream = get_existing_stream(&env, stream_id)?;
        Ok(release::vested_amount(&stream, env.ledger().timestamp()))
    }

    /// Captures a point-in-time [`StreamSnapshot`] for `stream_id` at `at_timestamp`.
    ///
    /// Evaluates the linear-accrual math at the supplied timestamp, returning
    /// vested, released, locked, and withdrawable amounts alongside the stream
    /// status at that moment.
    ///
    /// This is a **read-only** entrypoint: it never mutates state and requires
    /// no authorisation. It is unaffected by the global pause flag.
    ///
    /// # Parameters
    /// - `stream_id`    — Numeric ID of the stream to snapshot.
    /// - `at_timestamp` — Ledger timestamp at which to evaluate accrual.
    ///
    /// # Returns
    /// A [`StreamSnapshot`] containing all financial fields at `at_timestamp`.
    ///
    /// # Errors
    /// - [`Error::NotFound`] if `stream_id` does not exist.
    /// - [`Error::Overflow`] if any arithmetic step overflows `i128`.
    pub fn stream_snapshot(
        env: Env,
        stream_id: u64,
        at_timestamp: u64,
    ) -> Result<StreamSnapshot, Error> {
        snapshot_diff::stream_snapshot(&env, stream_id, at_timestamp)
    }

    /// Computes the delta between two [`StreamSnapshot`]s produced by
    /// [`Contract::stream_snapshot`].
    ///
    /// Both snapshots must reference the same `stream_id`. All `delta_*` fields
    /// express **`after − before`**: positive values mean growth, negative values
    /// mean a decrease (e.g. a large withdrawal yields a negative `delta_locked`).
    ///
    /// Passing the snapshots in reverse chronological order is allowed; the
    /// `elapsed_seconds` field is always the absolute difference between the two
    /// timestamps.
    ///
    /// This is a **read-only** entrypoint: it never mutates state and requires
    /// no authorisation. It is unaffected by the global pause flag.
    ///
    /// # Parameters
    /// - `before` — Snapshot at the earlier point in time.
    /// - `after`  — Snapshot at the later point in time.
    ///
    /// # Returns
    /// A [`SnapshotDiff`] with field-by-field deltas and elapsed time.
    ///
    /// # Errors
    /// - [`Error::NotFound`] if the two snapshots reference different stream IDs.
    /// - [`Error::Overflow`] if any arithmetic step overflows.
    pub fn diff_snapshots(
        env: Env,
        before: StreamSnapshot,
        after: StreamSnapshot,
    ) -> Result<SnapshotDiff, Error> {
        snapshot_diff::diff_snapshots(&env, &before, &after)
    }

    /// Withdraws accrued escrow on behalf of `caller`.
    ///
    /// Transfers `amount` tokens from the contract escrow to the stream
    /// recipient. The caller must be the stream recipient or an allowlisted
    /// withdrawer (see [`Contract::add_withdrawer`]).
    ///
    /// If the stream has a per-stream `fee_bps` and a fee collector has been
    /// configured, the fee is deducted before the transfer.
    ///
    /// # Parameters
    /// - `caller`    — Address initiating the withdrawal (must be recipient or
    ///   allowlisted withdrawer).
    /// - `stream_id` — Numeric ID of the stream to withdraw from.
    /// - `amount`    — Token amount (base units) to withdraw. Must be > 0 and
    ///   ≤ the currently accrued withdrawable balance.
    ///
    /// # Returns
    /// The `amount` that was withdrawn on success.
    ///
    /// # Errors
    /// - [`Error::ContractPaused`] if the global pause flag is set.
    /// - [`Error::InvalidAmount`] if `amount <= 0`.
    /// - [`Error::NotFound`] if `stream_id` does not exist.
    /// - [`Error::Unauthorized`] if `caller` is not the recipient or an
    ///   allowlisted withdrawer.
    /// - [`Error::AlreadySettled`] if the stream is already fully settled.
    /// - [`Error::InvalidState`] if the stream is not Active or Paused.
    /// - [`Error::OverWithdraw`] if `amount` exceeds accrued funds.
    ///
    /// # Auth
    /// Requires authorisation from `caller`.
    pub fn withdraw(env: Env, caller: Address, stream_id: u64, amount: i128) -> Result<i128, Error> {
        require_not_paused(&env)?;
        if amount <= 0 {
            return Err(Error::InvalidAmount);
        }

        let mut stream = get_existing_stream(&env, stream_id)?;

        // Enforce allowlist authorization: caller must be recipient or allowlisted.
        withdrawer::require_withdraw_auth(&env, stream_id, &caller, &stream.recipient)?;

        if stream.status == StreamStatus::Settled {
            return Err(Error::AlreadySettled);
        }

        // Allow withdrawals from Active or Paused streams
        if stream.status != StreamStatus::Active && stream.status != StreamStatus::Paused {
            return Err(Error::InvalidState);
        }

        let now = env.ledger().timestamp();
        let available = release::withdrawable(&stream, now);
        if amount > available {
            return Err(Error::OverWithdraw);
        }

        stream.released_amount = stream
            .released_amount
            .checked_add(amount)
            .ok_or(Error::InvalidAmount)?;
        stream.last_update = now;

        if stream.released_amount == stream.total_amount {
            stream.status = StreamStatus::Settled;
            limits::decrement_sender_stream_count(&env, &stream.sender);
        }

        // ── Fee split ──────────────────────────────────────────────────────────
        // Compute fee and net amount based on the per-stream fee_bps.  If no
        // fee collector has been configured the full `amount` goes to the
        // recipient regardless of `fee_bps`.
        let fee_result = fees::apply_fee(amount, stream.fee_bps)?;
        let maybe_collector = fees::get_fee_collector(&env);

        // Transfer to recipient (net amount after fee).
        #[allow(clippy::needless_borrows_for_generic_args)]
        token::Client::new(&env, &stream.token).transfer(
            &env.current_contract_address(),
            &stream.recipient,
            &fee_result.net_amount,
        );

        // Transfer fee to the collector if one is configured and fee > 0.
        if fee_result.fee_amount > 0 {
            if let Some(collector) = maybe_collector.clone() {
                #[allow(clippy::needless_borrows_for_generic_args)]
                token::Client::new(&env, &stream.token).transfer(
                    &env.current_contract_address(),
                    &collector,
                    &fee_result.fee_amount,
                );
                events::fee_charged(
                    &env,
                    stream_id,
                    fee_result.fee_amount,
                    stream.fee_bps,
                    &collector,
                    now,
                );
            } else {
                // No collector configured: forward fee to recipient as well so
                // no funds are stranded in the contract.
                #[allow(clippy::needless_borrows_for_generic_args)]
                token::Client::new(&env, &stream.token).transfer(
                    &env.current_contract_address(),
                    &stream.recipient,
                    &fee_result.fee_amount,
                );
            }
        }

        storage::set_stream(&env, stream_id, &stream);
        let ts = stream.last_update;
        events::withdrawn(&env, stream_id, &stream.recipient, amount, ts);
        if stream.status == StreamStatus::Settled {
            events::settled(&env, stream_id, &stream.recipient, stream.total_amount, ts);
        }

        Ok(amount)
    }

    /// Adds `withdrawer` to the per-stream allowlist, granting them the right
    /// to call [`withdraw`] on behalf of the recipient.
    ///
    /// Only the stream sender may manage the allowlist. Adding an address that
    /// is already present is a no-op (idempotent).
    ///
    /// # Errors
    /// - [`Error::NotFound`] if `stream_id` does not exist.
    /// - [`Error::Unauthorized`] if the caller is not the stream sender.
    ///
    /// # Auth
    /// Requires authorisation from the stream's `sender`.
    pub fn add_withdrawer(
        env: Env,
        stream_id: u64,
        withdrawer: Address,
    ) -> Result<(), Error> {
        let stream = get_existing_stream(&env, stream_id)?;
        stream.sender.require_auth();
        storage::add_withdrawer(&env, stream_id, &withdrawer);
        Ok(())
    }

    /// Removes `withdrawer` from the per-stream allowlist.
    ///
    /// Only the stream sender may manage the allowlist. Removing an address
    /// that is not in the allowlist is a no-op (idempotent).
    ///
    /// # Errors
    /// - [`Error::NotFound`] if `stream_id` does not exist.
    /// - [`Error::Unauthorized`] if the caller is not the stream sender.
    ///
    /// # Auth
    /// Requires authorisation from the stream's `sender`.
    pub fn remove_withdrawer(
        env: Env,
        stream_id: u64,
        withdrawer: Address,
    ) -> Result<(), Error> {
        let stream = get_existing_stream(&env, stream_id)?;
        stream.sender.require_auth();
        storage::remove_withdrawer(&env, stream_id, &withdrawer);
        Ok(())
    }

    /// Returns the current withdrawer allowlist for a stream.
    ///
    /// Returns an empty list if no allowlist has been set.
    ///
    /// # Errors
    /// - [`Error::NotFound`] if `stream_id` does not exist.
    pub fn get_withdrawer_allowlist(
        env: Env,
        stream_id: u64,
    ) -> Result<soroban_sdk::Vec<Address>, Error> {
        // Verify the stream exists before returning the allowlist.
        get_existing_stream(&env, stream_id)?;
        Ok(storage::get_withdrawer_allowlist(&env, stream_id))
    }

    /// Pauses an active stream, freezing accrual while preserving vested funds.
    ///
    /// Only the stream sender may call this. On pause, status is set to Paused
    /// and `paused_at` is recorded. Vested amount remains withdrawable but does
    /// not increase while paused.
    ///
    /// # Errors
    /// - [`Error::NotFound`] if `stream_id` does not exist.
    /// - [`Error::Unauthorized`] if caller is not the stream sender.
    /// - [`Error::InvalidState`] if the stream is not `Active`.
    ///
    /// # Auth
    /// Requires authorisation from the stream's `sender`.
    pub fn pause(env: Env, stream_id: u64) -> Result<Stream, Error> {
        let mut stream = get_existing_stream(&env, stream_id)?;
        stream.sender.require_auth();

        if stream.status != StreamStatus::Active {
            return Err(Error::InvalidState);
        }

        let now = env.ledger().timestamp();
        stream.paused_at = now;
        stream.last_update = now;
        stream.status = StreamStatus::Paused;

        storage::set_stream(&env, stream_id, &stream);

        events::paused(&env, stream_id, &stream.sender, stream.paused_at, now);

        Ok(stream)
    }

    /// Resumes a previously paused stream, extending `end_time` to preserve
    /// unstreamed time.
    ///
    /// Only the stream sender may call this. On resume, the `end_time` is extended
    /// by the paused duration so the remaining streamable amount is preserved.
    /// Status is set back to Active.
    ///
    /// # Errors
    /// - [`Error::NotFound`] if `stream_id` does not exist.
    /// - [`Error::Unauthorized`] if caller is not the stream sender.
    /// - [`Error::InvalidState`] if the stream is not `Paused`.
    /// - [`Error::InvalidTimeRange`] if time calculation overflows.
    ///
    /// # Auth
    /// Requires authorisation from the stream's `sender`.
    pub fn resume(env: Env, stream_id: u64) -> Result<Stream, Error> {
        let mut stream = get_existing_stream(&env, stream_id)?;
        stream.sender.require_auth();

        if stream.status != StreamStatus::Paused {
            return Err(Error::InvalidState);
        }

        let now = env.ledger().timestamp();
        let paused_duration = now
            .checked_sub(stream.paused_at)
            .ok_or(Error::InvalidTimeRange)?;

        // Track total paused duration for accrual calculations
        stream.total_paused_duration = stream
            .total_paused_duration
            .checked_add(paused_duration)
            .ok_or(Error::InvalidTimeRange)?;

        // Extend end_time by the paused duration to preserve unstreamed time
        stream.end_time = stream
            .end_time
            .checked_add(paused_duration)
            .ok_or(Error::InvalidTimeRange)?;

        stream.last_update = now;
        stream.status = StreamStatus::Active;
        stream.paused_at = 0;

        storage::set_stream(&env, stream_id, &stream);

        events::resumed(&env, stream_id, &stream.sender, stream.end_time, now);

        Ok(stream)
    }

    /// Finalizes a stream whose time window has fully elapsed, paying out
    /// any remaining vested funds to the recipient and transitioning it to a
    /// terminal `Settled` state.
    ///
    /// This function is permissionless and can be triggered by anyone after
    /// `end_time` has been reached. Calling it on an already `Settled` stream
    /// is a no-op (returns `Ok(())`).
    ///
    /// # Errors
    /// - [`Error::ContractPaused`] if the contract is paused.
    /// - [`Error::NotFound`] if `stream_id` does not exist.
    /// - [`Error::InvalidState`] if the stream is in `Draft` or cancelled state,
    ///   or if the current ledger timestamp has not yet reached `end_time`.
    pub fn settle(env: Env, stream_id: u64) -> Result<(), Error> {
        require_not_paused(&env)?;
        let mut stream = get_existing_stream(&env, stream_id)?;

        if stream.status == StreamStatus::Settled {
            return Ok(());
        }

        if stream.status != StreamStatus::Active && stream.status != StreamStatus::Paused {
            return Err(Error::InvalidState);
        }

        let now = env.ledger().timestamp();
        if now < stream.end_time {
            return Err(Error::InvalidState);
        }

        let payout_amount = stream
            .total_amount
            .checked_sub(stream.released_amount)
            .ok_or(Error::Overflow)?;
        if payout_amount > 0 {
            #[allow(clippy::needless_borrows_for_generic_args)]
            token::Client::new(&env, &stream.token).transfer(
                &env.current_contract_address(),
                &stream.recipient,
                &payout_amount,
            );
            stream.released_amount = stream.total_amount;
        }

        stream.status = StreamStatus::Settled;
        stream.last_update = now;

        limits::decrement_sender_stream_count(&env, &stream.sender);
        storage::set_stream(&env, stream_id, &stream);
        events::settled(&env, stream_id, &stream.recipient, stream.released_amount, now);

        Ok(())
    }

    /// Cancels an active, paused, or draft stream, returning unvested funds to
    /// the sender and paying accrued-but-unreleased funds to the recipient.
    ///
    /// At the moment of cancellation the stream's vested amount is computed. Funds
    /// are split as follows:
    ///
    /// - **Recipient** receives `vested_amount - released_amount` (accrued but
    ///   not yet withdrawn).
    /// - **Sender** receives `total_amount - vested_amount` (unvested / unstreamed).
    ///
    /// For draft streams, `vested_amount = 0` so the full escrow returns to the sender.
    /// This preserves the invariant that the recipient is entitled to everything
    /// that has already vested, regardless of whether they have withdrawn it yet.
    ///
    /// The stream transitions to [`StreamStatus::Cancelled`] (terminal state).
    ///
    /// # Parameters
    /// - `stream_id` — Numeric ID of the stream to cancel.
    ///
    /// # Returns
    /// The updated [`Stream`] record after cancellation.
    ///
    /// # Errors
    /// - [`Error::NotFound`] if `stream_id` does not exist.
    /// - [`Error::InvalidState`] if the stream is already `Settled` or `Cancelled`.
    /// - [`Error::Overflow`] if any amount arithmetic overflows.
    ///
    /// # Auth
    /// Requires authorisation from the stream's `sender`.
    pub fn cancel_stream(env: Env, stream_id: u64) -> Result<Stream, Error> {
        let mut stream = get_existing_stream(&env, stream_id)?;
        stream.sender.require_auth();

        if stream.status == StreamStatus::Settled || stream.status == StreamStatus::Cancelled {
            return Err(Error::InvalidState);
        }

        let now = env.ledger().timestamp();
        let contract = env.current_contract_address();
        let token = token::Client::new(&env, &stream.token);

        // Compute vested amount at cancellation time (handles Active, Paused, Draft).
        // For Draft streams, vested = 0 so the full amount returns to sender.
        let vested = release::vested_amount(&stream, now)?;

        // Recipient is owed vested - already_released (may be 0).
        let recipient_payout = vested
            .checked_sub(stream.released_amount)
            .ok_or(Error::Overflow)?;

        // Sender reclaims everything that has not yet vested.
        let sender_refund = stream
            .total_amount
            .checked_sub(vested)
            .ok_or(Error::Overflow)?;

        if recipient_payout > 0 {
            #[allow(clippy::needless_borrows_for_generic_args)]
            token.transfer(&contract, &stream.recipient, &recipient_payout);
            stream.released_amount = vested;
        }

        if sender_refund > 0 {
            #[allow(clippy::needless_borrows_for_generic_args)]
            token.transfer(&contract, &stream.sender, &sender_refund);
        }

        stream.status = StreamStatus::Cancelled;
        stream.last_update = now;

        limits::decrement_sender_stream_count(&env, &stream.sender);
        storage::set_stream(&env, stream_id, &stream);

        events::cancelled(
            &env,
            stream_id,
            &stream.sender,
            sender_refund,
            recipient_payout,
            now,
        );

        Ok(stream)
    }

    /// Amends an active or paused stream to change its rate (via a new
    /// end-time) with overflow-safe, rate-aware validation.
    ///
    /// Only the stream sender may call this. The amendment moves the stream's
    /// `end_time`, which implicitly re-rates the remaining accrual. The
    /// following invariants are enforced so an amendment can never strand or
    /// claw back funds the recipient has already earned:
    ///
    /// 1. `new_rate_per_second` must be **positive** — a zero or negative rate
    ///    would never finish vesting the escrow.
    /// 2. `new_end_time` must be strictly **after `now`** and strictly after
    ///    `start_time`, so the resulting duration is non-zero.
    /// 3. The new schedule must still leave the **already-released amount**
    ///    within what will eventually vest (i.e. the recipient never ends up
    ///    "owing" funds). Because the full `total_amount` always vests by
    ///    `end_time`, this reduces to ensuring `total_amount >= released_amount`,
    ///    which is checked with overflow-safe arithmetic.
    /// 4. The implied rate is sanity-checked: streaming `total_amount` over the
    ///    new duration must not overflow `i128` (`total_amount * 1` headroom).
    ///
    /// # Errors
    /// - [`Error::NotFound`] if `stream_id` does not exist.
    /// - [`Error::Unauthorized`] if caller is not the stream sender.
    /// - [`Error::InvalidState`] if the stream is settled or cancelled.
    /// - [`Error::InvalidAmount`] if `new_rate_per_second <= 0`.
    /// - [`Error::InvalidTimeRange`] if `new_end_time <= now`,
    ///   `new_end_time <= start_time`, or the new duration computation overflows.
    /// - [`Error::Overflow`] if the re-rated accrual math would overflow `i128`.
    ///
    /// # Auth
    /// Requires authorisation from the stream's `sender`.
    pub fn amend_stream(
        env: Env,
        stream_id: u64,
        new_rate_per_second: i128,
        new_end_time: u64,
    ) -> Result<Stream, Error> {
        require_not_paused(&env)?;
        let mut stream = get_existing_stream(&env, stream_id)?;
        stream.sender.require_auth();

        if stream.status == StreamStatus::Settled || stream.status == StreamStatus::Cancelled {
            return Err(Error::InvalidState);
        }

        // (1) Rate-change validation: the new rate must be strictly positive.
        if new_rate_per_second <= 0 {
            return Err(Error::InvalidAmount);
        }

        let now = env.ledger().timestamp();

        // (2) The amended window must be in the future and non-degenerate.
        if new_end_time <= now || new_end_time <= stream.start_time {
            return Err(Error::InvalidTimeRange);
        }

        let new_duration = new_end_time
            .checked_sub(stream.start_time)
            .ok_or(Error::InvalidTimeRange)?;

        // (3) Already-released funds must remain within the eventual vest.
        if stream.released_amount > stream.total_amount {
            return Err(Error::Overflow);
        }

        // (4) Overflow-safe sanity check of the re-rated accrual. The vested
        //     formula is `total_amount * elapsed / new_duration`; the largest
        //     intermediate product uses `elapsed = new_duration`, so we verify
        //     `total_amount * new_duration` does not overflow `i128`.
        stream
            .total_amount
            .checked_mul(new_duration as i128)
            .ok_or(Error::Overflow)?;

        // Update stream parameters.
        stream.end_time = new_end_time;
        stream.duration = new_duration;
        stream.last_update = now;

        storage::set_stream(&env, stream_id, &stream);

        events::amended(
            &env,
            stream_id,
            &stream.sender,
            new_rate_per_second,
            new_end_time,
            now,
        );

        Ok(stream)
    }

    /// Returns the unsettled accrual (vested minus released) for `stream_id`.
    ///
    /// This is a convenience alias for [`Contract::withdrawable`]. It computes
    /// the amount currently accrued and available for withdrawal using
    /// overflow-safe linear accrual.
    ///
    /// This is a read-only view that never mutates state or requires auth.
    /// It is unaffected by the global pause flag.
    ///
    /// # Parameters
    /// - `stream_id` — Numeric ID of the stream to query.
    ///
    /// # Returns
    /// The unsettled accrual amount (vested minus released). Always non-negative.
    ///
    /// # Errors
    /// - [`Error::NotFound`] if `stream_id` does not exist.
    /// - [`Error::Overflow`] if the vested-amount computation overflows.
    pub fn claim_drip(env: Env, stream_id: u64) -> Result<i128, Error> {
        let stream = get_existing_stream(&env, stream_id)?;
        release::withdrawable(&stream, env.ledger().timestamp())
    }

    /// Upgrades the contract to a new WASM binary.
    ///
    /// Replaces the running contract code with `new_wasm_hash`. The contract's
    /// storage (streams, admin, allowlist) is preserved across the upgrade.
    /// Only the contract admin may call this.
    ///
    /// # Parameters
    /// - `admin`         — Must match the admin set at initialisation.
    /// - `new_wasm_hash` — The WASM hash of the new contract code, obtained
    ///   via [`Env::deployer`]`::upload_contract_wasm`.
    ///
    /// # Errors
    /// - [`Error::Unauthorized`] if `admin` is not the initialised admin.
    /// - [`Error::NotFound`] if the contract has not been initialised.
    ///
    /// # Auth
    /// Requires authorisation from `admin`.
    pub fn upgrade(env: Env, admin: Address, new_wasm_hash: BytesN<32>) -> Result<(), Error> {
        require_admin(&env, &admin)?;
        env.deployer()
            .update_current_contract_wasm(new_wasm_hash.clone());
        events::upgraded(&env, new_wasm_hash);
        Ok(())
    }

    // ── Versioned migration ────────────────────────────────────────────────────

    /// Migrates the contract's persistent storage to the latest schema
    /// version.
    ///
    /// This entrypoint runs all pending migration steps sequentially to
    /// bring the contract's storage layout up to [`migrate::LATEST_VERSION`].
    /// If the contract is already at the latest version, the call is a
    /// no-op (returns `Ok(())`).
    ///
    /// Migrations are **one-way** and **irreversible** by design: once a
    /// contract has been migrated to version N, there is no supported path
    /// back to version N−1.
    ///
    /// # Parameters
    /// - `admin` — Must match the admin set at initialisation.
    ///
    /// # Errors
    /// - [`Error::Unauthorized`] if `admin` is not the initialised admin.
    /// - [`Error::NotFound`] if the contract has not been initialised.
    /// - Any error returned by an individual migration step. When a step
    ///   returns `Err`, the entire transaction is rolled back by the
    ///   Soroban host — no partial migration is committed.
    ///
    /// # Auth
    /// Requires authorisation from `admin`.
    ///
    /// # Pause semantics
    /// The global pause flag does **not** block migration; an admin should
    /// be able to migrate a paused contract.
    pub fn migrate(env: Env, admin: Address) -> Result<(), Error> {
        migrate::migrate_internal(&env, &admin)
    }

    /// Returns the current storage version of the contract.
    ///
    /// Returns `0` if no version has been recorded (pre-migration contract).
    ///
    /// This is a read-only view that never mutates state or requires auth.
    /// It is unaffected by the global pause flag.
    ///
    /// # Returns
    /// The current storage schema version (`u32`).
    ///
    /// # Errors
    /// This entrypoint is read-only and never returns an error.
    pub fn storage_version(env: Env) -> u32 {
        migrate::current_version(&env)
    }

    // ── Admin nonce ───────────────────────────────────────────────────────────

    /// Returns the current (next-expected) admin nonce.
    ///
    /// Call this before crafting an [`Contract::admin_override`] transaction to
    /// learn which nonce value to supply. The returned value is the nonce that
    /// **must** be provided in the very next `admin_override` call; any other
    /// value will be rejected.
    ///
    /// This is a read-only call; it never mutates state or requires auth.
    ///
    /// # Returns
    /// The current admin nonce. Starts at `0` and increments by 1 on each
    /// successful [`Contract::admin_override`] call.
    ///
    /// # Errors
    /// This entrypoint is read-only and never returns an error.
    pub fn get_admin_nonce(env: Env) -> u64 {
        admin::get_nonce(&env)
    }

    /// Performs a privileged admin override of a stream's `end_time`, protected
    /// by a monotonic nonce to prevent replay attacks.
    ///
    /// The admin must supply the **current** nonce (obtainable via
    /// [`Contract::get_admin_nonce`]) as `nonce`. After a successful call the
    /// stored nonce is incremented so the same `nonce` value cannot be reused.
    ///
    /// # Parameters
    /// - `admin`        — Must be the initialised contract admin.
    /// - `nonce`        — Current monotonic nonce; consumed on success.
    /// - `stream_id`    — ID of the stream to override.
    /// - `new_end_time` — Replacement `end_time` for the stream.
    ///
    /// # Returns
    /// The updated [`Stream`] after applying the override.
    ///
    /// # Errors
    /// - [`Error::NotFound`] if the contract is not initialised or `stream_id`
    ///   does not exist.
    /// - [`Error::Unauthorized`] if `admin` is not the stored admin.
    /// - [`Error::NonceTooLow`] if `nonce` has already been consumed (replay
    ///   attempt or stale nonce).
    /// - [`Error::NonceOutOfOrder`] if `nonce` skips ahead of the stored counter.
    /// - [`Error::InvalidTimeRange`] if `new_end_time <= stream.start_time`.
    /// - [`Error::InvalidState`] if the stream is in a terminal state.
    ///
    /// # Auth
    /// Requires authorisation from `admin`.
    ///
    /// # Security
    /// The nonce provides a long-lived, cross-ledger replay fence on top of
    /// Soroban's native per-ledger authorisation mechanism.
    pub fn admin_override(
        env: Env,
        admin: Address,
        nonce: u64,
        stream_id: u64,
        new_end_time: u64,
    ) -> Result<Stream, Error> {
        admin::admin_override(&env, &admin, nonce, stream_id, new_end_time)
    }

    // ──────────────────────────────────────────────────────────────────────
    // Read-only paginated enumeration views
    // ──────────────────────────────────────────────────────────────────────

    /// Returns a paginated list of all streams, ordered by ascending stream ID.
    ///
    /// This is a read-only view that never mutates state or requires auth.
    /// The global pause flag does not affect this call.
    ///
    /// # Parameters
    ///
    /// - `start_after` — Exclusive cursor: return streams with `id > start_after`.
    ///   Pass `None` to start from the beginning (stream ID 1).
    /// - `limit` — Maximum number of streams to return. Capped at [`MAX_PAGE_SIZE`].
    ///
    /// # Returns
    ///
    /// A [`StreamPage`] with up to `limit` streams. If `next_cursor` is `Some(id)`,
    /// there are more streams; pass `id` as `start_after` to the next call.
    pub fn list_streams(env: Env, start_after: Option<u64>, limit: u64) -> views::StreamPage {
        views::list_streams(&env, start_after, limit)
    }

    /// Returns a paginated list of streams sent by a given address.
    ///
    /// This is a read-only view that never mutates state or requires auth.
    ///
    /// # Parameters
    ///
    /// - `sender` — Filter: only return streams where `stream.sender == sender`.
    /// - `start_after` — Exclusive cursor: return streams with `id > start_after`.
    /// - `limit` — Maximum number of streams to return. Capped at [`MAX_PAGE_SIZE`].
    ///
    /// # Returns
    ///
    /// A [`StreamPage`] with up to `limit` streams sent by `sender`.
    pub fn list_streams_by_sender(
        env: Env,
        sender: Address,
        start_after: Option<u64>,
        limit: u64,
    ) -> views::StreamPage {
        views::list_streams_by_sender(&env, &sender, start_after, limit)
    }

    /// Returns a paginated list of streams received by a given address.
    ///
    /// This is a read-only view that never mutates state or requires auth.
    ///
    /// # Parameters
    ///
    /// - `recipient` — Filter: only return streams where `stream.recipient == recipient`.
    /// - `start_after` — Exclusive cursor: return streams with `id > start_after`.
    /// - `limit` — Maximum number of streams to return. Capped at [`MAX_PAGE_SIZE`].
    ///
    /// # Returns
    ///
    /// A [`StreamPage`] with up to `limit` streams received by `recipient`.
    pub fn list_streams_by_recipient(
        env: Env,
        recipient: Address,
        start_after: Option<u64>,
        limit: u64,
    ) -> views::StreamPage {
        views::list_streams_by_recipient(&env, &recipient, start_after, limit)
    }

    /// Returns a paginated list of streams filtered by status.
    ///
    /// This is a read-only view that never mutates state or requires auth.
    ///
    /// # Parameters
    ///
    /// - `status` — Filter: only return streams where `stream.status == status`.
    /// - `start_after` — Exclusive cursor: return streams with `id > start_after`.
    /// - `limit` — Maximum number of streams to return. Capped at [`MAX_PAGE_SIZE`].
    ///
    /// # Returns
    ///
    /// A [`StreamPage`] with up to `limit` streams in the given status.
    pub fn list_streams_by_status(
        env: Env,
        status: StreamStatus,
        start_after: Option<u64>,
        limit: u64,
    ) -> views::StreamPage {
        views::list_streams_by_status(&env, status, start_after, limit)
    }

    /// Returns a paginated list of streams filtered by recipient and status.
    ///
    /// This is a read-only view commonly used by frontends to show a user's
    /// active/paused/settled streams.
    ///
    /// # Parameters
    ///
    /// - `recipient` — Filter: only return streams where `stream.recipient == recipient`.
    /// - `status` — Filter: only return streams where `stream.status == status`.
    /// - `start_after` — Exclusive cursor: return streams with `id > start_after`.
    /// - `limit` — Maximum number of streams to return. Capped at [`MAX_PAGE_SIZE`].
    ///
    /// # Returns
    ///
    /// A [`StreamPage`] with up to `limit` streams matching both filters.
    pub fn list_streams_recipient_status(
        env: Env,
        recipient: Address,
        status: StreamStatus,
        start_after: Option<u64>,
        limit: u64,
    ) -> views::StreamPage {
        views::list_streams_by_recipient_and_status(&env, &recipient, status, start_after, limit)
    }

    // ── Multi-recipient split streams ────────────────────────────────────────

    /// Creates a split stream that distributes tokens across multiple
    /// recipients proportionally by weight.
    ///
    /// The `total_amount` is transferred from `sender` to the contract
    /// immediately. Each recipient receives `total_vested * weight / total_weight`
    /// as tokens vest linearly over the stream duration.
    ///
    /// # Parameters
    /// - `sender`       — Address funding the stream.
    /// - `token`        — Stellar asset contract address.
    /// - `total_amount` — Total tokens (base units) to lock in escrow. Must be > 0.
    /// - `start_time`   — Ledger timestamp when vesting begins.
    /// - `end_time`     — Ledger timestamp when vesting ends.
    /// - `recipients`   — Recipient addresses (must match `weights` in length).
    /// - `weights`      — Proportional weights for each recipient (all > 0).
    ///
    /// # Returns
    /// The numeric ID of the newly created split stream.
    ///
    /// # Errors
    /// - [`Error::ContractPaused`] if the global pause flag is set.
    /// - [`Error::InvalidAmount`] if `total_amount <= 0`, `recipients` has < 2
    ///   entries, or lengths of `recipients` and `weights` differ.
    /// - [`Error::SelfStream`] if any recipient equals `sender`.
    /// - [`Error::TokenNotAllowed`] if the token has been blocked.
    /// - [`Error::InvalidTimeRange`] if `end_time <= start_time` or
    ///   `start_time < now`.
    ///
    /// # Auth
    /// Requires authorisation from `sender`.
    #[allow(clippy::too_many_arguments)]
    pub fn create_split_stream(
        env: Env,
        sender: Address,
        token: Address,
        total_amount: i128,
        start_time: u64,
        end_time: u64,
        recipients: soroban_sdk::Vec<Address>,
        weights: soroban_sdk::Vec<u64>,
    ) -> Result<u64, Error> {
        multi::create_split_stream(env, sender, token, total_amount, start_time, end_time, recipients, weights)
    }

    /// Withdraws accrued tokens from a split stream for a specific recipient.
    ///
    /// The recipient must be one of the stream's allocated recipients.
    /// The `amount` must not exceed the recipient's currently withdrawable
    /// balance.
    ///
    /// # Parameters
    /// - `stream_id` — Numeric ID of the split stream.
    /// - `recipient` — The recipient withdrawing (must match an allocation).
    /// - `amount`    — Token amount (base units) to withdraw. Must be > 0.
    ///
    /// # Returns
    /// The `amount` withdrawn on success.
    ///
    /// # Errors
    /// - [`Error::ContractPaused`] if the global pause flag is set.
    /// - [`Error::NotFound`] if `stream_id` does not exist.
    /// - [`Error::AlreadySettled`] if the stream is already settled.
    /// - [`Error::InvalidState`] if the stream is not `Active` or `Paused`,
    ///   or the `recipient` is not in the allocation list.
    /// - [`Error::OverWithdraw`] if `amount` exceeds the withdrawable balance.
    ///
    /// # Auth
    /// Requires authorisation from `recipient`.
    pub fn withdraw_split(
        env: Env,
        stream_id: u64,
        recipient: Address,
        amount: i128,
    ) -> Result<i128, Error> {
        multi::withdraw_split(env, stream_id, recipient, amount)
    }

    /// Cancels a split stream, distributing vested-but-unreleased amounts to
    /// each recipient and returning unvested funds to the sender.
    ///
    /// # Parameters
    /// - `stream_id` — Numeric ID of the split stream to cancel.
    ///
    /// # Returns
    /// The final [`SplitStream`] record after cancellation.
    ///
    /// # Errors
    /// - [`Error::NotFound`] if `stream_id` does not exist.
    /// - [`Error::Unauthorized`] if caller is not the stream sender.
    /// - [`Error::InvalidState`] if the stream is already settled or cancelled.
    ///
    /// # Auth
    /// Requires authorisation from the stream's `sender`.
    pub fn cancel_split_stream(env: Env, stream_id: u64) -> Result<SplitStream, Error> {
        multi::cancel_split_stream(env, stream_id)
    }

    /// Returns the stored split stream record for `stream_id`.
    ///
    /// This is a read-only view that never mutates state or requires auth.
    /// It is unaffected by the global pause flag.
    ///
    /// # Parameters
    /// - `stream_id` — Numeric ID of the split stream to look up.
    ///
    /// # Returns
    /// The [`SplitStream`] record stored on-chain, containing all recipients,
    /// their weights, and cumulative release amounts.
    ///
    /// # Errors
    /// - [`Error::NotFound`] if `stream_id` does not exist.
    pub fn get_split_stream(env: Env, stream_id: u64) -> Result<SplitStream, Error> {
        multi::get_split_stream(env, stream_id)
    }

    /// Returns the withdrawable balance for a specific recipient in a split
    /// stream.
    ///
    /// This is a read-only view that never mutates state or requires auth.
    /// It is unaffected by the global pause flag.
    ///
    /// # Parameters
    /// - `stream_id` — Numeric ID of the split stream.
    /// - `recipient` — The recipient address to query.
    ///
    /// # Returns
    /// The withdrawable token amount (base units) for `recipient`. Always
    /// non-negative.
    ///
    /// # Errors
    /// - [`Error::NotFound`] if `stream_id` does not exist or `recipient`
    ///   is not in the allocation list.
    pub fn split_withdrawable(env: Env, stream_id: u64, recipient: Address) -> Result<i128, Error> {
        multi::split_withdrawable(env, stream_id, recipient)
    }

    /// Returns the total vested amount for a split stream at the current
    /// ledger timestamp.
    ///
    /// This is a read-only view that never mutates state or requires auth.
    /// It is unaffected by the global pause flag.
    ///
    /// # Parameters
    /// - `stream_id` — Numeric ID of the split stream.
    ///
    /// # Returns
    /// The total vested token amount (base units) across all recipients.
    ///
    /// # Errors
    /// - [`Error::NotFound`] if `stream_id` does not exist.
    /// - [`Error::Overflow`] if the vested-amount computation overflows.
    pub fn split_stream_balance(env: Env, stream_id: u64) -> Result<i128, Error> {
        multi::split_stream_balance(env, stream_id)
    }

    /// Returns a paginated list of streams filtered by sender and status.
    ///
    /// This is a read-only view that never mutates state or requires auth.
    ///
    /// # Parameters
    ///
    /// - `sender` — Filter: only return streams where `stream.sender == sender`.
    /// - `status` — Filter: only return streams where `stream.status == status`.
    /// - `start_after` — Exclusive cursor: return streams with `id > start_after`.
    /// - `limit` — Maximum number of streams to return. Capped at [`MAX_PAGE_SIZE`].
    ///
    /// # Returns
    ///
    /// A [`StreamPage`] with up to `limit` streams matching both filters.
    pub fn list_streams_sender_status(
        env: Env,
        sender: Address,
        status: StreamStatus,
        start_after: Option<u64>,
        limit: u64,
    ) -> views::StreamPage {
        views::list_streams_by_sender_and_status(&env, &sender, status, start_after, limit)
    }
}

fn get_existing_stream(env: &Env, stream_id: u64) -> Result<Stream, Error> {
    storage::get_stream(env, stream_id).ok_or(Error::NotFound)
}

fn require_admin(env: &Env, caller: &Address) -> Result<(), Error> {
    caller.require_auth();

    let admin: Address = storage::get_admin(env).ok_or(Error::NotFound)?;

    if admin != *caller {
        return Err(Error::Unauthorized);
    }

    Ok(())
}

/// Returns [`Error::ContractPaused`] when the global pause flag is `true`.
fn require_not_paused(env: &Env) -> Result<(), Error> {
    if storage::is_paused(env) {
        return Err(Error::ContractPaused);
    }

    Ok(())
}

/// Verifies the `recipient` has an established trustline for `token`.
///
/// We probe the recipient's balance through the SEP-41 token client. For a
/// Stellar Asset Contract wrapping a classic asset, the recipient must have a
/// trustline before they can hold a non-zero balance; the contract enforces a
/// non-negative balance here as a cheap, host-side liveness check that the
/// account can receive the asset. The native asset and well-formed SAC tokens
/// always return a (possibly zero) balance, so this never rejects a valid
/// recipient.
///
/// # Errors
/// - [`Error::RecipientTrustlineMissing`] if the recipient cannot hold the
///   token (balance query returns a negative value, which is impossible for a
///   trustlined account).
fn require_recipient_trustline(
    env: &Env,
    token: &Address,
    recipient: &Address,
) -> Result<(), Error> {
    let balance = token::Client::new(env, token).balance(recipient);
    if balance < 0 {
        return Err(Error::RecipientTrustlineMissing);
    }
    Ok(())
}

#[cfg(test)]
mod test;

#[cfg(test)]
mod prop_test;

/// Focused tests that close function-coverage gaps identified in the
/// GrantFox baseline (coverage-output.txt) and push the gate above 95 %.
/// See `src/coverage_test.rs` for the full test matrix.
#[cfg(test)]
mod coverage_test;

#[cfg(test)]
mod views_integration_test;

/// Focused tests for admin nonce / replay-prevention (issue #949).
#[cfg(test)]
mod admin_nonce_test;
/// Focused lifecycle-event tests: each test asserts that the exact structured
/// event (correct topic pair, correct payload fields) is emitted for every
/// state-changing entrypoint.  See `src/events_test.rs`.
#[cfg(test)]
mod events_test;

#[cfg(test)]
mod err_stab;

#[cfg(test)]
mod fee_test;

#[cfg(test)]
mod upgrade_test {
    use super::*;
    use soroban_sdk::testutils::Address as _;

    #[test]
    fn test_upgrade() {
        let env = Env::default();
        env.mock_all_auths();

        let admin = Address::generate(&env);
        let contract_id = env.register(Contract, ());
        let client = ContractClient::new(&env, &contract_id);

        client.initialize(&admin);

        let new_wasm_hash = env.deployer().upload_contract_wasm(&[] as &[u8]);

        client.upgrade(&admin, &new_wasm_hash);
    }
}
