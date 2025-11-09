module intenus::solver_registry;

use sui::balance::{Self, Balance};
use sui::clock::{Self, Clock};
use sui::coin::{Self, Coin};
use sui::event;
use sui::sui::SUI;
use sui::table::{Self, Table};

// ===== ERRORS =====
const E_INSUFFICIENT_STAKE: u64 = 1001;
const E_SOLVER_NOT_REGISTERED: u64 = 1002;
const E_SOLVER_ALREADY_REGISTERED: u64 = 1003;
const E_COOLDOWN_NOT_COMPLETE: u64 = 1007;
const E_INVALID_STATUS: u64 = 1009;
const E_INSUFFICIENT_BALANCE: u64 = 1011;
const E_NO_PENDING_WITHDRAWAL: u64 = 1012;

// ===== CONSTANTS =====
const MIN_STAKE_AMOUNT: u64 = 1_000_000_000_000; // 1000 SUI
const WITHDRAWAL_COOLDOWN_MS: u64 = 604_800_000; // 7 days
const SLASH_PERCENTAGE: u8 = 20; // 20%
const REWARD_PERCENTAGE: u8 = 10; // 10%
const MAX_REPUTATION: u64 = 10_000;

// Solver status constants
const STATUS_ACTIVE: u8 = 0;
const STATUS_SLASHED: u8 = 1;
const STATUS_UNSTAKING: u8 = 3;

// ===== STRUCTS =====

/// Admin capability for managing the solver registry
public struct AdminCap has key, store {
    id: object::UID,
}

/// Individual solver profile with performance metrics
public struct SolverProfile has copy, drop, store {
    solver_address: address,
    stake_amount: u64,
    reputation_score: u64,
    total_batches_participated: u64,
    batches_won: u64,
    total_surplus_generated: u64,
    accuracy_score: u64,
    last_submission_epoch: u64,
    registration_timestamp: u64,
    status: u8,
    pending_withdrawal: Option<u64>, // Timestamp when can withdraw
}

/// Main solver registry (shared object)
public struct SolverRegistry has key {
    id: object::UID,
    profiles: Table<address, SolverProfile>,
    stakes: Table<address, Balance<SUI>>, // Separate table for balances
    min_stake: u64,
    slash_percentage: u8,
    withdrawal_cooldown: u64,
    reward_percentage: u8,
    total_solvers: u64,
    admin: address,
}

// ===== EVENTS =====

public struct SolverRegistered has copy, drop {
    solver: address,
    stake: u64,
    timestamp: u64,
}

public struct SolverSlashed has copy, drop {
    solver: address,
    slash_amount: u64,
    reason: vector<u8>,
    timestamp: u64,
}

public struct WithdrawalInitiated has copy, drop {
    solver: address,
    amount: u64,
    available_at: u64,
}

public struct WithdrawalCompleted has copy, drop {
    solver: address,
    amount: u64,
    timestamp: u64,
}

public struct ReputationUpdated has copy, drop {
    solver: address,
    old_reputation: u64,
    new_reputation: u64,
    batch_id: vector<u8>,
}

public struct BatchRewardDistributed has copy, drop {
    batch_id: vector<u8>,
    winner: address,
    surplus_amount: u64,
    reward_amount: u64,
}

// ===== INITIALIZATION =====

/// Initialize the solver registry
fun init(ctx: &mut tx_context::TxContext) {
    let admin_cap = AdminCap {
        id: object::new(ctx),
    };

    let registry = SolverRegistry {
        id: object::new(ctx),
        profiles: table::new(ctx),
        stakes: table::new(ctx),
        min_stake: MIN_STAKE_AMOUNT,
        slash_percentage: SLASH_PERCENTAGE,
        withdrawal_cooldown: WITHDRAWAL_COOLDOWN_MS,
        reward_percentage: REWARD_PERCENTAGE,
        total_solvers: 0,
        admin: tx_context::sender(ctx),
    };

    transfer::transfer(admin_cap, tx_context::sender(ctx));
    transfer::share_object(registry);
}

// ===== ENTRY FUNCTIONS (User-facing) =====

/// Register as a solver with initial stake
public fun register_solver(
    registry: &mut SolverRegistry,
    stake: Coin<SUI>,
    clock: &Clock,
    ctx: &mut tx_context::TxContext,
) {
    let solver_address = tx_context::sender(ctx);
    let stake_amount = coin::value(&stake);
    let timestamp = clock::timestamp_ms(clock);

    // Validate stake amount
    assert!(stake_amount >= registry.min_stake, E_INSUFFICIENT_STAKE);

    // Check if solver is not already registered
    assert!(!table::contains(&registry.profiles, solver_address), E_SOLVER_ALREADY_REGISTERED);

    // Create solver profile
    let profile = SolverProfile {
        solver_address,
        stake_amount,
        reputation_score: MAX_REPUTATION / 2, // Start with 50% reputation
        total_batches_participated: 0,
        batches_won: 0,
        total_surplus_generated: 0,
        accuracy_score: 100, // Start with perfect accuracy
        last_submission_epoch: 0,
        registration_timestamp: timestamp,
        status: STATUS_ACTIVE,
        pending_withdrawal: option::none(),
    };

    // Store profile and stake
    table::add(&mut registry.profiles, solver_address, profile);
    table::add(&mut registry.stakes, solver_address, coin::into_balance(stake));
    registry.total_solvers = registry.total_solvers + 1;

    // Emit event
    event::emit(SolverRegistered {
        solver: solver_address,
        stake: stake_amount,
        timestamp,
    });
}

/// Increase stake amount
public fun increase_stake(
    registry: &mut SolverRegistry,
    additional_stake: Coin<SUI>,
    ctx: &mut tx_context::TxContext,
) {
    let solver_address = tx_context::sender(ctx);
    let additional_amount = coin::value(&additional_stake);

    // Check if solver is registered
    assert!(table::contains(&registry.profiles, solver_address), E_SOLVER_NOT_REGISTERED);

    // Update profile
    let profile = table::borrow_mut(&mut registry.profiles, solver_address);
    profile.stake_amount = profile.stake_amount + additional_amount;

    // Add to balance
    let stake_balance = table::borrow_mut(&mut registry.stakes, solver_address);
    balance::join(stake_balance, coin::into_balance(additional_stake));
}

/// Initiate withdrawal process (starts cooldown)
public fun initiate_withdrawal(
    registry: &mut SolverRegistry,
    amount: u64,
    clock: &Clock,
    ctx: &mut tx_context::TxContext,
) {
    let solver_address = tx_context::sender(ctx);
    let timestamp = clock::timestamp_ms(clock);

    // Check if solver is registered
    assert!(table::contains(&registry.profiles, solver_address), E_SOLVER_NOT_REGISTERED);

    let profile = table::borrow_mut(&mut registry.profiles, solver_address);

    // Check if solver has sufficient stake
    assert!(profile.stake_amount >= amount, E_INSUFFICIENT_BALANCE);

    // Check minimum stake requirement after withdrawal
    assert!(profile.stake_amount - amount >= registry.min_stake, E_INSUFFICIENT_STAKE);

    // Set withdrawal timestamp
    let available_at = timestamp + registry.withdrawal_cooldown;
    profile.pending_withdrawal = option::some(available_at);
    profile.status = STATUS_UNSTAKING;

    event::emit(WithdrawalInitiated {
        solver: solver_address,
        amount,
        available_at,
    });
}

/// Complete withdrawal after cooldown period
public fun complete_withdrawal(
    registry: &mut SolverRegistry,
    amount: u64,
    clock: &Clock,
    ctx: &mut tx_context::TxContext,
) {
    let solver_address = tx_context::sender(ctx);
    let timestamp = clock::timestamp_ms(clock);

    // Check if solver is registered
    assert!(table::contains(&registry.profiles, solver_address), E_SOLVER_NOT_REGISTERED);

    let profile = table::borrow_mut(&mut registry.profiles, solver_address);

    // Check if withdrawal was initiated
    assert!(option::is_some(&profile.pending_withdrawal), E_NO_PENDING_WITHDRAWAL);

    let available_at = *option::borrow(&profile.pending_withdrawal);

    // Check if cooldown period has passed
    assert!(timestamp >= available_at, E_COOLDOWN_NOT_COMPLETE);

    // Update profile
    profile.stake_amount = profile.stake_amount - amount;
    profile.pending_withdrawal = option::none();
    profile.status = STATUS_ACTIVE;

    // Withdraw from balance
    let stake_balance = table::borrow_mut(&mut registry.stakes, solver_address);
    let withdrawal_balance = balance::split(stake_balance, amount);
    let withdrawal_coin = coin::from_balance(withdrawal_balance, ctx);

    // Transfer to solver
    transfer::public_transfer(withdrawal_coin, solver_address);

    event::emit(WithdrawalCompleted {
        solver: solver_address,
        amount,
        timestamp,
    });
}

// ===== FRIEND FUNCTIONS (Inter-module) =====

/// Record batch participation and update metrics
public(package) fun record_batch_participation(
    registry: &mut SolverRegistry,
    solver: address,
    batch_id: vector<u8>,
    won: bool,
    surplus_generated: u64,
    claimed_metrics: u64,
    actual_metrics: u64,
    epoch: u64,
) {
    assert!(table::contains(&registry.profiles, solver), E_SOLVER_NOT_REGISTERED);

    let profile = table::borrow_mut(&mut registry.profiles, solver);
    let old_reputation = profile.reputation_score;

    // Update participation metrics
    profile.total_batches_participated = profile.total_batches_participated + 1;
    profile.last_submission_epoch = epoch;

    if (won) {
        profile.batches_won = profile.batches_won + 1;
        profile.total_surplus_generated = profile.total_surplus_generated + surplus_generated;
    };

    // Update accuracy score
    if (claimed_metrics > 0) {
        let accuracy_delta = if (actual_metrics > claimed_metrics) {
            actual_metrics - claimed_metrics
        } else {
            claimed_metrics - actual_metrics
        };

        let accuracy_percentage = if (accuracy_delta * 100 / claimed_metrics > 100) {
            0
        } else {
            100 - (accuracy_delta * 100 / claimed_metrics)
        };

        // Weighted average with previous accuracy
        profile.accuracy_score = (profile.accuracy_score * 9 + accuracy_percentage) / 10;
    };

    // Calculate new reputation
    let new_reputation = calculate_reputation(profile);
    profile.reputation_score = new_reputation;

    event::emit(ReputationUpdated {
        solver,
        old_reputation,
        new_reputation,
        batch_id,
    });
}

/// Slash solver for malicious behavior
public(package) fun slash_solver(
    _: &AdminCap,
    registry: &mut SolverRegistry,
    solver: address,
    evidence: vector<u8>,
    clock: &Clock,
    _ctx: &mut tx_context::TxContext,
) {
    assert!(table::contains(&registry.profiles, solver), E_SOLVER_NOT_REGISTERED);

    let profile = table::borrow_mut(&mut registry.profiles, solver);
    let stake_balance = table::borrow_mut(&mut registry.stakes, solver);

    let slash_amount = (profile.stake_amount * (registry.slash_percentage as u64)) / 100;

    // Update profile
    profile.stake_amount = profile.stake_amount - slash_amount;
    profile.status = STATUS_SLASHED;
    profile.reputation_score = profile.reputation_score / 2; // Halve reputation

    // Burn slashed tokens by destroying the balance
    let slashed_balance = balance::split(stake_balance, slash_amount);
    balance::destroy_zero(slashed_balance);

    event::emit(SolverSlashed {
        solver,
        slash_amount,
        reason: evidence,
        timestamp: clock::timestamp_ms(clock),
    });
}

/// Distribute batch rewards to winner
public(package) fun distribute_batch_rewards(
    registry: &SolverRegistry,
    batch_id: vector<u8>,
    winner: address,
    surplus_amount: u64,
    reward_coin: Coin<SUI>,
) {
    assert!(table::contains(&registry.profiles, winner), E_SOLVER_NOT_REGISTERED);

    let reward_amount = coin::value(&reward_coin);

    // Transfer reward to winner
    transfer::public_transfer(reward_coin, winner);

    event::emit(BatchRewardDistributed {
        batch_id,
        winner,
        surplus_amount,
        reward_amount,
    });
}

// ===== VIEW FUNCTIONS (Read-only) =====

/// Get solver profile information
public fun get_solver_profile(registry: &SolverRegistry, solver: address): Option<SolverProfile> {
    if (table::contains(&registry.profiles, solver)) {
        option::some(*table::borrow(&registry.profiles, solver))
    } else {
        option::none()
    }
}

/// Get solver stake amount
public fun get_solver_stake(registry: &SolverRegistry, solver: address): u64 {
    if (table::contains(&registry.profiles, solver)) {
        table::borrow(&registry.profiles, solver).stake_amount
    } else {
        0
    }
}

/// Get solver reputation score
public fun get_solver_reputation(registry: &SolverRegistry, solver: address): u64 {
    if (table::contains(&registry.profiles, solver)) {
        table::borrow(&registry.profiles, solver).reputation_score
    } else {
        0
    }
}

/// Check if solver is active
public fun is_solver_active(registry: &SolverRegistry, solver: address): bool {
    if (table::contains(&registry.profiles, solver)) {
        table::borrow(&registry.profiles, solver).status == STATUS_ACTIVE
    } else {
        false
    }
}

/// Get registry statistics
public fun get_registry_stats(registry: &SolverRegistry): (u64, u64, u64) {
    (registry.total_solvers, registry.min_stake, registry.withdrawal_cooldown)
}

// ===== INTERNAL HELPERS =====

/// Calculate reputation score based on performance metrics
fun calculate_reputation(profile: &SolverProfile): u64 {
    if (profile.total_batches_participated == 0) {
        return MAX_REPUTATION / 2 // Default for new solvers
    };

    // Win rate component (40% weight)
    let win_rate = (profile.batches_won * 100) / profile.total_batches_participated;
    let win_component = (win_rate * 40) / 100;

    // Accuracy component (30% weight)
    let accuracy_component = (profile.accuracy_score * 30) / 100;

    // Volume component (30% weight) - logarithmic scaling
    let volume_component = if (profile.total_surplus_generated > 0) {
        let log_volume = log_approximation(profile.total_surplus_generated);
        let max_log = log_approximation(1_000_000_000_000); // 1M SUI equivalent
        (log_volume * 30) / max_log
    } else {
        0
    };

    let total_score = win_component + accuracy_component + volume_component;

    // Cap at maximum reputation
    if (total_score > MAX_REPUTATION) {
        MAX_REPUTATION
    } else {
        total_score
    }
}

/// Simple logarithm approximation for reputation calculation
fun log_approximation(value: u64): u64 {
    if (value <= 1) return 0;

    let mut result = 0;
    let mut temp = value;

    while (temp > 1) {
        temp = temp / 2;
        result = result + 1;
    };

    result * 100 // Scale for precision
}

// ===== ADMIN FUNCTIONS =====

/// Update minimum stake requirement (admin only)
public fun update_min_stake(_: &AdminCap, registry: &mut SolverRegistry, new_min_stake: u64) {
    registry.min_stake = new_min_stake;
}

/// Update slash percentage (admin only)
public fun update_slash_percentage(
    _: &AdminCap,
    registry: &mut SolverRegistry,
    new_percentage: u8,
) {
    assert!(new_percentage <= 50, E_INVALID_STATUS); // Max 50% slash
    registry.slash_percentage = new_percentage;
}

// ===== TEST FUNCTIONS =====

#[test_only]
public fun init_for_testing(ctx: &mut tx_context::TxContext) {
    init(ctx);
}

#[test_only]
public fun create_test_solver_profile(
    solver_address: address,
    stake_amount: u64,
    reputation_score: u64,
): SolverProfile {
    SolverProfile {
        solver_address,
        stake_amount,
        reputation_score,
        total_batches_participated: 0,
        batches_won: 0,
        total_surplus_generated: 0,
        accuracy_score: 100,
        last_submission_epoch: 0,
        registration_timestamp: 0,
        status: STATUS_ACTIVE,
        pending_withdrawal: option::none(),
    }
}
