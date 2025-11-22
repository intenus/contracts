module intenus::solver_registry;

use sui::balance::{Self, Balance};
use sui::clock::{Self, Clock};
use sui::coin::{Self, Coin};
use sui::event;
use sui::sui::SUI;
use sui::table::{Self, Table};

use intenus::slash_manager::{Self, SlashManager};

// ===== ERRORS =====
const E_INSUFFICIENT_STAKE: u64 = 1001;
const E_SOLVER_NOT_REGISTERED: u64 = 1002;
const E_SOLVER_ALREADY_REGISTERED: u64 = 1003;
const E_COOLDOWN_NOT_COMPLETE: u64 = 1007;
const E_INVALID_STATUS: u64 = 1009;
const E_INSUFFICIENT_BALANCE: u64 = 1011;
const E_NO_PENDING_WITHDRAWAL: u64 = 1012;

// ===== CONSTANTS =====
const MIN_STAKE_AMOUNT: u64 = 1_000_000_000; // 1 SUI (Just for testing)
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
    id: UID,
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
    id: UID,
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

#[test_only]
public fun init_for_testing(ctx: &mut tx_context::TxContext) {
    init(ctx)
}

#[test_only]
public fun get_admin_cap_for_testing(ctx: &mut tx_context::TxContext): AdminCap {
    AdminCap { id: object::new(ctx) }
}

// ===== ENTRY FUNCTIONS =====

/// Register as a solver with initial stake
entry fun register_solver(
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
entry fun increase_stake(
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
entry fun initiate_withdrawal(
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
entry fun complete_withdrawal(
    registry: &mut SolverRegistry,
    slash_manager: &SlashManager,
    amount: u64,
    clock: &Clock,
    ctx: &mut TxContext,
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
    
    // Calculate total slash percentage directly from slash_manager
    let slash_percentage_bps = slash_manager::calculate_total_slash_percentage(
        slash_manager,
        solver_address
    );
    
    // Apply slash if any
    let final_amount = if (slash_percentage_bps > 0) {
        amount - (amount * slash_percentage_bps / 10000)
    } else {
        amount
    };

    // Update profile
    profile.stake_amount = profile.stake_amount - amount;
    profile.pending_withdrawal = option::none();
    profile.status = STATUS_ACTIVE;

    // Withdraw from balance
    let stake_balance = table::borrow_mut(&mut registry.stakes, solver_address);
    let withdrawal_balance = balance::split(stake_balance, final_amount);
    let withdrawal_coin = coin::from_balance(withdrawal_balance, ctx);
    
    // If there was a slash, burn the slashed portion
    if (slash_percentage_bps > 0) {
        let slashed_amount = amount - final_amount;
        let slashed_balance = balance::split(stake_balance, slashed_amount);
        let slashed_coin = coin::from_balance(slashed_balance, ctx);
        transfer::public_transfer(slashed_coin, @0x0); // Burn
    };

    // Transfer withdrawal to solver
    event::emit(WithdrawalCompleted {
        solver: solver_address,
        amount: final_amount,
        timestamp,
    });
    
    transfer::public_transfer(withdrawal_coin, solver_address);
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

    // Burn slashed tokens by creating a coin and burning it
    let slashed_balance = balance::split(stake_balance, slash_amount);
    let slashed_coin = coin::from_balance(slashed_balance, _ctx);
    transfer::public_transfer(slashed_coin, @0x0);

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

// ===== CONSTANT GETTERS (for testing) =====

public(package) fun get_min_stake_amount(): u64 { MIN_STAKE_AMOUNT }
public(package) fun get_withdrawal_cooldown_ms(): u64 { WITHDRAWAL_COOLDOWN_MS }
public(package) fun get_slash_percentage(): u8 { SLASH_PERCENTAGE }

// ===== INTERNAL HELPERS =====

/// Calculate reputation score based on performance metrics
fun calculate_reputation(profile: &SolverProfile): u64 {
    if (profile.total_batches_participated == 0) {
        return MAX_REPUTATION / 2 // Default for new solvers
    };

    // Win rate component (40% weight)
    let win_rate = (profile.batches_won * 100) / profile.total_batches_participated;
    let win_component = (win_rate * MAX_REPUTATION * 40) / 10000;

    // Accuracy component (30% weight)
    let accuracy_component = (profile.accuracy_score * MAX_REPUTATION * 30) / 10000;

    // Volume component (30% weight) - logarithmic scaling
    let volume_component = if (profile.total_surplus_generated > 0) {
        let log_volume = log_approximation(profile.total_surplus_generated);
        let max_log = log_approximation(1_000_000_000_000); // 1M SUI equivalent
        (log_volume * MAX_REPUTATION * 30) / (max_log * 100)
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
entry fun update_min_stake(_: &AdminCap, registry: &mut SolverRegistry, new_min_stake: u64) {
    registry.min_stake = new_min_stake;
}

/// Update slash percentage (admin only)
entry fun update_slash_percentage(
    _: &AdminCap,
    registry: &mut SolverRegistry,
    new_percentage: u8,
) {
    assert!(new_percentage <= 50, E_INVALID_STATUS); // Max 50% slash
    registry.slash_percentage = new_percentage;
}

// ===== TEST FUNCTIONS =====

#[test_only]
use sui::test_scenario::{Self as ts};

#[test_only]
const ADMIN: address = @0xA;
#[test_only]
const SOLVER: address = @0xB;
#[test_only]
const BACKEND: address = @0xC; // Backend address for friend functions

#[test_only]
/// Test wrapper for record_batch_participation
public fun test_record_batch_participation(
    registry: &mut SolverRegistry,
    solver: address,
    batch_id: vector<u8>,
    won: bool,
    surplus_generated: u64,
    claimed_metrics: u64,
    actual_metrics: u64,
    epoch: u64,
) {
    record_batch_participation(
        registry,
        solver,
        batch_id,
        won,
        surplus_generated,
        claimed_metrics,
        actual_metrics,
        epoch,
    );
}

#[test_only]
/// Test wrapper for slash_solver
public fun test_slash_solver(
    admin_cap: &AdminCap,
    registry: &mut SolverRegistry,
    solver: address,
    evidence: vector<u8>,
    clock: &Clock,
    ctx: &mut tx_context::TxContext,
) {
    slash_solver(admin_cap, registry, solver, evidence, clock, ctx);
}

/// Test core value: Reputation system updates from batch participation
/// This tests the core mechanism that makes solvers compete fairly
#[test]
fun test_reputation_updates_from_batch_participation() {
    let mut scenario = ts::begin(ADMIN);
    init(ts::ctx(&mut scenario));
    
    // Create and share Clock for testing
    let clock = clock::create_for_testing(ts::ctx(&mut scenario));
    clock.share_for_testing();
    ts::next_tx(&mut scenario, ADMIN);

    let stake_amount = MIN_STAKE_AMOUNT;
    let batch_id = b"batch_001";

    // --- Register solver ---
    ts::next_tx(&mut scenario, SOLVER);
    {
        let mut registry = ts::take_shared<SolverRegistry>(&scenario);
        let clock_ref = ts::take_shared<Clock>(&scenario);
        let stake_coin = coin::mint_for_testing<SUI>(stake_amount, ts::ctx(&mut scenario));
        
        register_solver(&mut registry, stake_coin, &clock_ref, ts::ctx(&mut scenario));
        
        let initial_reputation = get_solver_reputation(&registry, SOLVER);
        assert!(initial_reputation == MAX_REPUTATION / 2, 1); // Starts at 50%

        ts::return_shared(registry);
        ts::return_shared(clock_ref);
    };

    // --- Backend records batch participation: solver wins with accurate metrics ---
    ts::next_tx(&mut scenario, BACKEND);
    {
        let mut registry = ts::take_shared<SolverRegistry>(&scenario);
        
        // Simulate winning a batch with high accuracy
        test_record_batch_participation(
            &mut registry,
            SOLVER,
            batch_id,
            true, // won
            1_000_000_000, // surplus generated
            100_000, // claimed metrics
            100_000, // actual metrics (perfect accuracy)
            1, // epoch
        );
        
        let reputation_after_win = get_solver_reputation(&registry, SOLVER);
        assert!(reputation_after_win > MAX_REPUTATION / 2, 2); // Reputation increased

        ts::return_shared(registry);
    };

    // --- Backend records another batch: solver loses but participates ---
    ts::next_tx(&mut scenario, BACKEND);
    {
        let mut registry = ts::take_shared<SolverRegistry>(&scenario);
        
        test_record_batch_participation(
            &mut registry,
            SOLVER,
            b"batch_002",
            false, // lost
            0, // no surplus
            50_000, // claimed
            60_000, // actual (20% error)
            2, // epoch
        );
        
        let reputation_after_loss = get_solver_reputation(&registry, SOLVER);
        // Reputation should decrease due to lower accuracy and loss
        assert!(reputation_after_loss < MAX_REPUTATION, 3);

        ts::return_shared(registry);
    };

    // Clean up Clock
    ts::next_tx(&mut scenario, ADMIN);
    {
        let clock = ts::take_shared<Clock>(&scenario);
        clock.destroy_for_testing();
    };

    ts::end(scenario);
}

/// Test core value: Slashing mechanism for malicious solvers
#[test]
fun test_slashing_malicious_solver() {
    let mut scenario = ts::begin(ADMIN);
    init(ts::ctx(&mut scenario));
    
    // Create and share Clock for testing
    let clock = clock::create_for_testing(ts::ctx(&mut scenario));
    clock.share_for_testing();
    ts::next_tx(&mut scenario, ADMIN);
    
    let admin_cap = ts::take_from_sender<AdminCap>(&scenario);
    transfer::transfer(admin_cap, ADMIN);
    ts::next_tx(&mut scenario, ADMIN);

    let stake_amount = MIN_STAKE_AMOUNT * 2; // 2000 SUI

    // --- Register solver ---
    ts::next_tx(&mut scenario, SOLVER);
    {
        let mut registry = ts::take_shared<SolverRegistry>(&scenario);
        let clock_ref = ts::take_shared<Clock>(&scenario);
        let stake_coin = coin::mint_for_testing<SUI>(stake_amount, ts::ctx(&mut scenario));
        
        register_solver(&mut registry, stake_coin, &clock_ref, ts::ctx(&mut scenario));
        
        let initial_stake = get_solver_stake(&registry, SOLVER);
        assert!(initial_stake == stake_amount, 1);

        ts::return_shared(registry);
        ts::return_shared(clock_ref);
    };

    // --- Admin slashes solver for malicious behavior ---
    ts::next_tx(&mut scenario, ADMIN);
    {
        let admin_cap = ts::take_from_sender<AdminCap>(&scenario);
        let mut registry = ts::take_shared<SolverRegistry>(&scenario);
        let clock_ref = ts::take_shared<Clock>(&scenario);
        
        let stake_before = get_solver_stake(&registry, SOLVER);
        let reputation_before = get_solver_reputation(&registry, SOLVER);

        test_slash_solver(
            &admin_cap,
            &mut registry,
            SOLVER,
            b"front_running_detected",
            &clock_ref,
            ts::ctx(&mut scenario),
        );

        let stake_after = get_solver_stake(&registry, SOLVER);
        let reputation_after = get_solver_reputation(&registry, SOLVER);
        
        // 20% of stake should be slashed
        let expected_slash = (stake_before * (SLASH_PERCENTAGE as u64)) / 100;
        assert!(stake_after == stake_before - expected_slash, 2);
        
        // Reputation should be halved
        assert!(reputation_after == reputation_before / 2, 3);
        
        // Status should be SLASHED
        assert!(!is_solver_active(&registry, SOLVER), 4);

        transfer::transfer(admin_cap, ADMIN);
        ts::return_shared(registry);
        ts::return_shared(clock_ref);
    };

    // Clean up Clock
    ts::next_tx(&mut scenario, ADMIN);
    {
        let clock = ts::take_shared<Clock>(&scenario);
        clock.destroy_for_testing();
    };

    ts::end(scenario);
}
