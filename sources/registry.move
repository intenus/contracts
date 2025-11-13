module intenus::registry;

use sui::clock::{Self, Clock};
use sui::event;
use intenus::solver_registry::{Self, SolverRegistry};

// ===== ERRORS =====
const E_INVALID_BLOB_ID: u64 = 6001;
const E_UNAUTHORIZED_SOLVER: u64 = 6002;
const E_POLICY_VALIDATION_FAILED: u64 = 6003;
const E_INTENT_REVOKED: u64 = 6004;
const E_UNAUTHORIZED: u64 = 6005;
const E_INVALID_TIME_WINDOW: u64 = 6006;
const E_SOLUTION_ALREADY_SELECTED: u64 = 6007;

// ===== CONSTANTS =====
const STATUS_PENDING: u8 = 0;
const STATUS_BEST_SOLUTION_SELECTED: u8 = 1;
const STATUS_REVOKED: u8 = 2;

// ===== STRUCTS =====

/// Time window for solver access control
public struct TimeWindow has copy, drop, store {
    start_ms: u64,
    end_ms: u64,
}

/// Access condition for policy enforcement
public struct AccessCondition has copy, drop, store {
    requires_solver_registration: bool,
    min_solver_stake: u64,
    requires_tee_attestation: bool,
    expected_measurement: vector<u8>,
    purpose: vector<u8>,
}

/// Policy parameters embedded in Intent
public struct PolicyParams has copy, drop, store {
    solver_access_window: TimeWindow,
    router_access_enabled: bool,
    auto_revoke_time: u64,
    access_condition: AccessCondition,
}

/// Intent object submitted by users (owned object)
public struct Intent has key, store {
    id: UID,
    user_address: address,
    created_ts: u64,
    blob_id: vector<u8>,
    policy: PolicyParams,
    status: u8,
    best_solution_id: Option<ID>,
    pending_solutions: vector<ID>,
}

/// Solution object submitted by solvers (owned object)
public struct Solution has key, store {
    id: UID,
    intent_id: ID,
    solver_address: address,
    created_ts: u64,
    blob_id: vector<u8>,
    is_validated: bool,
}

// ===== EVENTS =====

public struct IntentSubmitted has copy, drop {
    intent_id: ID,
    user_address: address,
    blob_id: vector<u8>,
    created_ts: u64,
    solver_access_start: u64,
    solver_access_end: u64,
}

public struct IntentRevoked has copy, drop {
    intent_id: ID,
    user_address: address,
    revoked_at: u64,
}

public struct SolutionSubmitted has copy, drop {
    solution_id: ID,
    intent_id: ID,
    solver_address: address,
    blob_id: vector<u8>,
    created_ts: u64,
}

public struct SolutionValidated has copy, drop {
    solution_id: ID,
    intent_id: ID,
    solver_address: address,
    validated_at: u64,
}

public struct BestSolutionSelected has copy, drop {
    intent_id: ID,
    solution_id: ID,
    user_address: address,
    selected_at: u64,
}

// ===== ENTRY FUNCTIONS =====

/// Submit a new intent with embedded policy parameters
/// Creates an Intent object and transfers it to the user
public entry fun submit_intent(
    blob_id: vector<u8>,
    solver_access_start_ms: u64,
    solver_access_end_ms: u64,
    router_access_enabled: bool,
    auto_revoke_time: u64,
    requires_solver_registration: bool,
    min_solver_stake: u64,
    requires_tee_attestation: bool,
    expected_measurement: vector<u8>,
    purpose: vector<u8>,
    clock: &Clock,
    ctx: &mut TxContext,
) {
    let sender = tx_context::sender(ctx);
    let timestamp = clock::timestamp_ms(clock);

    // Validate input
    assert!(vector::length(&blob_id) > 0, E_INVALID_BLOB_ID);
    assert!(solver_access_start_ms < solver_access_end_ms, E_INVALID_TIME_WINDOW);

    // Create intent with embedded policy
    let intent_uid = object::new(ctx);
    let intent_id = object::uid_to_inner(&intent_uid);

    let intent = Intent {
        id: intent_uid,
        user_address: sender,
        created_ts: timestamp,
        blob_id,
        policy: PolicyParams {
            solver_access_window: TimeWindow {
                start_ms: solver_access_start_ms,
                end_ms: solver_access_end_ms,
            },
            router_access_enabled,
            auto_revoke_time,
            access_condition: AccessCondition {
                requires_solver_registration,
                min_solver_stake,
                requires_tee_attestation,
                expected_measurement,
                purpose,
            },
        },
        status: STATUS_PENDING,
        best_solution_id: option::none(),
        pending_solutions: vector::empty(),
    };

    // Emit event
    event::emit(IntentSubmitted {
        intent_id,
        user_address: sender,
        blob_id: intent.blob_id,
        created_ts: timestamp,
        solver_access_start: solver_access_start_ms,
        solver_access_end: solver_access_end_ms,
    });

    // Transfer intent to user
    transfer::public_transfer(intent, sender);
}

/// Submit a solution for an intent with policy validation
/// Creates a Solution object and transfers it to the solver
/// Also registers the solution with the Intent
public entry fun submit_solution(
    intent: &mut Intent,
    solver_registry: &SolverRegistry,
    blob_id: vector<u8>,
    clock: &Clock,
    ctx: &mut TxContext,
) {
    let solver = tx_context::sender(ctx);
    let timestamp = clock::timestamp_ms(clock);

    // Validate inputs
    assert!(vector::length(&blob_id) > 0, E_INVALID_BLOB_ID);
    assert!(intent.status != STATUS_REVOKED, E_INTENT_REVOKED);

    // Validate policy conditions
    validate_solution_against_policy(intent, solver, timestamp, solver_registry);

    // Create solution
    let solution_uid = object::new(ctx);
    let solution_id = object::uid_to_inner(&solution_uid);
    let intent_id = object::uid_to_inner(&intent.id);

    let solution = Solution {
        id: solution_uid,
        intent_id,
        solver_address: solver,
        created_ts: timestamp,
        blob_id,
        is_validated: true,
    };

    // Register solution with intent
    vector::push_back(&mut intent.pending_solutions, solution_id);

    // Emit events
    event::emit(SolutionSubmitted {
        solution_id,
        intent_id,
        solver_address: solver,
        blob_id: solution.blob_id,
        created_ts: timestamp,
    });

    event::emit(SolutionValidated {
        solution_id,
        intent_id,
        solver_address: solver,
        validated_at: timestamp,
    });

    // Transfer solution to solver
    transfer::public_transfer(solution, solver);
}

/// Select the best solution for an intent (only owner can select)
public entry fun select_best_solution(
    intent: &mut Intent,
    solution_id: ID,
    clock: &Clock,
    ctx: &mut TxContext,
) {
    let sender = tx_context::sender(ctx);
    let timestamp = clock::timestamp_ms(clock);

    // Verify sender is the intent owner
    assert!(intent.user_address == sender, E_UNAUTHORIZED);
    assert!(intent.status == STATUS_PENDING, E_SOLUTION_ALREADY_SELECTED);

    // Verify solution is in pending list
    assert!(vector::contains(&intent.pending_solutions, &solution_id), E_UNAUTHORIZED_SOLVER);

    // Update intent
    intent.status = STATUS_BEST_SOLUTION_SELECTED;
    intent.best_solution_id = option::some(solution_id);

    // Emit event
    event::emit(BestSolutionSelected {
        intent_id: object::uid_to_inner(&intent.id),
        solution_id,
        user_address: sender,
        selected_at: timestamp,
    });
}

/// Revoke an intent (only owner can revoke)
public entry fun revoke_intent(
    intent: &mut Intent,
    clock: &Clock,
    ctx: &mut TxContext,
) {
    let sender = tx_context::sender(ctx);
    let timestamp = clock::timestamp_ms(clock);

    // Verify sender is the intent owner
    assert!(intent.user_address == sender, E_UNAUTHORIZED);
    assert!(intent.status == STATUS_PENDING, E_UNAUTHORIZED);

    // Update status
    intent.status = STATUS_REVOKED;

    // Emit event
    event::emit(IntentRevoked {
        intent_id: object::uid_to_inner(&intent.id),
        user_address: sender,
        revoked_at: timestamp,
    });
}

// ===== INTERNAL HELPER FUNCTIONS (DRY PRINCIPLE) =====

/// Validate solution submission against intent policy
/// Reuses logic patterns from seal_policy_coordinator
fun validate_solution_against_policy(
    intent: &Intent,
    solver: address,
    timestamp: u64,
    solver_registry: &SolverRegistry,
) {
    let policy = &intent.policy;

    // Check time window
    let in_window = timestamp >= policy.solver_access_window.start_ms
        && timestamp <= policy.solver_access_window.end_ms;
    assert!(in_window, E_POLICY_VALIDATION_FAILED);

    // Check auto-revoke time
    if (policy.auto_revoke_time > 0) {
        assert!(timestamp <= policy.auto_revoke_time, E_POLICY_VALIDATION_FAILED);
    };

    // Check solver registration requirement
    if (policy.access_condition.requires_solver_registration) {
        let is_active = solver_registry::is_solver_active(solver_registry, solver);
        assert!(is_active, E_UNAUTHORIZED_SOLVER);

        // Check minimum stake
        let stake = solver_registry::get_solver_stake(solver_registry, solver);
        assert!(stake >= policy.access_condition.min_solver_stake, E_UNAUTHORIZED_SOLVER);
    };

    // Note: TEE attestation would be validated here in production
    // For now, we assume the blob_id contains the attestation proof
}

// ===== VIEW FUNCTIONS =====

/// Get intent ID
public fun get_intent_id(intent: &Intent): ID {
    object::uid_to_inner(&intent.id)
}

/// Get intent user address
public fun get_intent_user(intent: &Intent): address {
    intent.user_address
}

/// Get intent status
public fun get_intent_status(intent: &Intent): u8 {
    intent.status
}

/// Get intent blob_id
public fun get_intent_blob_id(intent: &Intent): vector<u8> {
    intent.blob_id
}

/// Get intent best solution id
public fun get_intent_best_solution(intent: &Intent): Option<ID> {
    intent.best_solution_id
}

/// Get intent pending solutions
public fun get_intent_pending_solutions(intent: &Intent): vector<ID> {
    intent.pending_solutions
}

/// Get solution ID
public fun get_solution_id(solution: &Solution): ID {
    object::uid_to_inner(&solution.id)
}

/// Get solution intent ID
public fun get_solution_intent_id(solution: &Solution): ID {
    solution.intent_id
}

/// Get solution solver address
public fun get_solution_solver(solution: &Solution): address {
    solution.solver_address
}

/// Get solution blob_id
public fun get_solution_blob_id(solution: &Solution): vector<u8> {
    solution.blob_id
}

/// Check if solution is validated
public fun is_solution_validated(solution: &Solution): bool {
    solution.is_validated
}

// ===== TEST HELPERS =====

#[test_only]
use sui::test_scenario::{Self as ts};
#[test_only]
use sui::coin;
#[test_only]
use sui::sui::SUI;

#[test_only]
const ADMIN: address = @0xA;
#[test_only]
const USER: address = @0xB;
#[test_only]
const SOLVER: address = @0xC;

/// Test core value: Complete intent-solution lifecycle
#[test]
fun test_intent_solution_lifecycle() {
    let mut scenario = ts::begin(ADMIN);

    // Initialize solver registry
    solver_registry::init_for_testing(ts::ctx(&mut scenario));

    // Create and share Clock
    let clock = clock::create_for_testing(ts::ctx(&mut scenario));
    clock.share_for_testing();
    ts::next_tx(&mut scenario, ADMIN);

    // Register solver
    ts::next_tx(&mut scenario, SOLVER);
    {
        let mut solver_reg = ts::take_shared<SolverRegistry>(&scenario);
        let clock_ref = ts::take_shared<Clock>(&scenario);
        let stake = coin::mint_for_testing<SUI>(
            solver_registry::get_min_stake_amount(),
            ts::ctx(&mut scenario),
        );

        solver_registry::register_solver(&mut solver_reg, stake, &clock_ref, ts::ctx(&mut scenario));

        ts::return_shared(solver_reg);
        ts::return_shared(clock_ref);
    };

    // User submits intent
    ts::next_tx(&mut scenario, USER);
    {
        let clock_ref = ts::take_shared<Clock>(&scenario);
        let now = clock::timestamp_ms(&clock_ref);

        submit_intent(
            b"blob_intent_data",
            now, // solver_access_start
            now + 10_000, // solver_access_end
            true, // router_access_enabled
            now + 86_400_000, // auto_revoke_time (24h)
            true, // requires_solver_registration
            solver_registry::get_min_stake_amount(),
            false, // requires_tee_attestation
            vector::empty(),
            b"test_purpose",
            &clock_ref,
            ts::ctx(&mut scenario),
        );

        ts::return_shared(clock_ref);
    };

    // Solver submits solution
    ts::next_tx(&mut scenario, SOLVER);
    {
        let mut intent = ts::take_from_sender<Intent>(&scenario);
        let solver_reg = ts::take_shared<SolverRegistry>(&scenario);
        let clock_ref = ts::take_shared<Clock>(&scenario);

        submit_solution(
            &mut intent,
            &solver_reg,
            b"blob_solution_data",
            &clock_ref,
            ts::ctx(&mut scenario),
        );

        // Check solution was registered
        let pending = get_intent_pending_solutions(&intent);
        assert!(vector::length(&pending) == 1, 1);

        ts::return_to_sender(&scenario, intent);
        ts::return_shared(solver_reg);
        ts::return_shared(clock_ref);
    };

    // User selects best solution
    ts::next_tx(&mut scenario, USER);
    {
        let mut intent = ts::take_from_sender<Intent>(&scenario);
        let clock_ref = ts::take_shared<Clock>(&scenario);

        let pending = get_intent_pending_solutions(&intent);
        let solution_id = *vector::borrow(&pending, 0);

        select_best_solution(&mut intent, solution_id, &clock_ref, ts::ctx(&mut scenario));

        assert!(get_intent_status(&intent) == STATUS_BEST_SOLUTION_SELECTED, 2);
        assert!(option::is_some(&get_intent_best_solution(&intent)), 3);

        ts::return_to_sender(&scenario, intent);
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

/// Test policy validation: Unregistered solver should fail
#[test]
#[expected_failure(abort_code = E_UNAUTHORIZED_SOLVER)]
fun test_unregistered_solver_fails() {
    let mut scenario = ts::begin(ADMIN);

    // Initialize solver registry
    solver_registry::init_for_testing(ts::ctx(&mut scenario));

    let clock = clock::create_for_testing(ts::ctx(&mut scenario));
    clock.share_for_testing();
    ts::next_tx(&mut scenario, ADMIN);

    // User submits intent requiring solver registration
    ts::next_tx(&mut scenario, USER);
    {
        let clock_ref = ts::take_shared<Clock>(&scenario);
        let now = clock::timestamp_ms(&clock_ref);

        submit_intent(
            b"blob_data",
            now,
            now + 10_000,
            true,
            now + 86_400_000,
            true, // REQUIRES solver registration
            solver_registry::get_min_stake_amount(),
            false,
            vector::empty(),
            b"test",
            &clock_ref,
            ts::ctx(&mut scenario),
        );

        ts::return_shared(clock_ref);
    };

    // Unregistered solver tries to submit solution (should fail)
    ts::next_tx(&mut scenario, SOLVER);
    {
        let mut intent = ts::take_from_address<Intent>(&scenario, USER);
        let solver_reg = ts::take_shared<SolverRegistry>(&scenario);
        let clock_ref = ts::take_shared<Clock>(&scenario);

        submit_solution(
            &mut intent,
            &solver_reg,
            b"blob_solution",
            &clock_ref,
            ts::ctx(&mut scenario),
        );

        transfer::public_transfer(intent, USER);
        ts::return_shared(solver_reg);
        ts::return_shared(clock_ref);
    };

    // Cleanup
    ts::next_tx(&mut scenario, ADMIN);
    {
        let clock = ts::take_shared<Clock>(&scenario);
        clock.destroy_for_testing();
    };

    ts::end(scenario);
}

/// Test intent revocation
#[test]
fun test_intent_revocation() {
    let mut scenario = ts::begin(USER);

    let clock = clock::create_for_testing(ts::ctx(&mut scenario));
    clock.share_for_testing();
    ts::next_tx(&mut scenario, USER);

    // User submits intent
    {
        let clock_ref = ts::take_shared<Clock>(&scenario);
        let now = clock::timestamp_ms(&clock_ref);

        submit_intent(
            b"blob_data",
            now,
            now + 10_000,
            true,
            now + 86_400_000,
            false,
            0,
            false,
            vector::empty(),
            b"test",
            &clock_ref,
            ts::ctx(&mut scenario),
        );

        ts::return_shared(clock_ref);
    };

    // User revokes intent
    ts::next_tx(&mut scenario, USER);
    {
        let mut intent = ts::take_from_sender<Intent>(&scenario);
        let clock_ref = ts::take_shared<Clock>(&scenario);

        revoke_intent(&mut intent, &clock_ref, ts::ctx(&mut scenario));

        assert!(get_intent_status(&intent) == STATUS_REVOKED, 1);

        ts::return_to_sender(&scenario, intent);
        ts::return_shared(clock_ref);
    };

    // Cleanup
    ts::next_tx(&mut scenario, USER);
    {
        let clock = ts::take_shared<Clock>(&scenario);
        clock.destroy_for_testing();
    };

    ts::end(scenario);
}
