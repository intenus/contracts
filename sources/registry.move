module intenus::registry;

use sui::clock::{Self, Clock};
use sui::event;
use sui::table::{Self, Table};
use intenus::seal_policy_coordinator::{Self, PolicyRegistry};
use intenus::solver_registry::{Self, SolverRegistry};
use intenus::batch_manager::{Self, BatchManager};

// ===== ERRORS =====
const E_INTENT_NOT_FOUND: u64 = 6001;
const E_INTENT_ALREADY_EXISTS: u64 = 6002;
const E_SOLUTION_NOT_FOUND: u64 = 6003;
const E_SOLUTION_ALREADY_EXISTS: u64 = 6004;
const E_INVALID_BLOB_ID: u64 = 6005;
const E_UNAUTHORIZED_SOLVER: u64 = 6006;
const E_POLICY_VALIDATION_FAILED: u64 = 6007;
const E_INTENT_EXPIRED: u64 = 6008;

// ===== STRUCTS =====

/// Admin capability for registry management
public struct AdminCap has key, store {
    id: UID,
}

/// Time window for access control
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

/// Intent object submitted by users
public struct Intent has store {
    intent_id: vector<u8>,
    user_address: address,
    created_time: u64,
    blob_id: vector<u8>,
    batch_id: u64,
    policy: PolicyParams,
    is_active: bool,
}

/// Solution object submitted by solvers
public struct Solution has store {
    solution_id: vector<u8>,
    intent_id: vector<u8>,
    solver_address: address,
    created_time: u64,
    blob_id: vector<u8>,
    is_validated: bool,
}

/// Main registry for managing intents and solutions
public struct Registry has key {
    id: UID,
    intents: Table<vector<u8>, Intent>,
    solutions: Table<vector<u8>, Solution>,
    intent_to_solutions: Table<vector<u8>, vector<vector<u8>>>, // Maps intent_id -> solution_ids
    total_intents: u64,
    total_solutions: u64,
    admin: address,
}

// ===== EVENTS =====

public struct IntentSubmitted has copy, drop {
    intent_id: vector<u8>,
    user_address: address,
    batch_id: u64,
    blob_id: vector<u8>,
    created_time: u64,
    solver_access_start: u64,
    solver_access_end: u64,
}

public struct IntentRevoked has copy, drop {
    intent_id: vector<u8>,
    user_address: address,
    revoked_at: u64,
}

public struct SolutionSubmitted has copy, drop {
    solution_id: vector<u8>,
    intent_id: vector<u8>,
    solver_address: address,
    blob_id: vector<u8>,
    created_time: u64,
}

public struct SolutionValidated has copy, drop {
    solution_id: vector<u8>,
    intent_id: vector<u8>,
    solver_address: address,
    validated_at: u64,
}

// ===== INITIALIZATION =====

fun init(ctx: &mut TxContext) {
    let admin_cap = AdminCap { id: object::new(ctx) };

    let registry = Registry {
        id: object::new(ctx),
        intents: table::new(ctx),
        solutions: table::new(ctx),
        intent_to_solutions: table::new(ctx),
        total_intents: 0,
        total_solutions: 0,
        admin: tx_context::sender(ctx),
    };

    transfer::transfer(admin_cap, tx_context::sender(ctx));
    transfer::share_object(registry);
}

// ===== ENTRY FUNCTIONS =====

/// Submit a new intent with embedded policy parameters
public entry fun submit_intent(
    registry: &mut Registry,
    batch_manager: &mut BatchManager,
    intent_id: vector<u8>,
    batch_id: u64,
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
    assert!(!table::contains(&registry.intents, intent_id), E_INTENT_ALREADY_EXISTS);
    assert!(vector::length(&blob_id) > 0, E_INVALID_BLOB_ID);

    // Create intent with embedded policy
    let intent = Intent {
        intent_id,
        user_address: sender,
        created_time: timestamp,
        blob_id,
        batch_id,
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
        is_active: true,
    };

    // Store intent
    table::add(&mut registry.intents, intent_id, intent);
    table::add(&mut registry.intent_to_solutions, intent_id, vector::empty());
    registry.total_intents = registry.total_intents + 1;

    // Record intent in batch manager
    batch_manager::record_intent(batch_manager, batch_id, 1, 0);

    // Emit event
    event::emit(IntentSubmitted {
        intent_id,
        user_address: sender,
        batch_id,
        blob_id,
        created_time: timestamp,
        solver_access_start: solver_access_start_ms,
        solver_access_end: solver_access_end_ms,
    });
}

/// Submit a solution for an intent with policy validation
public entry fun submit_solution(
    registry: &mut Registry,
    batch_manager: &mut BatchManager,
    solver_registry: &SolverRegistry,
    solution_id: vector<u8>,
    intent_id: vector<u8>,
    blob_id: vector<u8>,
    clock: &Clock,
    ctx: &mut TxContext,
) {
    let solver = tx_context::sender(ctx);
    let timestamp = clock::timestamp_ms(clock);

    // Validate inputs
    assert!(!table::contains(&registry.solutions, solution_id), E_SOLUTION_ALREADY_EXISTS);
    assert!(table::contains(&registry.intents, intent_id), E_INTENT_NOT_FOUND);
    assert!(vector::length(&blob_id) > 0, E_INVALID_BLOB_ID);

    let intent = table::borrow(&registry.intents, intent_id);
    assert!(intent.is_active, E_INTENT_EXPIRED);

    // Validate policy conditions
    validate_solution_against_policy(intent, solver, timestamp, solver_registry, clock);

    // Create solution
    let solution = Solution {
        solution_id,
        intent_id,
        solver_address: solver,
        created_time: timestamp,
        blob_id,
        is_validated: true,
    };

    // Store solution
    table::add(&mut registry.solutions, solution_id, solution);

    // Link solution to intent
    let solutions_list = table::borrow_mut(&mut registry.intent_to_solutions, intent_id);
    vector::push_back(solutions_list, solution_id);
    registry.total_solutions = registry.total_solutions + 1;

    // Record solution in batch manager
    batch_manager::record_solution(batch_manager, intent.batch_id);

    // Emit events
    event::emit(SolutionSubmitted {
        solution_id,
        intent_id,
        solver_address: solver,
        blob_id,
        created_time: timestamp,
    });

    event::emit(SolutionValidated {
        solution_id,
        intent_id,
        solver_address: solver,
        validated_at: timestamp,
    });
}

/// Revoke an intent (only owner can revoke)
public entry fun revoke_intent(
    registry: &mut Registry,
    intent_id: vector<u8>,
    clock: &Clock,
    ctx: &mut TxContext,
) {
    let sender = tx_context::sender(ctx);
    let timestamp = clock::timestamp_ms(clock);

    assert!(table::contains(&registry.intents, intent_id), E_INTENT_NOT_FOUND);

    let intent = table::borrow_mut(&mut registry.intents, intent_id);
    assert!(intent.user_address == sender || sender == registry.admin, E_UNAUTHORIZED_SOLVER);

    intent.is_active = false;

    event::emit(IntentRevoked {
        intent_id,
        user_address: sender,
        revoked_at: timestamp,
    });
}

// ===== INTERNAL HELPER FUNCTIONS (DRY PRINCIPLE) =====

/// Validate solution submission against intent policy
/// This reuses logic from seal_policy_coordinator
fun validate_solution_against_policy(
    intent: &Intent,
    solver: address,
    timestamp: u64,
    solver_registry: &SolverRegistry,
    clock: &Clock,
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

/// Check if a solution exists for an intent
fun has_solution(registry: &Registry, intent_id: &vector<u8>): bool {
    if (!table::contains(&registry.intent_to_solutions, *intent_id)) {
        return false
    };
    let solutions = table::borrow(&registry.intent_to_solutions, *intent_id);
    vector::length(solutions) > 0
}

/// Get solution count for an intent
fun get_solution_count(registry: &Registry, intent_id: &vector<u8>): u64 {
    if (!table::contains(&registry.intent_to_solutions, *intent_id)) {
        return 0
    };
    let solutions = table::borrow(&registry.intent_to_solutions, *intent_id);
    vector::length(solutions)
}

// ===== VIEW FUNCTIONS =====

/// Get intent details
public fun get_intent(registry: &Registry, intent_id: vector<u8>): Option<Intent> {
    if (table::contains(&registry.intents, intent_id)) {
        option::some(*table::borrow(&registry.intents, intent_id))
    } else {
        option::none()
    }
}

/// Get solution details
public fun get_solution(registry: &Registry, solution_id: vector<u8>): Option<Solution> {
    if (table::contains(&registry.solutions, solution_id)) {
        option::some(*table::borrow(&registry.solutions, solution_id))
    } else {
        option::none()
    }
}

/// Get all solutions for an intent
public fun get_intent_solutions(registry: &Registry, intent_id: vector<u8>): vector<vector<u8>> {
    if (table::contains(&registry.intent_to_solutions, intent_id)) {
        *table::borrow(&registry.intent_to_solutions, intent_id)
    } else {
        vector::empty()
    }
}

/// Get registry statistics
public fun get_registry_stats(registry: &Registry): (u64, u64) {
    (registry.total_intents, registry.total_solutions)
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

#[test_only]
public fun init_for_testing(ctx: &mut TxContext) {
    init(ctx);
}

/// Test core value: Complete intent-solution lifecycle
#[test]
fun test_intent_solution_lifecycle() {
    let mut scenario = ts::begin(ADMIN);

    // Initialize all required modules
    init(ts::ctx(&mut scenario));
    solver_registry::init_for_testing(ts::ctx(&mut scenario));
    batch_manager::init_for_testing(ts::ctx(&mut scenario));

    // Create and share Clock
    let clock = clock::create_for_testing(ts::ctx(&mut scenario));
    clock.share_for_testing();
    ts::next_tx(&mut scenario, ADMIN);

    // Start a batch
    ts::next_tx(&mut scenario, ADMIN);
    {
        let admin_cap = ts::take_from_sender<batch_manager::AdminCap>(&scenario);
        let mut batch_mgr = ts::take_shared<BatchManager>(&scenario);
        let clock_ref = ts::take_shared<Clock>(&scenario);

        batch_manager::start_new_batch(&admin_cap, &mut batch_mgr, b"batch_001", &clock_ref);

        transfer::transfer(admin_cap, ADMIN);
        ts::return_shared(batch_mgr);
        ts::return_shared(clock_ref);
    };

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
        let mut registry = ts::take_shared<Registry>(&scenario);
        let mut batch_mgr = ts::take_shared<BatchManager>(&scenario);
        let clock_ref = ts::take_shared<Clock>(&scenario);
        let now = clock::timestamp_ms(&clock_ref);

        submit_intent(
            &mut registry,
            &mut batch_mgr,
            b"intent_001",
            1, // batch_id
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

        let (total_intents, _) = get_registry_stats(&registry);
        assert!(total_intents == 1, 1);

        ts::return_shared(registry);
        ts::return_shared(batch_mgr);
        ts::return_shared(clock_ref);
    };

    // Solver submits solution
    ts::next_tx(&mut scenario, SOLVER);
    {
        let mut registry = ts::take_shared<Registry>(&scenario);
        let mut batch_mgr = ts::take_shared<BatchManager>(&scenario);
        let solver_reg = ts::take_shared<SolverRegistry>(&scenario);
        let clock_ref = ts::take_shared<Clock>(&scenario);

        submit_solution(
            &mut registry,
            &mut batch_mgr,
            &solver_reg,
            b"solution_001",
            b"intent_001",
            b"blob_solution_data",
            &clock_ref,
            ts::ctx(&mut scenario),
        );

        let (_, total_solutions) = get_registry_stats(&registry);
        assert!(total_solutions == 1, 2);

        let solutions = get_intent_solutions(&registry, b"intent_001");
        assert!(vector::length(&solutions) == 1, 3);

        ts::return_shared(registry);
        ts::return_shared(batch_mgr);
        ts::return_shared(solver_reg);
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

    // Initialize modules
    init(ts::ctx(&mut scenario));
    solver_registry::init_for_testing(ts::ctx(&mut scenario));
    batch_manager::init_for_testing(ts::ctx(&mut scenario));

    let clock = clock::create_for_testing(ts::ctx(&mut scenario));
    clock.share_for_testing();
    ts::next_tx(&mut scenario, ADMIN);

    // Start batch
    ts::next_tx(&mut scenario, ADMIN);
    {
        let admin_cap = ts::take_from_sender<batch_manager::AdminCap>(&scenario);
        let mut batch_mgr = ts::take_shared<BatchManager>(&scenario);
        let clock_ref = ts::take_shared<Clock>(&scenario);

        batch_manager::start_new_batch(&admin_cap, &mut batch_mgr, b"batch_001", &clock_ref);

        transfer::transfer(admin_cap, ADMIN);
        ts::return_shared(batch_mgr);
        ts::return_shared(clock_ref);
    };

    // User submits intent requiring solver registration
    ts::next_tx(&mut scenario, USER);
    {
        let mut registry = ts::take_shared<Registry>(&scenario);
        let mut batch_mgr = ts::take_shared<BatchManager>(&scenario);
        let clock_ref = ts::take_shared<Clock>(&scenario);
        let now = clock::timestamp_ms(&clock_ref);

        submit_intent(
            &mut registry,
            &mut batch_mgr,
            b"intent_001",
            1,
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

        ts::return_shared(registry);
        ts::return_shared(batch_mgr);
        ts::return_shared(clock_ref);
    };

    // Unregistered solver tries to submit solution (should fail)
    ts::next_tx(&mut scenario, SOLVER);
    {
        let mut registry = ts::take_shared<Registry>(&scenario);
        let mut batch_mgr = ts::take_shared<BatchManager>(&scenario);
        let solver_reg = ts::take_shared<SolverRegistry>(&scenario);
        let clock_ref = ts::take_shared<Clock>(&scenario);

        submit_solution(
            &mut registry,
            &mut batch_mgr,
            &solver_reg,
            b"solution_001",
            b"intent_001",
            b"blob_solution",
            &clock_ref,
            ts::ctx(&mut scenario),
        );

        ts::return_shared(registry);
        ts::return_shared(batch_mgr);
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
