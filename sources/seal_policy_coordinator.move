module intenus::seal_policy_coordinator;

use intenus::registry::{Self, Intent, Solution, TimeWindow, AccessCondition};
use intenus::solver_registry;
use sui::clock::{Self, Clock};
use sui::event;
use sui::address;

// ===== ERRORS =====
const E_INTENT_REVOKED: u64 = 3001;
const E_UNAUTHORIZED: u64 = 3002;
const E_OUTSIDE_TIME_WINDOW: u64 = 3003;
const E_SOLVER_NOT_REGISTERED: u64 = 3004;
const E_INSUFFICIENT_STAKE: u64 = 3005;
const E_ATTESTATION_REQUIRED: u64 = 3006;
const E_NO_ENCLAVE_PK: u64 = 3007;

// ===== CONSTANTS =====
const ROLE_USER: u8 = 0;
const ROLE_SOLVER: u8 = 1;

// ===== STRUCTS =====

/// Enclave configuration for seal approval
/// Stores the public key of the trusted enclave that has blanket access
public struct EnclaveConfig has key {
    id: UID,
    /// Enclave's public key (ed25519)
    enclave_pk: vector<u8>,
    /// Admin address who can update the enclave_pk
    admin_addr: address,
}

// ===== EVENTS =====

public struct IntentAccessGranted has copy, drop {
    intent_id: ID,
    requester_addr: address,
    granted_at_ms: u64,
}

public struct SolutionAccessGranted has copy, drop {
    solution_id: ID,
    intent_id: ID,
    requester_addr: address,
    granted_at_ms: u64,
}

public struct EnclaveConfigUpdated has copy, drop {
    new_enclave_pk: vector<u8>,
    updated_at_ms: u64,
}

// ===== INITIALIZATION =====

fun init(ctx: &mut TxContext) {
    let config = EnclaveConfig {
        id: object::new(ctx),
        enclave_pk: vector::empty<u8>(),
        admin_addr: tx_context::sender(ctx),
    };
    transfer::share_object(config);
}

// ===== ADMIN FUNCTIONS =====

/// Update enclave public key
entry fun update_enclave_pk(
    config: &mut EnclaveConfig,
    new_enclave_pk: vector<u8>,
    clock: &Clock,
    ctx: &TxContext,
) {
    assert!(tx_context::sender(ctx) == config.admin_addr, E_UNAUTHORIZED);
    config.enclave_pk = new_enclave_pk;

    event::emit(EnclaveConfigUpdated {
        new_enclave_pk,
        updated_at_ms: clock::timestamp_ms(clock),
    });
}

// ===== SEAL APPROVE ENTRYPOINTS =====

/// Seal entry point to approve access to an Intent.
/// Following Nautilus pattern: approves if called by enclave public key.
/// Also checks standard access control (user and solver permissions).
entry fun seal_approve_intent(
    intent: &Intent,
    config: &EnclaveConfig,
    solver_registry_ref: &solver_registry::SolverRegistry,
    clock: &Clock,
    ctx: &TxContext,
) {
    let requester_addr = tx_context::sender(ctx);

    // Check if requester is the enclave (has blanket access)
    if (is_enclave_caller(requester_addr, config)) {
        event::emit(IntentAccessGranted {
            intent_id: object::id(intent),
            requester_addr,
            granted_at_ms: clock::timestamp_ms(clock),
        });
        return
    };

    // Check if intent is revoked
    assert!(!registry::is_intent_revoked(intent), E_INTENT_REVOKED);

    let policy = registry::get_intent_policy(intent);
    let access_condition = registry::get_policy_access_condition(policy);
    let solver_access_window = registry::get_policy_solver_window(policy);

    // Determine role
    let role = get_requester_role(solver_registry_ref, requester_addr);

    // Check authorization based on role
    let is_authorized = if (role == ROLE_USER && requester_addr == registry::get_intent_user(intent)) {
        // Intent owner has access
        true
    } else if (role == ROLE_SOLVER) {
        check_solver_access(
            requester_addr,
            solver_registry_ref,
            solver_access_window,
            access_condition,
            clock,
        )
    } else {
        false
    };

    assert!(is_authorized, E_UNAUTHORIZED);

    event::emit(IntentAccessGranted {
        intent_id: object::id(intent),
        requester_addr,
        granted_at_ms: clock::timestamp_ms(clock),
    });
}

/// Seal entry point to approve access to a Solution.
/// Following Nautilus pattern: approves if called by enclave public key.
/// Also checks if requester is the solution owner.
entry fun seal_approve_solution(
    solution: &Solution,
    config: &EnclaveConfig,
    clock: &Clock,
    ctx: &TxContext,
) {
    let requester_addr = tx_context::sender(ctx);

    // Check if requester is the enclave (has blanket access)
    if (is_enclave_caller(requester_addr, config)) {
        event::emit(SolutionAccessGranted {
            solution_id: object::id(solution),
            intent_id: registry::get_solution_intent_id(solution),
            requester_addr,
            granted_at_ms: clock::timestamp_ms(clock),
        });
        return
    };

    // Check if requester is the solution owner
    let is_authorized = requester_addr == registry::get_solution_solver(solution);
    assert!(is_authorized, E_UNAUTHORIZED);

    event::emit(SolutionAccessGranted {
        solution_id: object::id(solution),
        intent_id: registry::get_solution_intent_id(solution),
        requester_addr,
        granted_at_ms: clock::timestamp_ms(clock),
    });
}

// ===== INTERNAL HELPERS =====

/// Check if caller address matches enclave public key
/// Following Nautilus pattern: derive address from pk
fun is_enclave_caller(caller_addr: address, config: &EnclaveConfig): bool {
    if (vector::is_empty(&config.enclave_pk)) {
        return false
    };

    // Derive address from enclave public key (ed25519)
    // Same as Nautilus: blake2b_hash(flag || pk)
    let enclave_addr = pk_to_address(&config.enclave_pk);
    caller_addr.to_bytes() == enclave_addr
}

/// Convert public key to address (same as Nautilus pattern)
fun pk_to_address(pk: &vector<u8>): vector<u8> {
    use sui::hash::blake2b256;
    // Assume ed25519 flag (0x00) for enclave's ephemeral key
    let mut arr = vector[0u8];
    arr.append(*pk);
    blake2b256(&arr)
}

/// Determines the role of a given address
fun get_requester_role(
    solver_registry_ref: &solver_registry::SolverRegistry,
    requester_addr: address,
): u8 {
    if (option::is_some(&solver_registry::get_solver_profile(solver_registry_ref, requester_addr))) {
        // Registered solver
        ROLE_SOLVER
    } else {
        // Default to user
        ROLE_USER
    }
}

/// Check if solver has access based on time window and conditions
fun check_solver_access(
    solver_addr: address,
    solver_registry_ref: &solver_registry::SolverRegistry,
    solver_access_window: &TimeWindow,
    access_condition: &AccessCondition,
    clock: &Clock,
): bool {
    let now = clock::timestamp_ms(clock);

    // Check time window
    let start_ms = registry::get_time_window_start(solver_access_window);
    let end_ms = registry::get_time_window_end(solver_access_window);
    if (now < start_ms || now > end_ms) {
        return false
    };

    // Check solver registration if required
    let requires_registration = registry::get_access_condition_requires_solver_registration(access_condition);
    if (requires_registration) {
        if (!solver_registry::is_solver_active(solver_registry_ref, solver_addr)) {
            return false
        };

        // Check stake requirement
        let min_stake = registry::get_access_condition_min_solver_stake(access_condition);
        let solver_stake = solver_registry::get_solver_stake(solver_registry_ref, solver_addr);
        if (solver_stake < min_stake) {
            return false
        };

        // Check reputation requirement
        let min_reputation = registry::get_access_condition_min_solver_reputation_score(access_condition);
        if (min_reputation > 0) {
            let solver_reputation = solver_registry::get_solver_reputation(solver_registry_ref, solver_addr);
            if (solver_reputation < min_reputation) {
                return false
            };
        };
    };

    true
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
public fun init_for_testing(ctx: &mut tx_context::TxContext) {
    init(ctx);
}

/// Test seal approve with enclave public key
#[test]
fun test_seal_approve_intent_with_enclave() {
    let mut scenario = ts::begin(ADMIN);

    // Initialize modules
    solver_registry::init_for_testing(ts::ctx(&mut scenario));
    registry::init_for_testing(ts::ctx(&mut scenario));
    init(ts::ctx(&mut scenario));

    // Create and share Clock
    let clock = clock::create_for_testing(ts::ctx(&mut scenario));
    clock.share_for_testing();
    ts::next_tx(&mut scenario, ADMIN);

    // Set enclave public key and derive its address
    ts::next_tx(&mut scenario, ADMIN);
    let enclave_addr = {
        let mut config = ts::take_shared<EnclaveConfig>(&scenario);
        let clock_ref = ts::take_shared<Clock>(&scenario);

        let enclave_pk = x"5c38d3668c45ff891766ee99bd3522ae48d9771dc77e8a6ac9f0bde6c3a2ca48";
        update_enclave_pk(&mut config, enclave_pk, &clock_ref, ts::ctx(&mut scenario));
        let derived_addr = address::from_bytes(pk_to_address(&enclave_pk));

        ts::return_shared(config);
        ts::return_shared(clock_ref);
        derived_addr
    };

    // User submits intent
    ts::next_tx(&mut scenario, USER);
    {
        let clock_ref = ts::take_shared<Clock>(&scenario);
        let now = clock::timestamp_ms(&clock_ref);
        let fee_coin = coin::mint_for_testing<SUI>(1_000_000, ts::ctx(&mut scenario));

        registry::submit_intent(
            "intent_blob_001",
            now,
            now + 10_000,
            now + 86_400_000,
            true,
            solver_registry::get_min_stake_amount(),
            false,
            0, // min_solver_reputation_score
            fee_coin,
            &clock_ref,
            ts::ctx(&mut scenario),
        );

        ts::return_shared(clock_ref);
    };

    // Enclave should have blanket access
    ts::next_tx(&mut scenario, enclave_addr);
    {
        let intent = ts::take_from_address<Intent>(&scenario, USER);
        let config = ts::take_shared<EnclaveConfig>(&scenario);
        let solver_reg = ts::take_shared<solver_registry::SolverRegistry>(&scenario);
        let clock_ref = ts::take_shared<Clock>(&scenario);

        // This should succeed because enclave has blanket access
        seal_approve_intent(
            &intent,
            &config,
            &solver_reg,
            &clock_ref,
            ts::ctx(&mut scenario),
        );

        transfer::public_transfer(intent, USER);
        ts::return_shared(config);
        ts::return_shared(solver_reg);
        ts::return_shared(clock_ref);
    };

    // Clean up
    ts::next_tx(&mut scenario, ADMIN);
    {
        let clock = ts::take_shared<Clock>(&scenario);
        clock.destroy_for_testing();
    };

    ts::end(scenario);
}

/// Test seal approve for solution owner
#[test]
fun test_seal_approve_solution_by_owner() {
    let mut scenario = ts::begin(ADMIN);

    // Initialize modules
    solver_registry::init_for_testing(ts::ctx(&mut scenario));
    registry::init_for_testing(ts::ctx(&mut scenario));
    init(ts::ctx(&mut scenario));

    // Create and share Clock
    let clock = clock::create_for_testing(ts::ctx(&mut scenario));
    clock.share_for_testing();
    ts::next_tx(&mut scenario, ADMIN);

    // Register solver
    ts::next_tx(&mut scenario, SOLVER);
    {
        let mut solver_reg = ts::take_shared<solver_registry::SolverRegistry>(&scenario);
        let clock_ref = ts::take_shared<Clock>(&scenario);
        let stake_coin = coin::mint_for_testing<SUI>(
            solver_registry::get_min_stake_amount(),
            ts::ctx(&mut scenario),
        );
        solver_registry::register_solver(&mut solver_reg, stake_coin, &clock_ref, ts::ctx(&mut scenario));
        ts::return_shared(solver_reg);
        ts::return_shared(clock_ref);
    };

    // User submits intent
    ts::next_tx(&mut scenario, USER);
    {
        let clock_ref = ts::take_shared<Clock>(&scenario);
        let now = clock::timestamp_ms(&clock_ref);
        let fee_coin = coin::mint_for_testing<SUI>(1_000_000, ts::ctx(&mut scenario));

        registry::submit_intent(
            "intent_blob_001",
            now,
            now + 10_000,
            now + 86_400_000,
            true,
            solver_registry::get_min_stake_amount(),
            false,
            0, // min_solver_reputation_score
            fee_coin,
            &clock_ref,
            ts::ctx(&mut scenario),
        );

        ts::return_shared(clock_ref);
    };

    // Solver submits solution
    ts::next_tx(&mut scenario, SOLVER);
    {
        let mut intent = ts::take_from_address<Intent>(&scenario, USER);
        let solver_reg = ts::take_shared<solver_registry::SolverRegistry>(&scenario);
        let clock_ref = ts::take_shared<Clock>(&scenario);

        registry::submit_solution(
            &mut intent,
            &solver_reg,
            "solution_blob_001",
            &clock_ref,
            ts::ctx(&mut scenario),
        );

        transfer::public_transfer(intent, USER);
        ts::return_shared(solver_reg);
        ts::return_shared(clock_ref);
    };

    // Solver should have access to their own solution
    ts::next_tx(&mut scenario, SOLVER);
    {
        let solution = ts::take_from_sender<Solution>(&scenario);
        let config = ts::take_shared<EnclaveConfig>(&scenario);
        let clock_ref = ts::take_shared<Clock>(&scenario);

        seal_approve_solution(&solution, &config, &clock_ref, ts::ctx(&mut scenario));

        transfer::public_transfer(solution, SOLVER);
        ts::return_shared(config);
        ts::return_shared(clock_ref);
    };

    // Clean up
    ts::next_tx(&mut scenario, ADMIN);
    {
        let clock = ts::take_shared<Clock>(&scenario);
        clock.destroy_for_testing();
    };

    ts::end(scenario);
}
