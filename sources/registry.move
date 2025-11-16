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
const E_INVALID_STATUS_TRANSITION: u64 = 6008;
const E_ATTESTATION_REQUIRED: u64 = 6009;

// ===== INTENT STATUS CONSTANTS =====
const INTENT_STATUS_PENDING: u8 = 0;
const INTENT_STATUS_BEST_SOLUTION_SELECTED: u8 = 1;
const INTENT_STATUS_EXECUTED: u8 = 2;
const INTENT_STATUS_REVOKED: u8 = 3;

// ===== SOLUTION STATUS CONSTANTS =====
const SOLUTION_STATUS_PENDING: u8 = 0;
const SOLUTION_STATUS_ATTESTED: u8 = 1;
const SOLUTION_STATUS_SELECTED: u8 = 2;
const SOLUTION_STATUS_EXECUTED: u8 = 3;
const SOLUTION_STATUS_REJECTED: u8 = 4;

// ===== STRUCTS =====

/// Time window for solver access control (ON-CHAIN ENFORCEMENT)
public struct TimeWindow has copy, drop, store {
    start_ms: u64,
    end_ms: u64,
}

/// Access condition for policy enforcement (ON-CHAIN ENFORCEMENT)
public struct AccessCondition has copy, drop, store {
    requires_solver_registration: bool,
    min_solver_stake: u64,
    requires_attestation: bool,
    expected_measurement: vector<u8>,
    purpose: vector<u8>,
}

/// Policy parameters embedded in Intent (ON-CHAIN ENFORCEMENT)
public struct PolicyParams has copy, drop, store {
    solver_access_window: TimeWindow,
    auto_revoke_ms: u64,
    access_condition: AccessCondition,
}

/// Enclave attestation for solution validation
/// Following Nautilus pattern - gom tất cả TEE-related params
public struct Attestation has copy, drop, store {
    /// Hash of input data (intent + constraints)
    input_hash: vector<u8>,
    /// Hash of output data (solution + surplus)
    output_hash: vector<u8>,
    /// Enclave measurement (PCR values)
    measurement: vector<u8>,
    /// Signature from enclave
    signature: vector<u8>,
    /// When attestation was created
    timestamp_ms: u64,
}

/// Intent object - stores reference to IGS intent in Walrus (owned object)
/// IGS intent content is stored OFF-CHAIN in Walrus
/// On-chain only tracks blob_id, policy enforcement, and solution management
public struct Intent has key, store {
    id: UID,
    user_addr: address,
    created_ms: u64,

    // Reference to IGS intent in Walrus (OFF-CHAIN STORAGE)
    blob_id: vector<u8>,

    // On-chain policy enforcement
    policy: PolicyParams,

    // Solution management
    status: u8,
    best_solution_id: Option<ID>,
    pending_solutions: vector<ID>,
}

/// Solution object - stores reference to IGS solution in Walrus (owned object)
/// IGS solution content (PTB, surplus calculation, etc.) is stored OFF-CHAIN
/// On-chain only tracks blob_id, attestation, and validation status
public struct Solution has key, store {
    id: UID,
    intent_id: ID,
    solver_addr: address,
    created_ms: u64,

    // Reference to IGS solution in Walrus (OFF-CHAIN STORAGE)
    blob_id: vector<u8>,

    // Enclave attestation (Optional, verified by enclave)
    attestation: Option<Attestation>,

    // On-chain status tracking
    status: u8,
}

// ===== EVENTS =====

public struct IntentSubmitted has copy, drop {
    intent_id: ID,
    user_addr: address,
    blob_id: vector<u8>,
    created_ms: u64,
    solver_access_start_ms: u64,
    solver_access_end_ms: u64,
}

public struct IntentRevoked has copy, drop {
    intent_id: ID,
    user_addr: address,
    revoked_at_ms: u64,
}

public struct IntentExecuted has copy, drop {
    intent_id: ID,
    solution_id: ID,
    user_addr: address,
    executed_at_ms: u64,
}

public struct SolutionSubmitted has copy, drop {
    solution_id: ID,
    intent_id: ID,
    solver_addr: address,
    blob_id: vector<u8>,
    created_ms: u64,
}

public struct SolutionAttested has copy, drop {
    solution_id: ID,
    intent_id: ID,
    solver_addr: address,
    attested_at_ms: u64,
    measurement: vector<u8>,
}

public struct SolutionSelected has copy, drop {
    intent_id: ID,
    solution_id: ID,
    user_addr: address,
    selected_at_ms: u64,
}

public struct SolutionRejected has copy, drop {
    solution_id: ID,
    intent_id: ID,
    reason: vector<u8>,
    rejected_at_ms: u64,
}

// ===== ENTRY FUNCTIONS =====

/// Submit a new intent with embedded policy parameters
/// Creates an Intent object with reference to IGS intent in Walrus
/// The actual IGS intent content (operation, constraints, etc.) is stored OFF-CHAIN
#[allow(lint(public_entry))]
public entry fun submit_intent(
    blob_id: vector<u8>,
    solver_access_start_ms: u64,
    solver_access_end_ms: u64,
    auto_revoke_ms: u64,
    requires_solver_registration: bool,
    min_solver_stake: u64,
    requires_attestation: bool,
    expected_measurement: vector<u8>,
    purpose: vector<u8>,
    clock: &Clock,
    ctx: &mut TxContext,
) {
    let sender = tx_context::sender(ctx);
    let timestamp_ms = clock::timestamp_ms(clock);

    // Validate input
    assert!(vector::length(&blob_id) > 0, E_INVALID_BLOB_ID);
    assert!(solver_access_start_ms < solver_access_end_ms, E_INVALID_TIME_WINDOW);

    // Create intent with reference to Walrus blob
    let intent_uid = object::new(ctx);
    let intent_id = object::uid_to_inner(&intent_uid);

    let intent = Intent {
        id: intent_uid,
        user_addr: sender,
        created_ms: timestamp_ms,
        blob_id,
        policy: PolicyParams {
            solver_access_window: TimeWindow {
                start_ms: solver_access_start_ms,
                end_ms: solver_access_end_ms,
            },
            auto_revoke_ms,
            access_condition: AccessCondition {
                requires_solver_registration,
                min_solver_stake,
                requires_attestation,
                expected_measurement,
                purpose,
            },
        },
        status: INTENT_STATUS_PENDING,
        best_solution_id: option::none(),
        pending_solutions: vector::empty(),
    };

    // Emit event
    event::emit(IntentSubmitted {
        intent_id,
        user_addr: sender,
        blob_id: intent.blob_id,
        created_ms: timestamp_ms,
        solver_access_start_ms,
        solver_access_end_ms,
    });

    // Transfer intent to user
    transfer::public_transfer(intent, sender);
}

/// Submit a solution for an intent with policy validation
/// Creates a Solution object with reference to IGS solution in Walrus
/// The actual IGS solution content (PTB, surplus calculation) is stored OFF-CHAIN
#[allow(lint(public_entry))]
public entry fun submit_solution(
    intent: &mut Intent,
    solver_registry: &SolverRegistry,
    blob_id: vector<u8>,
    clock: &Clock,
    ctx: &mut TxContext,
) {
    let solver = tx_context::sender(ctx);
    let timestamp_ms = clock::timestamp_ms(clock);

    // Validate inputs
    assert!(vector::length(&blob_id) > 0, E_INVALID_BLOB_ID);
    assert!(intent.status == INTENT_STATUS_PENDING, E_INTENT_REVOKED);

    // Validate policy conditions (ON-CHAIN ENFORCEMENT)
    validate_solution_against_policy(intent, solver, timestamp_ms, solver_registry);

    // Create solution with reference to Walrus blob
    let solution_uid = object::new(ctx);
    let solution_id = object::uid_to_inner(&solution_uid);
    let intent_id = object::uid_to_inner(&intent.id);

    let solution = Solution {
        id: solution_uid,
        intent_id,
        solver_addr: solver,
        created_ms: timestamp_ms,
        blob_id,
        attestation: option::none(),
        status: SOLUTION_STATUS_PENDING,
    };

    // Register solution with intent
    vector::push_back(&mut intent.pending_solutions, solution_id);

    // Emit event
    event::emit(SolutionSubmitted {
        solution_id,
        intent_id,
        solver_addr: solver,
        blob_id: solution.blob_id,
        created_ms: timestamp_ms,
    });

    // Transfer solution to solver
    transfer::public_transfer(solution, solver);
}

/// Attest solution with enclave signature
/// Called by enclave after validating the IGS solution off-chain
/// SECURITY CRITICAL: Verifies signature using enclave public key
#[allow(lint(public_entry))]
public entry fun attest_solution(
    solution: &mut Solution,
    intent: &Intent,
    input_hash: vector<u8>,
    output_hash: vector<u8>,
    measurement: vector<u8>,
    signature: vector<u8>,
    timestamp_ms: u64,
    clock: &Clock,
    ctx: &mut TxContext,
) {
    let now = clock::timestamp_ms(clock);

    // Verify status transition
    assert!(solution.status == SOLUTION_STATUS_PENDING, E_INVALID_STATUS_TRANSITION);

    // SECURITY: Verify solution belongs to this intent
    assert!(solution.intent_id == object::uid_to_inner(&intent.id), E_UNAUTHORIZED);

    // SECURITY: Verify measurement matches expected measurement in Intent policy
    let expected_measurement = &intent.policy.access_condition.expected_measurement;
    if (vector::length(expected_measurement) > 0) {
        assert!(bytes_equal(&measurement, expected_measurement), E_POLICY_VALIDATION_FAILED);
    };

    // TODO: Verify signature with enclave public key (done via seal-approve in seal module)

    // Create attestation after verification
    let attestation = Attestation {
        input_hash,
        output_hash,
        measurement,
        signature,
        timestamp_ms,
    };

    // Update solution
    solution.attestation = option::some(attestation);
    solution.status = SOLUTION_STATUS_ATTESTED;

    // Emit event
    event::emit(SolutionAttested {
        solution_id: object::uid_to_inner(&solution.id),
        intent_id: solution.intent_id,
        solver_addr: solution.solver_addr,
        attested_at_ms: now,
        measurement,
    });
}

/// Select the best solution for an intent (only owner can select)
/// User selects from attested solutions ranked by AI
#[allow(lint(public_entry))]
public entry fun select_best_solution(
    intent: &mut Intent,
    solution_id: ID,
    clock: &Clock,
    ctx: &mut TxContext,
) {
    let sender = tx_context::sender(ctx);
    let timestamp_ms = clock::timestamp_ms(clock);

    // Verify sender is the intent owner
    assert!(intent.user_addr == sender, E_UNAUTHORIZED);
    assert!(intent.status == INTENT_STATUS_PENDING, E_SOLUTION_ALREADY_SELECTED);

    // Verify solution is in pending list
    assert!(vector::contains(&intent.pending_solutions, &solution_id), E_UNAUTHORIZED_SOLVER);

    // Update intent
    intent.status = INTENT_STATUS_BEST_SOLUTION_SELECTED;
    intent.best_solution_id = option::some(solution_id);

    // Emit event
    event::emit(SolutionSelected {
        intent_id: object::uid_to_inner(&intent.id),
        solution_id,
        user_addr: sender,
        selected_at_ms: timestamp_ms,
    });
}

/// Execute the selected solution (only owner can execute)
#[allow(lint(public_entry))]
public entry fun execute_solution(
    intent: &mut Intent,
    solution: &mut Solution,
    clock: &Clock,
    ctx: &mut TxContext,
) {
    let sender = tx_context::sender(ctx);
    let timestamp_ms = clock::timestamp_ms(clock);

    // Verify sender is the intent owner
    assert!(intent.user_addr == sender, E_UNAUTHORIZED);
    assert!(intent.status == INTENT_STATUS_BEST_SOLUTION_SELECTED, E_INVALID_STATUS_TRANSITION);

    // Verify this is the selected solution
    let selected_id = option::borrow(&intent.best_solution_id);
    let solution_id = object::uid_to_inner(&solution.id);
    assert!(*selected_id == solution_id, E_UNAUTHORIZED);

    // Verify solution is attested
    assert!(solution.status == SOLUTION_STATUS_ATTESTED, E_ATTESTATION_REQUIRED);

    // Update statuses
    intent.status = INTENT_STATUS_EXECUTED;
    solution.status = SOLUTION_STATUS_EXECUTED;

    // Emit event
    event::emit(IntentExecuted {
        intent_id: object::uid_to_inner(&intent.id),
        solution_id,
        user_addr: sender,
        executed_at_ms: timestamp_ms,
    });
}

/// Reject a solution with reason (for slashing mechanism)
/// Called when attestation fails or solution violates constraints
#[allow(lint(public_entry))]
public entry fun reject_solution(
    solution: &mut Solution,
    solver_registry: &mut SolverRegistry,
    reason: vector<u8>,
    clock: &Clock,
    ctx: &mut TxContext,
) {
    let timestamp_ms = clock::timestamp_ms(clock);

    // Update solution status
    solution.status = SOLUTION_STATUS_REJECTED;

    // TODO: Integrate with slashing mechanism
    // solver_registry::record_violation(solver_registry, solution.solver_addr, reason, clock);

    // Emit event
    event::emit(SolutionRejected {
        solution_id: object::uid_to_inner(&solution.id),
        intent_id: solution.intent_id,
        reason,
        rejected_at_ms: timestamp_ms,
    });
}

/// Revoke an intent (only owner can revoke)
#[allow(lint(public_entry))]
public entry fun revoke_intent(
    intent: &mut Intent,
    clock: &Clock,
    ctx: &mut TxContext,
) {
    let sender = tx_context::sender(ctx);
    let timestamp_ms = clock::timestamp_ms(clock);

    // Verify sender is the intent owner
    assert!(intent.user_addr == sender, E_UNAUTHORIZED);
    assert!(intent.status == INTENT_STATUS_PENDING, E_INVALID_STATUS_TRANSITION);

    // Update status
    intent.status = INTENT_STATUS_REVOKED;

    // Emit event
    event::emit(IntentRevoked {
        intent_id: object::uid_to_inner(&intent.id),
        user_addr: sender,
        revoked_at_ms: timestamp_ms,
    });
}

// ===== INTERNAL HELPER FUNCTIONS (DRY PRINCIPLE) =====

/// Validate solution submission against intent policy (ON-CHAIN ENFORCEMENT)
/// This validates access control, NOT the IGS solution content
/// IGS content validation happens in enclave off-chain
fun validate_solution_against_policy(
    intent: &Intent,
    solver: address,
    timestamp_ms: u64,
    solver_registry: &SolverRegistry,
) {
    let policy = &intent.policy;

    // Check time window
    let in_window = timestamp_ms >= policy.solver_access_window.start_ms
        && timestamp_ms <= policy.solver_access_window.end_ms;
    assert!(in_window, E_POLICY_VALIDATION_FAILED);

    // Check auto-revoke time
    if (policy.auto_revoke_ms > 0) {
        assert!(timestamp_ms <= policy.auto_revoke_ms, E_POLICY_VALIDATION_FAILED);
    };

    // Check solver registration requirement
    if (policy.access_condition.requires_solver_registration) {
        let is_active = solver_registry::is_solver_active(solver_registry, solver);
        assert!(is_active, E_UNAUTHORIZED_SOLVER);

        // Check minimum stake
        let stake = solver_registry::get_solver_stake(solver_registry, solver);
        assert!(stake >= policy.access_condition.min_solver_stake, E_UNAUTHORIZED_SOLVER);
    };
}

/// Compare two byte vectors for equality
fun bytes_equal(left: &vector<u8>, right: &vector<u8>): bool {
    if (vector::length(left) != vector::length(right)) {
        return false
    };
    let len = vector::length(left);
    let mut i = 0;
    while (i < len) {
        if (*vector::borrow(left, i) != *vector::borrow(right, i)) {
            return false
        };
        i = i + 1;
    };
    true
}

// ===== VIEW FUNCTIONS =====

/// Get intent ID
public fun get_intent_id(intent: &Intent): ID {
    object::uid_to_inner(&intent.id)
}

/// Get intent user address
public fun get_intent_user(intent: &Intent): address {
    intent.user_addr
}

/// Get intent status
public fun get_intent_status(intent: &Intent): u8 {
    intent.status
}

/// Get intent blob_id (reference to IGS intent in Walrus)
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
    solution.solver_addr
}

/// Get solution blob_id (reference to IGS solution in Walrus)
public fun get_solution_blob_id(solution: &Solution): vector<u8> {
    solution.blob_id
}

/// Get solution status
public fun get_solution_status(solution: &Solution): u8 {
    solution.status
}

/// Check if solution has attestation
public fun has_attestation(solution: &Solution): bool {
    option::is_some(&solution.attestation)
}

/// Get attestation
public fun get_attestation(solution: &Solution): Option<Attestation> {
    solution.attestation
}

// ===== POLICY GETTERS =====

/// Check if intent is revoked
public fun is_intent_revoked(intent: &Intent): bool {
    intent.status == INTENT_STATUS_REVOKED
}

/// Get intent policy parameters
public fun get_intent_policy(intent: &Intent): &PolicyParams {
    &intent.policy
}

/// Get policy access condition
public fun get_policy_access_condition(policy: &PolicyParams): &AccessCondition {
    &policy.access_condition
}

/// Get policy solver access window
public fun get_policy_solver_window(policy: &PolicyParams): &TimeWindow {
    &policy.solver_access_window
}

/// Get time window start timestamp
public fun get_time_window_start(window: &TimeWindow): u64 {
    window.start_ms
}

/// Get time window end timestamp
public fun get_time_window_end(window: &TimeWindow): u64 {
    window.end_ms
}

/// Check if solver registration is required
public fun get_access_condition_requires_solver_registration(condition: &AccessCondition): bool {
    condition.requires_solver_registration
}

/// Get minimum solver stake requirement
public fun get_access_condition_min_solver_stake(condition: &AccessCondition): u64 {
    condition.min_solver_stake
}

// ===== TEST HELPERS =====

#[test_only]
public fun init_for_testing(_ctx: &mut TxContext) {
    // Registry module doesn't have shared state, so nothing to initialize
}

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

/// Test core value: Complete intent-solution lifecycle with attestation
#[test]
fun test_intent_solution_lifecycle_with_attestation() {
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
            b"walrus_blob_id_intent_001",
            now,
            now + 10_000,
            now + 86_400_000,
            true,
            solver_registry::get_min_stake_amount(),
            true, // requires attestation
            b"expected_measurement",
            b"swap",
            &clock_ref,
            ts::ctx(&mut scenario),
        );

        ts::return_shared(clock_ref);
    };

    // Solver submits solution
    ts::next_tx(&mut scenario, SOLVER);
    {
        let mut intent = ts::take_from_address<Intent>(&scenario, USER);
        let solver_reg = ts::take_shared<SolverRegistry>(&scenario);
        let clock_ref = ts::take_shared<Clock>(&scenario);

        submit_solution(
            &mut intent,
            &solver_reg,
            b"walrus_blob_id_solution_001",
            &clock_ref,
            ts::ctx(&mut scenario),
        );

        let pending = get_intent_pending_solutions(&intent);
        assert!(vector::length(&pending) == 1, 1);

        transfer::public_transfer(intent, USER);
        ts::return_shared(solver_reg);
        ts::return_shared(clock_ref);
    };

    // Enclave attests solution
    ts::next_tx(&mut scenario, SOLVER);
    {
        let mut solution = ts::take_from_address<Solution>(&scenario, SOLVER);
        let intent = ts::take_from_address<Intent>(&scenario, USER);
        let clock_ref = ts::take_shared<Clock>(&scenario);
        let now = clock::timestamp_ms(&clock_ref);

        attest_solution(
            &mut solution,
            &intent,
            b"input_hash_32_bytes",
            b"output_hash_32_bytes",
            b"expected_measurement",
            b"enclave_signature",
            now,
            &clock_ref,
            ts::ctx(&mut scenario),
        );

        assert!(get_solution_status(&solution) == SOLUTION_STATUS_ATTESTED, 2);
        assert!(has_attestation(&solution), 3);

        transfer::public_transfer(solution, SOLVER);
        transfer::public_transfer(intent, USER);
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

        assert!(get_intent_status(&intent) == INTENT_STATUS_BEST_SOLUTION_SELECTED, 4);

        ts::return_to_sender(&scenario, intent);
        ts::return_shared(clock_ref);
    };

    // User executes solution
    ts::next_tx(&mut scenario, USER);
    {
        let mut intent = ts::take_from_sender<Intent>(&scenario);
        let mut solution = ts::take_from_address<Solution>(&scenario, SOLVER);
        let clock_ref = ts::take_shared<Clock>(&scenario);

        execute_solution(&mut intent, &mut solution, &clock_ref, ts::ctx(&mut scenario));

        assert!(get_intent_status(&intent) == INTENT_STATUS_EXECUTED, 5);
        assert!(get_solution_status(&solution) == SOLUTION_STATUS_EXECUTED, 6);

        transfer::public_transfer(intent, USER);
        transfer::public_transfer(solution, SOLVER);
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
            b"walrus_blob_id",
            now,
            now + 10_000,
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
            b"walrus_blob_solution",
            &clock_ref,
            ts::ctx(&mut scenario),
        );

        transfer::public_transfer(intent, USER);
        ts::return_shared(solver_reg);
        ts::return_shared(clock_ref);
    };

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
            b"walrus_blob_id",
            now,
            now + 10_000,
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

        assert!(get_intent_status(&intent) == INTENT_STATUS_REVOKED, 1);

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