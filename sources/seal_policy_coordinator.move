module intenus::seal_policy_coordinator;

use intenus::solver_registry;
use sui::clock::{Self, Clock};
use sui::event;
use sui::table::{Self, Table};

// ===== ERRORS =====
const E_POLICY_EXISTS: u64 = 3001;
const E_POLICY_NOT_FOUND: u64 = 3002;
const E_INVALID_TIME_WINDOW: u64 = 3003;
const E_UNAUTHORIZED: u64 = 3004;
const E_POLICY_REVOKED: u64 = 3005;

// ===== CONSTANTS =====
const POLICY_TYPE_INTENT: u8 = 0;
const POLICY_TYPE_STRATEGY: u8 = 1;
const POLICY_TYPE_USER_HISTORY: u8 = 2;

const ROLE_USER: u8 = 0;
const ROLE_SOLVER: u8 = 1;
const ROLE_ROUTER: u8 = 2;
const ROLE_ADMIN: u8 = 3;

// ===== STRUCTS =====

/// Capability for administrative overrides.
public struct AdminCap has key, store {
    id: UID,
}

public struct TimeWindow has copy, drop, store {
    start_ms: u64,
    end_ms: u64,
}

public struct AccessCondition has copy, drop, store {
    requires_solver_registration: bool,
    min_solver_stake: u64,
    requires_tee_attestation: bool,
    expected_measurement: vector<u8>,
    purpose: vector<u8>,
}

public struct IntentPolicy has store {
    policy_id: vector<u8>,
    batch_id: u64,
    user_address: address,
    solver_access_window: TimeWindow,
    router_access_enabled: bool,
    auto_revoke_time: u64,
    is_revoked: bool,
    access_condition: AccessCondition,
}

public struct SolverStrategyPolicy has store {
    policy_id: vector<u8>,
    solver_address: address,
    router_can_access: bool,
    admin_unlock_time: u64,
    is_public: bool,
    is_revoked: bool,
    access_condition: AccessCondition,
}

public struct UserHistoryPolicy has store {
    policy_id: vector<u8>,
    user_address: address,
    router_access_level: u8,
    user_can_revoke: bool,
    last_updated: u64,
    is_revoked: bool,
    access_condition: AccessCondition,
}

public struct PolicyRegistry has key {
    id: UID,
    intent_policies: Table<vector<u8>, IntentPolicy>,
    strategy_policies: Table<vector<u8>, SolverStrategyPolicy>,
    history_policies: Table<vector<u8>, UserHistoryPolicy>,
    admin: address,
}

// ===== EVENTS =====

public struct PolicyCreated has copy, drop {
    policy_id: vector<u8>,
    policy_type: u8,
    owner: address,
}

public struct PolicyRevoked has copy, drop {
    policy_id: vector<u8>,
    policy_type: u8,
    revoked_by: address,
}

public struct PolicyAutoRevoked has copy, drop {
    policy_id: vector<u8>,
    policy_type: u8,
    timestamp: u64,
}

// ===== INITIALIZATION =====

fun init(ctx: &mut TxContext) {
    let admin_cap = AdminCap { id: object::new(ctx) };

    let registry = PolicyRegistry {
        id: object::new(ctx),
        intent_policies: table::new(ctx),
        strategy_policies: table::new(ctx),
        history_policies: table::new(ctx),
        admin: tx_context::sender(ctx),
    };

    transfer::transfer(admin_cap, tx_context::sender(ctx));
    transfer::share_object(registry);
}

// ===== SEAL APPROVE ENTRYPOINTS =====

/// Seal entry point to approve access to an Intent.
/// This is a read-only function that aborts if access is denied.
#[allow(lint(public_entry))]
public entry fun seal_approve_intent(
    id: vector<u8>,
    registry: &PolicyRegistry,
    solver_registry_ref: &solver_registry::SolverRegistry,
    clock: &Clock,
    ctx: &TxContext,
) {
    let policy_id = id;
    let requester = tx_context::sender(ctx);

    assert!(table::contains(&registry.intent_policies, policy_id), E_POLICY_NOT_FOUND);
    let policy = table::borrow(&registry.intent_policies, policy_id);
    assert!(!policy.is_revoked, E_POLICY_REVOKED);

    let now = clock::timestamp_ms(clock);
    assert!(policy.auto_revoke_time == 0 || now <= policy.auto_revoke_time, E_POLICY_REVOKED);

    let role = get_requester_role(registry, solver_registry_ref, requester);

    let is_authorized = if (
        policy.access_condition.requires_solver_registration && role != ROLE_SOLVER && role != ROLE_ADMIN
    ) {
        // If solver is required, and requester is neither solver nor admin, deny immediately.
        false
    } else if (role == ROLE_ADMIN) {
        true // Admin has blanket access
    } else if (requester == policy.user_address && role == ROLE_USER) {
        // Owner can access only if they are acting as a USER and solver is not required.
        // If a solver is required, this path is bypassed by the check above.
        true
    } else if (role == ROLE_SOLVER) {
        // Check time window
        let in_window =
            now >= policy.solver_access_window.start_ms && now <= policy.solver_access_window.end_ms;
        if (!in_window) { false } else {
            // Check solver status if required
            if (!policy.access_condition.requires_solver_registration) { true } else {
                let is_active = solver_registry::is_solver_active(solver_registry_ref, requester);
                let stake = solver_registry::get_solver_stake(solver_registry_ref, requester);
                is_active && stake >= policy.access_condition.min_solver_stake
            }
        }
    } else if (role == ROLE_ROUTER) {
        policy.router_access_enabled
        // NOTE: TEE attestation is verified off-chain by Seal Key Server before calling this.
    } else {
        false
    };

    assert!(is_authorized, E_UNAUTHORIZED);
}

/// Seal entry point to approve access to a Solver's Strategy.
/// This is a read-only function that aborts if access is denied.
#[allow(lint(public_entry))]
public entry fun seal_approve_strategy(
    id: vector<u8>,
    registry: &PolicyRegistry,
    solver_registry_ref: &solver_registry::SolverRegistry,
    clock: &Clock,
    ctx: &TxContext,
) {
    let policy_id = id;
    let requester = tx_context::sender(ctx);

    assert!(table::contains(&registry.strategy_policies, policy_id), E_POLICY_NOT_FOUND);
    let policy = table::borrow(&registry.strategy_policies, policy_id);
    assert!(!policy.is_revoked, E_POLICY_REVOKED);

    let role = get_requester_role(registry, solver_registry_ref, requester);

    let is_authorized = if (policy.is_public) {
        true
    } else if (role == ROLE_SOLVER && requester == policy.solver_address) {
        true // Owner can always access
    } else if (role == ROLE_ADMIN && clock::timestamp_ms(clock) >= policy.admin_unlock_time) {
        true // Admin can access after unlock time
    } else if (role == ROLE_ROUTER && policy.router_can_access) {
        true // Router access if enabled
    } else {
        false
    };

    assert!(is_authorized, E_UNAUTHORIZED);
}

/// Seal entry point to approve access to User History data.
/// This is a read-only function that aborts if access is denied.
#[allow(lint(public_entry))]
public entry fun seal_approve_history(
    id: vector<u8>,
    registry: &PolicyRegistry,
    solver_registry_ref: &solver_registry::SolverRegistry,
    ctx: &TxContext,
) {
    let policy_id = id;
    let requester = tx_context::sender(ctx);

    assert!(table::contains(&registry.history_policies, policy_id), E_POLICY_NOT_FOUND);
    let policy = table::borrow(&registry.history_policies, policy_id);
    assert!(!policy.is_revoked, E_POLICY_REVOKED);

    let role = get_requester_role(registry, solver_registry_ref, requester);

    let is_authorized = if (role == ROLE_USER && requester == policy.user_address) {
        true
    } else if (role == ROLE_ROUTER && policy.router_access_level > 0) {
        true
    } else {
        false
    };

    assert!(is_authorized, E_UNAUTHORIZED);
}

// ===== ENTRY FUNCTIONS =====

/// Create intent policy for a batch window.
public fun create_intent_policy(
    registry: &mut PolicyRegistry,
    policy_id: vector<u8>,
    batch_id: u64,
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
    assert!(!table::contains(&registry.intent_policies, policy_id), E_POLICY_EXISTS);
    assert!(solver_access_start_ms < solver_access_end_ms, E_INVALID_TIME_WINDOW);

    let now = clock::timestamp_ms(clock);
    let policy = IntentPolicy {
        policy_id,
        batch_id,
        user_address: sender,
        solver_access_window: TimeWindow {
            start_ms: solver_access_start_ms,
            end_ms: solver_access_end_ms,
        },
        router_access_enabled,
        auto_revoke_time,
        is_revoked: auto_revoke_time > 0 && now > auto_revoke_time,
        access_condition: AccessCondition {
            requires_solver_registration,
            min_solver_stake,
            requires_tee_attestation,
            expected_measurement,
            purpose,
        },
    };

    table::add(&mut registry.intent_policies, policy_id, policy);

    event::emit(PolicyCreated {
        policy_id,
        policy_type: POLICY_TYPE_INTENT,
        owner: sender,
    });
}

/// Create solver strategy policy protecting solver strategies.
public fun create_solver_strategy_policy(
    registry: &mut PolicyRegistry,
    policy_id: vector<u8>,
    router_can_access: bool,
    admin_unlock_time: u64,
    is_public: bool,
    // TEE related fields are part of AccessCondition
    requires_tee_attestation: bool,
    expected_measurement: vector<u8>,
    purpose: vector<u8>,
    ctx: &mut TxContext,
) {
    let sender = tx_context::sender(ctx);
    assert!(!table::contains(&registry.strategy_policies, policy_id), E_POLICY_EXISTS);

    let policy = SolverStrategyPolicy {
        policy_id,
        solver_address: sender,
        router_can_access: router_can_access && !is_public,
        admin_unlock_time,
        is_public,
        is_revoked: false,
        access_condition: AccessCondition {
            requires_solver_registration: false,
            min_solver_stake: 0,
            requires_tee_attestation,
            expected_measurement,
            purpose,
        },
    };

    table::add(&mut registry.strategy_policies, policy_id, policy);

    event::emit(PolicyCreated {
        policy_id,
        policy_type: POLICY_TYPE_STRATEGY,
        owner: sender,
    });
}

/// Create user history policy controlling router data access.
public fun create_user_history_policy(
    registry: &mut PolicyRegistry,
    policy_id: vector<u8>,
    router_access_level: u8,
    user_can_revoke: bool,
    // TEE related fields are part of AccessCondition
    requires_tee_attestation: bool,
    expected_measurement: vector<u8>,
    purpose: vector<u8>,
    clock: &Clock,
    ctx: &mut TxContext,
) {
    let sender = tx_context::sender(ctx);
    assert!(!table::contains(&registry.history_policies, policy_id), E_POLICY_EXISTS);

    let policy = UserHistoryPolicy {
        policy_id,
        user_address: sender,
        router_access_level,
        user_can_revoke,
        last_updated: clock::timestamp_ms(clock),
        is_revoked: false,
        access_condition: AccessCondition {
            requires_solver_registration: false,
            min_solver_stake: 0,
            requires_tee_attestation,
            expected_measurement,
            purpose,
        },
    };

    table::add(&mut registry.history_policies, policy_id, policy);

    event::emit(PolicyCreated {
        policy_id,
        policy_type: POLICY_TYPE_USER_HISTORY,
        owner: sender,
    });
}

/// Revoke policy by owner or admin.
public fun revoke_policy(
    registry: &mut PolicyRegistry,
    policy_type: u8,
    policy_id: vector<u8>,
    ctx: &mut TxContext,
) {
    let caller = tx_context::sender(ctx);
    if (policy_type == POLICY_TYPE_INTENT) {
        revoke_intent_policy(registry, &policy_id, caller);
    } else if (policy_type == POLICY_TYPE_STRATEGY) {
        revoke_strategy_policy(registry, &policy_id, caller);
    } else {
        revoke_history_policy(registry, &policy_id, caller);
    };
}

/// Auto revoke expired policies supplied by backend batch.
public fun auto_revoke_expired(
    registry: &mut PolicyRegistry,
    policy_type: u8,
    policy_ids: vector<vector<u8>>,
    clock: &Clock,
) {
    let now = clock::timestamp_ms(clock);
    let len = vector::length(&policy_ids);
    let mut i = 0;
    while (i < len) {
        let policy_id_ref = vector::borrow(&policy_ids, i);
        if (policy_type == POLICY_TYPE_INTENT) {
            auto_revoke_intent(registry, policy_id_ref, now);
        } else if (policy_type == POLICY_TYPE_STRATEGY) {
            auto_revoke_strategy(registry, policy_id_ref, now);
        } else {
            auto_revoke_history(registry, policy_id_ref, now);
        };
        i = i + 1;
    };
}

// ===== VIEW FUNCTIONS =====
// The `check_access` function is now replaced by `seal_approve_*` entry functions.

// ===== INTERNAL HELPERS =====

/// Determines the role of a given address.
fun get_requester_role(
    registry: &PolicyRegistry,
    solver_registry_ref: &solver_registry::SolverRegistry,
    requester: address,
): u8 {
    if (requester == registry.admin) {
        ROLE_ADMIN
    } else if (
        option::is_some(&solver_registry::get_solver_profile(solver_registry_ref, requester))
    ) {
        // We assume a "router" is also a registered solver with a specific designation,
        // but for this access control module, we'll treat any solver as ROLE_SOLVER.
        // The distinction between a regular solver and a router can be handled by TEE attestation checks.
        ROLE_SOLVER
    } else {
        // Default to user if not an admin or a known solver.
        // Specific user permissions are checked against the policy owner field.
        ROLE_USER
    }
}

fun revoke_intent_policy(registry: &mut PolicyRegistry, policy_id: &vector<u8>, caller: address) {
    assert!(table::contains(&registry.intent_policies, *policy_id), E_POLICY_NOT_FOUND);
    let policy = table::borrow_mut(&mut registry.intent_policies, *policy_id);
    assert!(!policy.is_revoked, E_POLICY_REVOKED);
    assert!(caller == policy.user_address || caller == registry.admin, E_UNAUTHORIZED);
    policy.is_revoked = true;

    event::emit(PolicyRevoked {
        policy_id: policy.policy_id,
        policy_type: POLICY_TYPE_INTENT,
        revoked_by: caller,
    });
}

fun revoke_strategy_policy(registry: &mut PolicyRegistry, policy_id: &vector<u8>, caller: address) {
    assert!(table::contains(&registry.strategy_policies, *policy_id), E_POLICY_NOT_FOUND);
    let policy = table::borrow_mut(&mut registry.strategy_policies, *policy_id);
    assert!(!policy.is_revoked, E_POLICY_REVOKED);
    assert!(caller == policy.solver_address || caller == registry.admin, E_UNAUTHORIZED);
    policy.is_revoked = true;

    event::emit(PolicyRevoked {
        policy_id: policy.policy_id,
        policy_type: POLICY_TYPE_STRATEGY,
        revoked_by: caller,
    });
}

fun revoke_history_policy(registry: &mut PolicyRegistry, policy_id: &vector<u8>, caller: address) {
    assert!(table::contains(&registry.history_policies, *policy_id), E_POLICY_NOT_FOUND);
    let policy = table::borrow_mut(&mut registry.history_policies, *policy_id);
    assert!(!policy.is_revoked, E_POLICY_REVOKED);
    assert!(
        caller == policy.user_address || caller == registry.admin || policy.user_can_revoke,
        E_UNAUTHORIZED,
    );
    policy.is_revoked = true;

    event::emit(PolicyRevoked {
        policy_id: policy.policy_id,
        policy_type: POLICY_TYPE_USER_HISTORY,
        revoked_by: caller,
    });
}

fun auto_revoke_intent(registry: &mut PolicyRegistry, policy_id: &vector<u8>, now: u64) {
    if (!table::contains(&registry.intent_policies, *policy_id)) {
        return
    };
    let policy = table::borrow_mut(&mut registry.intent_policies, *policy_id);
    if (!policy.is_revoked && policy.auto_revoke_time > 0 && now > policy.auto_revoke_time) {
        policy.is_revoked = true;
        event::emit(PolicyAutoRevoked {
            policy_id: policy.policy_id,
            policy_type: POLICY_TYPE_INTENT,
            timestamp: now,
        });
    }
}

fun auto_revoke_strategy(registry: &mut PolicyRegistry, policy_id: &vector<u8>, now: u64) {
    if (!table::contains(&registry.strategy_policies, *policy_id)) {
        return
    };
    let policy = table::borrow_mut(&mut registry.strategy_policies, *policy_id);
    if (
        !policy.is_revoked && policy.is_public && policy.admin_unlock_time > 0 && now > policy.admin_unlock_time
    ) {
        policy.is_revoked = true;
        event::emit(PolicyAutoRevoked {
            policy_id: policy.policy_id,
            policy_type: POLICY_TYPE_STRATEGY,
            timestamp: now,
        });
    }
}

fun auto_revoke_history(registry: &mut PolicyRegistry, policy_id: &vector<u8>, now: u64) {
    if (!table::contains(&registry.history_policies, *policy_id)) {
        return
    };
    let policy = table::borrow_mut(&mut registry.history_policies, *policy_id);
    if (
        !policy.is_revoked && policy.access_condition.requires_tee_attestation && policy.last_updated < now
    ) {
        policy.is_revoked = true;
        event::emit(PolicyAutoRevoked {
            policy_id: policy.policy_id,
            policy_type: POLICY_TYPE_USER_HISTORY,
            timestamp: now,
        });
    }
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

/// Test core value: Seal policies and Solver Registry integration
/// This tests the integration between Seal policies and Solver Registry
#[test]
fun test_seal_approve_intent_success() {
    let mut scenario = ts::begin(ADMIN);

    // Initialize both registries
    solver_registry::init_for_testing(ts::ctx(&mut scenario));
    init(ts::ctx(&mut scenario));

    // Create and share Clock for testing
    let clock = clock::create_for_testing(ts::ctx(&mut scenario));
    clock.share_for_testing();
    ts::next_tx(&mut scenario, ADMIN);

    // Register solver first
    ts::next_tx(&mut scenario, SOLVER);
    {
        let mut solver_reg = ts::take_shared<solver_registry::SolverRegistry>(&scenario);
        let clock_ref = ts::take_shared<Clock>(&scenario);
        let stake_coin = coin::mint_for_testing<SUI>(
            solver_registry::get_min_stake_amount(),
            ts::ctx(&mut scenario),
        );
        solver_registry::register_solver(
            &mut solver_reg,
            stake_coin,
            &clock_ref,
            ts::ctx(&mut scenario),
        );
        ts::return_shared(solver_reg);
        ts::return_shared(clock_ref);
    };

    // User creates intent policy
    ts::next_tx(&mut scenario, USER);
    {
        let mut policy_reg = ts::take_shared<PolicyRegistry>(&scenario);
        let clock_ref = ts::take_shared<Clock>(&scenario);
        let now = clock::timestamp_ms(&clock_ref);

        create_intent_policy(
            &mut policy_reg,
            b"policy_001",
            1, // batch_id
            now, // solver_access_start
            now + 10_000, // solver_access_end (10s window)
            true, // router_access_enabled
            now + 86_400_000, // auto_revoke (24h)
            true, // requires_solver_registration
            solver_registry::get_min_stake_amount(), // min_stake
            false, // requires_tee_attestation
            vector::empty<u8>(), // expected_measurement
            b"ranking", // purpose
            &clock_ref,
            ts::ctx(&mut scenario),
        );

        ts::return_shared(policy_reg);
        ts::return_shared(clock_ref);
    };

    // Test access: Registered solver should have access
    ts::next_tx(&mut scenario, SOLVER);
    {
        let policy_reg = ts::take_shared<PolicyRegistry>(&scenario);
        let solver_reg = ts::take_shared<solver_registry::SolverRegistry>(&scenario);
        let clock_ref = ts::take_shared<Clock>(&scenario);

        // This should complete successfully
        seal_approve_intent(
            b"policy_001",
            &policy_reg,
            &solver_reg,
            &clock_ref,
            ts::ctx(&mut scenario),
        );

        ts::return_shared(policy_reg);
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

#[test]
#[expected_failure(abort_code = E_UNAUTHORIZED)]
fun test_seal_approve_intent_fail_unregistered() {
    let mut scenario = ts::begin(ADMIN);

    // Initialize both registries
    solver_registry::init_for_testing(ts::ctx(&mut scenario));
    init(ts::ctx(&mut scenario));

    // Create and share Clock for testing
    let clock = clock::create_for_testing(ts::ctx(&mut scenario));
    clock.share_for_testing();
    ts::next_tx(&mut scenario, ADMIN);

    // User creates intent policy that requires solver registration
    ts::next_tx(&mut scenario, USER);
    {
        let mut policy_reg = ts::take_shared<PolicyRegistry>(&scenario);
        let clock_ref = ts::take_shared<Clock>(&scenario);
        let now = clock::timestamp_ms(&clock_ref);

        create_intent_policy(
            &mut policy_reg,
            b"policy_001",
            1,
            now,
            now + 10_000,
            true,
            now + 86_400_000,
            true, // requires_solver_registration
            solver_registry::get_min_stake_amount(),
            false,
            vector::empty<u8>(),
            b"ranking",
            &clock_ref,
            ts::ctx(&mut scenario),
        );

        ts::return_shared(policy_reg);
        ts::return_shared(clock_ref);
    };

    // Test access failure: An unregistered address (USER) attempts access
    ts::next_tx(&mut scenario, USER);
    {
        let policy_reg = ts::take_shared<PolicyRegistry>(&scenario);
        let solver_reg = ts::take_shared<solver_registry::SolverRegistry>(&scenario);
        let clock_ref = ts::take_shared<Clock>(&scenario);

        seal_approve_intent(
            b"policy_001",
            &policy_reg,
            &solver_reg,
            &clock_ref,
            ts::ctx(&mut scenario),
        );

        // Return shared objects to avoid memory leaks in test harness
        ts::return_shared(policy_reg);
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

/// Test core value: Auto-revocation of expired policies
#[test]
#[expected_failure(abort_code = E_POLICY_REVOKED)]
fun test_auto_revoke_expired_policies() {
    let mut scenario = ts::begin(ADMIN);
    init(ts::ctx(&mut scenario));

    // Create and share Clock for testing
    let clock = clock::create_for_testing(ts::ctx(&mut scenario));
    clock.share_for_testing();
    ts::next_tx(&mut scenario, ADMIN);

    // Create a solver registry for the test
    solver_registry::init_for_testing(ts::ctx(&mut scenario));
    ts::next_tx(&mut scenario, ADMIN);

    // Create policy with short expiry
    ts::next_tx(&mut scenario, USER);
    {
        let mut policy_reg = ts::take_shared<PolicyRegistry>(&scenario);
        let clock_ref = ts::take_shared<Clock>(&scenario);
        let now = clock::timestamp_ms(&clock_ref);

        create_intent_policy(
            &mut policy_reg,
            b"expiring_policy",
            1,
            now,
            now + 5_000,
            false,
            now + 1_000, // Expires in 1 second
            false,
            0,
            false,
            vector::empty<u8>(),
            b"test",
            &clock_ref,
            ts::ctx(&mut scenario),
        );

        ts::return_shared(policy_reg);
        ts::return_shared(clock_ref);
    };

    // Advance time past the expiry
    ts::next_tx(&mut scenario, ADMIN);
    {
        let mut clock = ts::take_shared<Clock>(&scenario);
        clock::increment_for_testing(&mut clock, 2000); // Advance time by 2s
        ts::return_shared(clock);
    };

    // Auto-revoke expired policies
    ts::next_tx(&mut scenario, ADMIN);
    {
        let mut policy_reg = ts::take_shared<PolicyRegistry>(&scenario);
        let clock_ref = ts::take_shared<Clock>(&scenario);
        let mut policy_ids = vector::empty<vector<u8>>();
        vector::push_back(&mut policy_ids, b"expiring_policy");

        auto_revoke_expired(&mut policy_reg, POLICY_TYPE_INTENT, policy_ids, &clock_ref);

        ts::return_shared(policy_reg);
        ts::return_shared(clock_ref);
    };

    // Now, trying to approve access should fail because the policy is expired
    ts::next_tx(&mut scenario, USER);
    {
        let policy_reg = ts::take_shared<PolicyRegistry>(&scenario);
        let solver_reg = ts::take_shared<solver_registry::SolverRegistry>(&scenario);
        let clock_ref = ts::take_shared<Clock>(&scenario);

        seal_approve_intent(
            b"expiring_policy",
            &policy_reg,
            &solver_reg,
            &clock_ref,
            ts::ctx(&mut scenario),
        );

        // This part won't be reached, but for completeness:
        ts::return_shared(policy_reg);
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
