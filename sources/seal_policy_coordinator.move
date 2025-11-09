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
const E_POLICY_REVOKED: u64 = 1006;

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
    id: object::UID,
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

public struct IntentPolicy has drop, store {
    policy_id: vector<u8>,
    batch_id: u64,
    user_address: address,
    solver_access_window: TimeWindow,
    router_access_enabled: bool,
    auto_revoke_time: u64,
    is_revoked: bool,
    access_condition: AccessCondition,
}

public struct SolverStrategyPolicy has drop, store {
    policy_id: vector<u8>,
    solver_address: address,
    router_can_access: bool,
    admin_unlock_time: u64,
    is_public: bool,
    is_revoked: bool,
    access_condition: AccessCondition,
}

public struct UserHistoryPolicy has drop, store {
    policy_id: vector<u8>,
    user_address: address,
    router_access_level: u8,
    user_can_revoke: bool,
    last_updated: u64,
    is_revoked: bool,
    access_condition: AccessCondition,
}

public struct PolicyRegistry has key {
    id: object::UID,
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

fun init(ctx: &mut tx_context::TxContext) {
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
    ctx: &mut tx_context::TxContext,
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
    requires_tee_attestation: bool,
    expected_measurement: vector<u8>,
    purpose: vector<u8>,
    ctx: &mut tx_context::TxContext,
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
    requires_tee_attestation: bool,
    expected_measurement: vector<u8>,
    purpose: vector<u8>,
    clock: &Clock,
    ctx: &mut tx_context::TxContext,
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
    ctx: &mut tx_context::TxContext,
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

/// Validate access request against policy rules.
public fun check_access(
    registry: &PolicyRegistry,
    solver_registry_ref: &solver_registry::SolverRegistry,
    policy_type: u8,
    policy_id: &vector<u8>,
    requester: address,
    role: u8,
    has_valid_attestation: bool,
    provided_measurement: &vector<u8>,
    purpose: &vector<u8>,
    clock: &Clock,
): bool {
    if (role == ROLE_ADMIN && requester == registry.admin) {
        return true
    };

    if (policy_type == POLICY_TYPE_INTENT) {
        if (!table::contains(&registry.intent_policies, *policy_id)) {
            return false
        };
        let policy = table::borrow(&registry.intent_policies, *policy_id);
        return can_access_intent_policy(
                policy,
                solver_registry_ref,
                requester,
                role,
                has_valid_attestation,
                provided_measurement,
                purpose,
                clock,
            )
    } else if (policy_type == POLICY_TYPE_STRATEGY) {
        if (!table::contains(&registry.strategy_policies, *policy_id)) {
            return false
        };
        let policy = table::borrow(&registry.strategy_policies, *policy_id);
        return can_access_strategy_policy(
                policy,
                requester,
                role,
                has_valid_attestation,
                provided_measurement,
                purpose,
                clock,
            )
    } else {
        if (!table::contains(&registry.history_policies, *policy_id)) {
            return false
        };
        let policy = table::borrow(&registry.history_policies, *policy_id);
        return can_access_history_policy(
                policy,
                requester,
                role,
                has_valid_attestation,
                provided_measurement,
                purpose,
            )
    };
    false
}

// ===== INTERNAL HELPERS =====

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

fun can_access_intent_policy(
    policy: &IntentPolicy,
    solver_registry_ref: &solver_registry::SolverRegistry,
    requester: address,
    role: u8,
    has_valid_attestation: bool,
    provided_measurement: &vector<u8>,
    purpose: &vector<u8>,
    clock: &Clock,
): bool {
    if (policy.is_revoked) {
        return false
    };

    let now = clock::timestamp_ms(clock);
    if (policy.auto_revoke_time > 0 && now > policy.auto_revoke_time) {
        return false
    };

    if (role == ROLE_USER) {
        return requester == policy.user_address
    };

    if (role == ROLE_SOLVER) {
        if (
            now < policy.solver_access_window.start_ms || now > policy.solver_access_window.end_ms
        ) {
            return false
        };
        if (!policy.access_condition.requires_solver_registration) {
            return true
        };
        if (!solver_registry::is_solver_active(solver_registry_ref, requester)) {
            return false
        };
        let stake = solver_registry::get_solver_stake(solver_registry_ref, requester);
        return stake >= policy.access_condition.min_solver_stake;
    };

    if (role == ROLE_ROUTER) {
        if (!policy.router_access_enabled) {
            return false
        };
        return validate_attestation(
                &policy.access_condition,
                has_valid_attestation,
                provided_measurement,
                purpose,
            )
    };

    false
}

fun can_access_strategy_policy(
    policy: &SolverStrategyPolicy,
    requester: address,
    role: u8,
    has_valid_attestation: bool,
    provided_measurement: &vector<u8>,
    purpose: &vector<u8>,
    clock: &Clock,
): bool {
    if (policy.is_revoked) {
        return false
    };

    if (role == ROLE_SOLVER && requester == policy.solver_address) {
        return true
    };

    if (role == ROLE_ADMIN && clock::timestamp_ms(clock) >= policy.admin_unlock_time) {
        return true
    };

    if (policy.is_public) {
        return true
    };

    if (role == ROLE_ROUTER && policy.router_can_access) {
        return validate_attestation(
                &policy.access_condition,
                has_valid_attestation,
                provided_measurement,
                purpose,
            )
    };

    false
}

fun can_access_history_policy(
    policy: &UserHistoryPolicy,
    requester: address,
    role: u8,
    has_valid_attestation: bool,
    provided_measurement: &vector<u8>,
    purpose: &vector<u8>,
): bool {
    if (policy.is_revoked) {
        return false
    };

    if (role == ROLE_USER && requester == policy.user_address) {
        return true
    };

    if (role == ROLE_ROUTER && policy.router_access_level > 0) {
        return validate_attestation(
                &policy.access_condition,
                has_valid_attestation,
                provided_measurement,
                purpose,
            )
    };

    false
}

fun validate_attestation(
    condition: &AccessCondition,
    has_valid_attestation: bool,
    provided_measurement: &vector<u8>,
    purpose: &vector<u8>,
): bool {
    if (!condition.requires_tee_attestation) {
        return true
    };
    if (!has_valid_attestation) {
        return false
    };
    if (!bytes_equal(&condition.expected_measurement, provided_measurement)) {
        return false
    };
    if (vector::length(&condition.purpose) == 0) {
        return true
    };
    bytes_equal(&condition.purpose, purpose)
}

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

// ===== TEST HELPERS =====

#[test_only]
public fun init_for_testing(ctx: &mut tx_context::TxContext) {
    init(ctx);
}
