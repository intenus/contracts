# Intenus Protocol - Smart Contracts API Reference

## Module: `intenus::solver_registry`

### Entry Functions

#### `register_solver`
```move
public fun register_solver(
    registry: &mut SolverRegistry,
    stake: Coin<SUI>,
    clock: &Clock,
    ctx: &mut TxContext
)
```
Register as a solver with minimum stake requirement.

#### `increase_stake`
```move
public fun increase_stake(
    registry: &mut SolverRegistry,
    additional_stake: Coin<SUI>,
    ctx: &mut TxContext
)
```
Increase stake amount for an existing solver.

#### `initiate_withdrawal`
```move
public fun initiate_withdrawal(
    registry: &mut SolverRegistry,
    amount: u64,
    clock: &Clock,
    ctx: &mut TxContext
)
```
Start withdrawal process with 7-day cooldown.

#### `complete_withdrawal`
```move
public fun complete_withdrawal(
    registry: &mut SolverRegistry,
    slash_manager: &SlashManager,
    amount: u64,
    clock: &Clock,
    ctx: &mut TxContext
): Coin<SUI>
```
Complete withdrawal after cooldown, applying any slashes.

### View Functions

#### `get_solver_profile`
```move
public fun get_solver_profile(
    registry: &SolverRegistry,
    solver: address
): Option<SolverProfile>
```

#### `get_solver_stake`
```move
public fun get_solver_stake(
    registry: &SolverRegistry,
    solver: address
): u64
```

#### `get_solver_reputation`
```move
public fun get_solver_reputation(
    registry: &SolverRegistry,
    solver: address
): u64
```

#### `is_solver_active`
```move
public fun is_solver_active(
    registry: &SolverRegistry,
    solver: address
): bool
```

#### `get_registry_stats`
```move
public fun get_registry_stats(
    registry: &SolverRegistry
): (u64, u64, u64)
```
Returns: (total_solvers, min_stake, withdrawal_cooldown)

### Internal (Package) Functions

#### `record_batch_participation`
```move
public(package) fun record_batch_participation(
    registry: &mut SolverRegistry,
    solver: address,
    batch_id: vector<u8>,
    won: bool,
    surplus_generated: u64,
    clock: &Clock
)
```

#### `slash_solver`
```move
public(package) fun slash_solver(
    admin_cap: &AdminCap,
    registry: &mut SolverRegistry,
    solver: address,
    evidence: vector<u8>,
    clock: &Clock
)
```

#### `distribute_batch_rewards`
```move
public(package) fun distribute_batch_rewards(
    registry: &SolverRegistry,
    batch_id: vector<u8>,
    winner: address,
    surplus_amount: u64,
    reward_coin: Coin<SUI>,
    ctx: &mut TxContext
)
```

#### Constants Getters
```move
public(package) fun get_min_stake_amount(): u64
public(package) fun get_withdrawal_cooldown_ms(): u64
public(package) fun get_slash_percentage(): u8
```

### Admin Functions

#### `update_min_stake`
```move
public fun update_min_stake(
    admin_cap: &AdminCap,
    registry: &mut SolverRegistry,
    new_min_stake: u64
)
```

#### `update_slash_percentage`
```move
public fun update_slash_percentage(
    admin_cap: &AdminCap,
    registry: &mut SolverRegistry,
    new_percentage: u8
)
```
Max 50% slash allowed.

---

## Module: `intenus::slash_manager`

### Entry Functions

#### `submit_slash`
```move
public fun submit_slash(
    manager: &mut SlashManager,
    verifier: &TeeVerifier,
    evidence: SlashEvidence,
    clock: &Clock,
    ctx: &mut TxContext
)
```
Submit slash with TEE evidence, creates soulbound NFT.

#### `file_appeal`
```move
public fun file_appeal(
    manager: &mut SlashManager,
    slash_record: &mut SlashRecord,
    appeal_reason: vector<u8>,
    counter_evidence: vector<u8>,
    clock: &Clock,
    ctx: &mut TxContext
)
```
File appeal within 24 hours of slash.

#### `resolve_appeal`
```move
public fun resolve_appeal(
    admin_cap: &AdminCap,
    manager: &mut SlashManager,
    slash_record: &mut SlashRecord,
    appeal: &mut Appeal,
    approved: bool,
    clock: &Clock
)
```
Admin resolves appeal (approved/rejected).

### View Functions

#### `get_solver_slashes`
```move
public fun get_solver_slashes(
    manager: &SlashManager,
    solver: address
): VecMap<ID, u8>
```
Returns: Map of slash_id -> severity

#### `calculate_total_slash_percentage`
```move
public fun calculate_total_slash_percentage(
    manager: &SlashManager,
    solver: address
): u64
```
Returns: Total slash in basis points (capped at 10000 = 100%)

#### `is_slash_appealed_and_approved`
```move
public fun is_slash_appealed_and_approved(
    manager: &SlashManager,
    slash_id: ID
): bool
```

#### `has_active_slashes`
```move
public fun has_active_slashes(
    manager: &SlashManager,
    solver: address
): bool
```

### Structs

#### `SlashEvidence`
```move
public struct SlashEvidence has copy, drop, store {
    batch_id: u64,
    solution_id: vector<u8>,
    solver_address: address,
    severity: u8,
    reason_code: u8,
    reason_message: vector<u8>,
    failure_context: vector<u8>,
    attestation: vector<u8>,
    attestation_timestamp: u64,
    tee_measurement: vector<u8>,
}
```

---

## Module: `intenus::batch_manager`

### Entry Functions

#### `start_new_batch`
```move
public fun start_new_batch(
    admin_cap: &AdminCap,
    manager: &mut BatchManager,
    batch_id: vector<u8>,
    clock: &Clock
)
```

### View Functions

#### `get_current_batch`
```move
public fun get_current_batch(
    manager: &BatchManager
): Option<BatchSummary>
```

#### `get_batch_stats`
```move
public fun get_batch_stats(
    manager: &BatchManager,
    epoch: u64
): Option<BatchSummary>
```

### Structs

#### `BatchSummary`
```move
public struct BatchSummary has copy, drop {
    batch_id: vector<u8>,
    epoch: u64,
    intent_count: u64,
    total_value_usd: u64,
    solver_count: u64,
    winning_solver: Option<address>,
    winning_solution_id: Option<vector<u8>>,
    total_surplus_generated: u64,
    status: u8,
    created_at: u64,
    executed_at: Option<u64>,
}
```

---

## Module: `intenus::tee_verifier`

### Entry Functions

#### `initialize_trusted_measurement`
```move
public fun initialize_trusted_measurement(
    admin_cap: &AdminCap,
    verifier: &mut TeeVerifier,
    service_name: vector<u8>,
    measurement: vector<u8>,
    version: vector<u8>,
    attestation_pubkey: vector<u8>,
    clock: &Clock
)
```
One-time initialization of trusted TEE measurement.

#### `rotate_attestation_key`
```move
public fun rotate_attestation_key(
    admin_cap: &AdminCap,
    verifier: &mut TeeVerifier,
    new_measurement: vector<u8>,
    new_version: vector<u8>,
    new_pubkey: vector<u8>,
    clock: &Clock
)
```
Rotate attestation key and measurement.

#### `submit_attestation_record`
```move
public fun submit_attestation_record(
    verifier: &mut TeeVerifier,
    batch_id: u64,
    input_hash: vector<u8>,
    output_hash: vector<u8>,
    measurement: vector<u8>,
    clock: &Clock
)
```
Submit TEE attestation record for a batch.

### View Functions

#### `verify_measurement_match`
```move
public fun verify_measurement_match(
    verifier: &TeeVerifier,
    provided: &vector<u8>
): bool
```

#### `check_timestamp_freshness`
```move
public fun check_timestamp_freshness(
    attestation_timestamp: u64,
    clock: &Clock
): bool
```
Checks if timestamp is within 5 minutes drift.

#### `get_attestation_record`
```move
public fun get_attestation_record(
    verifier: &TeeVerifier,
    batch_id: u64
): bool
```

---

## Module: `intenus::seal_policy_coordinator`

### Entry Functions

#### `seal_approve_intent`
```move
public entry fun seal_approve_intent(
    policy_id: vector<u8>,
    registry: &PolicyRegistry,
    solver_registry_ref: &solver_registry::SolverRegistry,
    clock: &Clock,
    ctx: &TxContext
)
```
Validate intent policy access (for solvers).

#### `seal_approve_strategy`
```move
public entry fun seal_approve_strategy(
    policy_id: vector<u8>,
    registry: &PolicyRegistry,
    solver_registry_ref: &solver_registry::SolverRegistry,
    clock: &Clock,
    ctx: &TxContext
)
```
Validate strategy policy access.

#### `seal_approve_history`
```move
public entry fun seal_approve_history(
    policy_id: vector<u8>,
    registry: &PolicyRegistry,
    solver_registry_ref: &solver_registry::SolverRegistry,
    ctx: &TxContext
)
```
Validate user history policy access.

### Policy Management

#### `create_intent_policy`
```move
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
    ctx: &mut TxContext
)
```
Create policy for user intent encryption.

#### `create_solver_strategy_policy`
```move
public fun create_solver_strategy_policy(
    registry: &mut PolicyRegistry,
    policy_id: vector<u8>,
    router_can_access: bool,
    admin_unlock_time: u64,
    is_public: bool,
    requires_solver_registration: bool,
    min_solver_stake: u64,
    requires_tee_attestation: bool,
    expected_measurement: vector<u8>,
    purpose: vector<u8>,
    clock: &Clock,
    ctx: &mut TxContext
)
```
Create policy for solver strategy encryption.

#### `create_user_history_policy`
```move
public fun create_user_history_policy(
    registry: &mut PolicyRegistry,
    policy_id: vector<u8>,
    router_access_level: u8,
    user_can_revoke: bool,
    requires_solver_registration: bool,
    min_solver_stake: u64,
    requires_tee_attestation: bool,
    expected_measurement: vector<u8>,
    purpose: vector<u8>,
    clock: &Clock,
    ctx: &mut TxContext
)
```
Create policy for user history encryption.

#### `revoke_policy`
```move
public fun revoke_policy(
    registry: &mut PolicyRegistry,
    policy_type: u8,
    policy_id: vector<u8>,
    ctx: &mut TxContext
)
```
Revoke a policy (owner only).

#### `auto_revoke_expired`
```move
public fun auto_revoke_expired(
    registry: &mut PolicyRegistry,
    policy_type: u8,
    policy_ids: vector<vector<u8>>,
    clock: &Clock
)
```
Auto-revoke expired policies in batch.

---

## Type Definitions

### `SolverProfile`
```move
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
    pending_withdrawal: Option<u64>,
}
```

### `SlashRecord` (Soulbound NFT)
```move
public struct SlashRecord has key, store {
    id: UID,
    solver_address: address,
    batch_id: u64,
    solution_id: vector<u8>,
    severity: u8,
    reason: vector<u8>,
    slash_percentage_bps: u64,
    created_at: u64,
    appealed: bool,
    appeal_approved: bool,
}
```

### `Appeal`
```move
public struct Appeal has key, store {
    id: UID,
    slash_id: ID,
    solver_address: address,
    reason: vector<u8>,
    counter_evidence: vector<u8>,
    created_at: u64,
    status: u8,
}
```

---

## Constants

### Solver Registry
```move
MIN_STAKE_AMOUNT: u64 = 1_000_000_000          // 1 SUI
WITHDRAWAL_COOLDOWN_MS: u64 = 604_800_000      // 7 days
SLASH_PERCENTAGE: u8 = 20                      // 20%
REWARD_PERCENTAGE: u8 = 10                     // 10%
MAX_REPUTATION: u64 = 10_000

STATUS_ACTIVE: u8 = 0
STATUS_SLASHED: u8 = 1
STATUS_UNSTAKING: u8 = 3
```

### Slash Manager
```move
SEVERITY_MINOR: u8 = 1                         // 5% slash
SEVERITY_SIGNIFICANT: u8 = 2                   // 20% slash
SEVERITY_MALICIOUS: u8 = 3                     // 100% slash

MINOR_SLASH_BPS: u64 = 500                     // 5%
SIGNIFICANT_SLASH_BPS: u64 = 2000              // 20%
MALICIOUS_SLASH_BPS: u64 = 10000               // 100%

APPEAL_WINDOW_MS: u64 = 86_400_000             // 24 hours
```

### Batch Manager
```move
STATUS_OPEN: u8 = 0
STATUS_SOLVING: u8 = 1
STATUS_RANKING: u8 = 2
STATUS_EXECUTED: u8 = 3

DEFAULT_BATCH_DURATION_MS: u64 = 10_000        // 10 seconds
DEFAULT_SOLVER_WINDOW_MS: u64 = 5_000          // 5 seconds
```

### TEE Verifier
```move
MAX_TIMESTAMP_DRIFT_MS: u64 = 300_000          // 5 minutes
```

### Seal Policy Coordinator
```move
POLICY_TYPE_INTENT: u8 = 0
POLICY_TYPE_STRATEGY: u8 = 1
POLICY_TYPE_USER_HISTORY: u8 = 2

ROLE_USER: u8 = 0
ROLE_SOLVER: u8 = 1
ROLE_ROUTER: u8 = 2
ROLE_ADMIN: u8 = 3
```

---

## Error Codes

### Solver Registry (1xxx)
```move
E_INSUFFICIENT_STAKE: u64 = 1001
E_SOLVER_NOT_REGISTERED: u64 = 1002
E_SOLVER_ALREADY_REGISTERED: u64 = 1003
E_COOLDOWN_NOT_COMPLETE: u64 = 1007
E_INVALID_STATUS: u64 = 1009
E_INSUFFICIENT_BALANCE: u64 = 1011
E_NO_PENDING_WITHDRAWAL: u64 = 1012
```

### Seal Policy Coordinator (3xxx)
```move
E_POLICY_EXISTS: u64 = 3001
E_POLICY_NOT_FOUND: u64 = 3002
E_INVALID_TIME_WINDOW: u64 = 3003
E_UNAUTHORIZED: u64 = 3004
E_POLICY_REVOKED: u64 = 3005
```

### TEE Verifier (4xxx)
```move
E_NOT_CONFIGURED: u64 = 4001
E_INVALID_ATTESTATION: u64 = 4002
E_MEASUREMENT_MISMATCH: u64 = 4003
E_STALE_TIMESTAMP: u64 = 4004
E_DUPLICATE_RECORD: u64 = 4005
```

### Batch Manager (5xxx)
```move
E_BATCH_EXISTS: u64 = 5002
E_BATCH_NOT_FOUND: u64 = 5003
E_INVALID_STATUS: u64 = 5004
```

### Slash Manager (6xxx)
```move
E_UNAUTHORIZED: u64 = 6001
E_INVALID_SEVERITY: u64 = 6003
E_APPEAL_ALREADY_FILED: u64 = 6004
E_APPEAL_NOT_FOUND: u64 = 6005
E_APPEAL_WINDOW_EXPIRED: u64 = 6006
E_INVALID_TEE_ATTESTATION: u64 = 6009
E_TRANSFER_REJECTED: u64 = 6010
```

---

## Architecture Overview

### Module Dependencies
```
seal_policy_coordinator → solver_registry
solver_registry → slash_manager
slash_manager → tee_verifier
batch_manager (standalone)
```

### Shared Objects
- `SolverRegistry` - Global solver management
- `SlashManager` - Global slash records
- `BatchManager` - Batch lifecycle tracking
- `TeeVerifier` - TEE attestation verification
- `PolicyRegistry` - Seal policy coordination

### Owned Objects
- `AdminCap` - Admin capability (one per module)
- `SlashRecord` - Soulbound NFT (owned by slashed solver)

### Package Objects
- `Appeal` - Shared appeal object

---

## Usage Examples

### Register as Solver
```move
use intenus::solver_registry;

public entry fun register(
    registry: &mut SolverRegistry,
    payment: Coin<SUI>,
    clock: &Clock,
    ctx: &mut TxContext
) {
    solver_registry::register_solver(registry, payment, clock, ctx);
}
```

### Submit Slash
```move
use intenus::slash_manager;

public entry fun slash(
    manager: &mut SlashManager,
    verifier: &TeeVerifier,
    evidence: SlashEvidence,
    clock: &Clock,
    ctx: &mut TxContext
) {
    slash_manager::submit_slash(manager, verifier, evidence, clock, ctx);
}
```

### Create Intent Policy
```move
use intenus::seal_policy_coordinator;

public entry fun create_policy(
    registry: &mut PolicyRegistry,
    policy_id: vector<u8>,
    batch_id: u64,
    // ... other params
    clock: &Clock,
    ctx: &mut TxContext
) {
    seal_policy_coordinator::create_intent_policy(
        registry,
        policy_id,
        batch_id,
        // ... other args
        clock,
        ctx
    );
}
```
