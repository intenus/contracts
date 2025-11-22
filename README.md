# Intenus Protocol - Smart Contracts API Reference

Quick reference for developers on important functions in Intenus smart contracts.

---

## Module Overview

- **`registry`** - Core intent & solution lifecycle (submit, attest, execute)
- **`solver_registry`** - Solver registration, staking, reputation
- **`slash_manager`** - Slashing mechanism with TEE evidence
- **`tee_verifier`** - TEE attestation verification
- **`seal_policy_coordinator`** - Seal policy coordination for encryption

---

## Deployment

### Package Information

| Property | Value |
|----------|-------|
| **Package ID** | `0x993c7635b44582e9c47c589c759239d3e1ce787811af5bfa0056aa253caa394a` |
| **Transaction Digest** | `FCFvV7MeCMF2uNjVHCvbo4exNyhvTw1hXzEysaZ5kW2A` |
| **Version** | 1 |
| **Modules** | `registry`, `seal_policy_coordinator`, `slash_manager`, `solver_registry`, `tee_verifier` |

### Shared Objects

After publishing, the following shared objects are created:

| Object | Address | Module |
|--------|---------|--------|
| **SolverRegistry** | `0xf71c16414b66054dfe9ebca5f22f8076a8294715d5a3e4ae4b2b4e0cd5d7e64a` | `solver_registry` |
| **SlashManager** | `0x1d023609156241468439e933c094dba4982d35292b0dd21c66cf85cc8f53b283` | `slash_manager` |
| **TeeVerifier** | `0xf0867b65374e34905b7737432e93d53722b08bc39cd621740b685a366272f857` | `tee_verifier` |
| **EnclaveConfig** | `0xe525e478d2448b4e895d744b31f9fa7cab599f6ce5c36b6b24dab2f9c54ad0fd` | `seal_policy_coordinator` |
| **Treasury** | `0x1aa5d3878fac1e2b10bf471bd1cbef6868ca1d04643c24c3d3b358d762f34f53` | `registry` |

### Environment Variables

All deployment addresses are available in `.env` file. To use them:

```bash
# Load environment variables
source .env

# Use in your scripts
echo $INTENUS_PACKAGE_ID
echo $INTENUS_SOLVER_REGISTRY_ID
echo $INTENUS_TREASURY_ID
```

Available environment variables:
- `INTENUS_PACKAGE_ID` - Package ID
- `INTENUS_SOLVER_REGISTRY_ID` - SolverRegistry shared object
- `INTENUS_SLASH_MANAGER_ID` - SlashManager shared object
- `INTENUS_TEE_VERIFIER_ID` - TeeVerifier shared object
- `INTENUS_SEAL_ENCLAVE_CONFIG_ID` - EnclaveConfig shared object
- `INTENUS_TREASURY_ID` - Treasury shared object
- `INTENUS_*_ADMIN_CAP` - Admin capabilities for each module
- `INTENUS_PACKAGE_UPGRADE_CAP` - Package upgrade capability
- `INTENUS_PACKAGE_PUBLISHER` - Package publisher object

---

## Entry Functions (Main Functions)

### Module: `intenus::registry`

#### `submit_intent`

```move
public entry fun submit_intent(
    blob_id: String,
    solver_access_start_ms: u64,
    solver_access_end_ms: u64,
    auto_revoke_ms: u64,
    requires_solver_registration: bool,
    min_solver_stake: u64,
    requires_attestation: bool,
    min_solver_reputation_score: u64,
    fee: Coin<SUI>,
    clock: &Clock,
    ctx: &mut TxContext
)
```

**Purpose:** User submits intent with fee and policy parameters.

#### `submit_solution`

```move
public entry fun submit_solution(
    intent: &mut Intent,
    solver_registry: &SolverRegistry,
    blob_id: String,
    clock: &Clock,
    ctx: &mut TxContext
)
```

**Purpose:** Solver submits solution for intent (validates policy on-chain).

#### `attest_solution`

```move
public entry fun attest_solution(
    solution: &mut Solution,
    intent: &Intent,
    input_hash: vector<u8>,
    output_hash: vector<u8>,
    measurement: vector<u8>,
    signature: vector<u8>,
    timestamp_ms: u64,
    clock: &Clock,
    ctx: &mut TxContext
)
```

**Purpose:** Enclave attests solution with signature and measurement.

#### `select_best_solution`

```move
public entry fun select_best_solution(
    intent: &mut Intent,
    solution_id: ID,
    clock: &Clock,
    ctx: &mut TxContext
)
```

**Purpose:** User selects best solution from attested solutions.

#### `execute_solution`

```move
public entry fun execute_solution(
    intent: &mut Intent,
    solution: &mut Solution,
    treasury: &mut Treasury,
    clock: &Clock,
    ctx: &mut TxContext
)
```

**Purpose:** Execute solution, distribute fee (solver reward + platform fee).

#### `reject_solution`

```move
public entry fun reject_solution(
    solution: &mut Solution,
    solver_registry: &mut SolverRegistry,
    reason: vector<u8>,
    clock: &Clock,
    ctx: &mut TxContext
)
```

**Purpose:** Reject solution (for slashing mechanism).

#### `revoke_intent`

```move
public entry fun revoke_intent(
    intent: &mut Intent,
    clock: &Clock,
    ctx: &mut TxContext
)
```

**Purpose:** User revokes intent and refunds fee.

---

### Module: `intenus::solver_registry`

#### `register_solver`

```move
entry fun register_solver(
    registry: &mut SolverRegistry,
    stake: Coin<SUI>,
    clock: &Clock,
    ctx: &mut TxContext
)
```

**Purpose:** Register as a solver with minimum stake (1 SUI).

#### `increase_stake`

```move
public fun increase_stake(
    registry: &mut SolverRegistry,
    additional_stake: Coin<SUI>,
    ctx: &mut TxContext
)
```

**Purpose:** Increase stake amount.

#### `initiate_withdrawal`

```move
public fun initiate_withdrawal(
    registry: &mut SolverRegistry,
    amount: u64,
    clock: &Clock,
    ctx: &mut TxContext
)
```

**Purpose:** Start withdrawal with 7-day cooldown.

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

**Purpose:** Complete withdrawal after cooldown, apply slashes.

---

### Module: `intenus::slash_manager`

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

**Purpose:** Submit slash with TEE evidence, creates soulbound NFT.

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

**Purpose:** Solver files appeal within 24h after slash.

#### `resolve_appeal`

```move
public entry fun resolve_appeal(
    admin_cap: &AdminCap,
    manager: &mut SlashManager,
    slash_record: &mut SlashRecord,
    appeal: &mut Appeal,
    approved: bool,
    clock: &Clock
)
```

**Mục đích:** Admin resolve appeal (approved/rejected).

---

### Module: `intenus::tee_verifier`

#### `initialize_trusted_measurement`

```move
entry fun initialize_trusted_measurement(
    _: &AdminCap,
    verifier: &mut TeeVerifier,
    service_name: vector<u8>,
    measurement: vector<u8>,
    version: vector<u8>,
    attestation_pubkey: vector<u8>,
    clock: &Clock
)
```

**Mục đích:** One-time init trusted TEE measurement (admin only).

#### `rotate_attestation_key`

```move
public entry fun rotate_attestation_key(
    _: &AdminCap,
    verifier: &mut TeeVerifier,
    new_measurement: vector<u8>,
    new_version: vector<u8>,
    new_pubkey: vector<u8>,
    clock: &Clock
)
```

**Purpose:** Rotate attestation key and measurement.

---

### Module: `intenus::seal_policy_coordinator`

#### `seal_approve_intent`

```move
entry fun seal_approve_intent(
    intent: &Intent,
    config: &EnclaveConfig,
    solver_registry_ref: &solver_registry::SolverRegistry,
    clock: &Clock,
    ctx: &TxContext
)
```

**Purpose:** Seal entry point to approve access for Intent (validates solver permissions).

#### `seal_approve_strategy`

```move
entry fun seal_approve_strategy(
    strategy_id: vector<u8>,
    config: &EnclaveConfig,
    solver_registry_ref: &solver_registry::SolverRegistry,
    clock: &Clock,
    ctx: &TxContext
)
```

**Purpose:** Seal entry point to approve access for Solver Strategy.

#### `seal_approve_history`

```move
entry fun seal_approve_history(
    user_addr: address,
    config: &EnclaveConfig,
    solver_registry_ref: &solver_registry::SolverRegistry,
    ctx: &TxContext
)
```

**Purpose:** Seal entry point to approve access for User History.

---

## View Functions (Important)

### `solver_registry`

```move
// Get solver profile (stake, reputation, metrics)
public fun get_solver_profile(registry: &SolverRegistry, solver: address): Option<SolverProfile>

// Get stake amount
public fun get_solver_stake(registry: &SolverRegistry, solver: address): u64

// Get reputation (0-10000)
public fun get_solver_reputation(registry: &SolverRegistry, solver: address): u64

// Check if solver is active
public fun is_solver_active(registry: &SolverRegistry, solver: address): bool

// Get registry stats
public fun get_registry_stats(registry: &SolverRegistry): (u64, u64, u64)
// Returns: (total_solvers, min_stake, withdrawal_cooldown)
```

### `registry`

```move
// Get intent status
public fun get_intent_status(intent: &Intent): u8

// Get pending solutions
public fun get_intent_pending_solutions(intent: &Intent): vector<ID>

// Check if solution has attestation
public fun has_attestation(solution: &Solution): bool

// Get attestation
public fun get_attestation(solution: &Solution): Option<Attestation>
```

### `slash_manager`

```move
// Get all slashes for a solver
public fun get_solver_slashes(manager: &SlashManager, solver: address): VecMap<ID, u8>

// Calculate total slash percentage (capped at 100%)
public fun calculate_total_slash_percentage(manager: &SlashManager, solver: address): u64

// Check if solver has active slashes
public fun has_active_slashes(manager: &SlashManager, solver: address): bool
```

### `tee_verifier`

```move
// Verify if measurement matches trusted measurement
public fun verify_measurement_match(verifier: &TeeVerifier, provided: &vector<u8>): bool

// Check if attestation timestamp is fresh (within 5 min)
public fun check_timestamp_freshness(attestation_timestamp: u64, clock: &Clock): bool
```

---

## Key Structs

### `Intent`

```move
public struct Intent has key, store {
    id: UID,
    user_addr: address,
    created_ms: u64,
    blob_id: String,  // Walrus blob reference
    policy: PolicyParams,
    intent_fee: Balance<SUI>,
    status: u8,
    best_solution_id: Option<ID>,
    pending_solutions: vector<ID>,
}
```

### `Solution`

```move
public struct Solution has key, store {
    id: UID,
    intent_id: ID,
    solver_addr: address,
    created_ms: u64,
    blob_id: String,  // Walrus blob reference
    attestation: Option<Attestation>,
    status: u8,
}
```

### `SolverProfile`

```move
public struct SolverProfile has copy, drop, store {
    solver_address: address,
    stake_amount: u64,
    reputation_score: u64,  // 0-10000
    total_batches_participated: u64,
    batches_won: u64,
    total_surplus_generated: u64,
    accuracy_score: u64,
    status: u8,
    pending_withdrawal: Option<u64>,
}
```

### `SlashEvidence`

```move
public struct SlashEvidence has copy, drop, store {
    batch_id: u64,
    solution_id: vector<u8>,
    solver_address: address,
    severity: u8,  // 1=minor(5%), 2=significant(20%), 3=malicious(100%)
    reason_message: vector<u8>,
    attestation_timestamp: u64,
    tee_measurement: vector<u8>,
}
```

---

## Constants

### Solver Registry

- `MIN_STAKE_AMOUNT`: `1_000_000_000` (1 SUI)
- `WITHDRAWAL_COOLDOWN_MS`: `604_800_000` (7 days)
- `MAX_REPUTATION`: `10_000`

### Slash Severity

- `SEVERITY_MINOR`: `1` → 5% slash
- `SEVERITY_SIGNIFICANT`: `2` → 20% slash
- `SEVERITY_MALICIOUS`: `3` → 100% slash

### Intent Status

- `INTENT_STATUS_PENDING`: `0`
- `INTENT_STATUS_BEST_SOLUTION_SELECTED`: `1`
- `INTENT_STATUS_EXECUTED`: `2`
- `INTENT_STATUS_REVOKED`: `3`

### Solution Status

- `SOLUTION_STATUS_PENDING`: `0`
- `SOLUTION_STATUS_ATTESTED`: `1`
- `SOLUTION_STATUS_EXECUTED`: `2`
- `SOLUTION_STATUS_REJECTED`: `3`

---

## Architecture

### Shared Objects

- `SolverRegistry` - Global solver management
- `SlashManager` - Global slash records
- `TeeVerifier` - TEE attestation verification
- `EnclaveConfig` (seal) - Seal policy coordination
- `Treasury` - Platform fee collection

### Owned Objects

- `Intent` - Owned by user
- `Solution` - Owned by solver
- `SlashRecord` - Soulbound NFT (owned by slashed solver)
- `AdminCap` - Admin capability (one per module)

### Module Dependencies

```
registry → solver_registry
slash_manager → tee_verifier, solver_registry
seal_policy_coordinator → solver_registry, registry
```

---

## Typical Flow

### 1. User Submit Intent

```move
submit_intent(blob_id, time_window, fee, policy_params, ...)
```

### 2. Solver Submit Solution

```move
submit_solution(intent, solver_registry, blob_id, ...)
// Validates: solver registered, stake sufficient, reputation OK, time window
```

### 3. Enclave Attest Solution

```move
attest_solution(solution, intent, input_hash, output_hash, signature, ...)
```

### 4. User Select Best Solution

```move
select_best_solution(intent, solution_id, ...)
```

### 5. User Execute Solution

```move
execute_solution(intent, solution, treasury, ...)
// Distributes: solver reward (90%) + platform fee (10%)
```

---

## Important Notes

1. **Off-chain storage**: Intent & Solution content stored on Walrus, only `blob_id` on-chain
2. **Policy enforcement**: Access conditions (stake, reputation, time window) validated on-chain
3. **TEE verification**: Attestations verified by `tee_verifier` module
4. **Slashing**: Applied during withdrawal, calculated from all active slashes
5. **Seal integration**: Encryption/decryption handled by Seal client, contracts only validate access

---

## Testing

All modules include `init_for_testing()` for test scenarios:

```move
#[test_only]
public fun init_for_testing(ctx: &mut TxContext)
```

Run tests:

```bash
sui move test
```
