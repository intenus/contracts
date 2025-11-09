# **INTENUS PROTOCOL - SYSTEM DESIGN DOCUMENT (SDD) v1.0**
*Complete Technical Specification for All Teams*

---

## **1. EXECUTIVE SUMMARY**

### **What is Intenus?**
Intent-based aggregation protocol on Sui that enables natural language DeFi execution through verifiable AI-powered routing with privacy preservation.

### **Core Principle**
"Aggregate, don't compete" - We don't build new DEXs/lending protocols, we optimize routing across existing ones.

### **Key Innovations**
1. Natural language → DeFi execution
2. Solver freedom (no routing restrictions)
3. AI ranking in TEE (verifiable & private)
4. MEV protection via batch auctions
5. User data sovereignty with Seal

---

## **2. ARCHITECTURE OVERVIEW**

```
User Input (Natural Language)
    ↓
[LAYER 1: Intent Ingestion]
NLP Parser → Canonical JSON → Walrus Storage
    ↓
[LAYER 2: Batch Orchestration]
Batch Manager (NestJS) → Publish to Solvers
    ↓
[LAYER 3: Solver Competition]
Multiple Solvers (Black Box) → Submit Solutions
    ↓
[LAYER 4: AI Router Optimizer]
TEE (Nautilus) → ML Ranking → Generate PTBs
    ↓
[LAYER 5: User Decision]
Show Top 3 PTBs → User Signs → Execute on Sui
```

---

## **3. SMART CONTRACTS SPECIFICATION**

### **3.1 SOLVER REGISTRY**

**Purpose**: Manage solver staking, reputation, participation metrics, and rewards while keeping on-chain logic minimal.

**State**:
```move
SolverProfile {
    solver_address: address,
    stake_amount: u64,              // Held in parallel Balance<SUI>
    reputation_score: u64,          // 0-10000 capped
    total_batches_participated: u64,
    batches_won: u64,
    total_surplus_generated: u64,
    accuracy_score: u64,            // Rolling accuracy percentage
    last_submission_epoch: u64,
    registration_timestamp: u64,
    status: u8,                     // 0=active, 1=slashed, 2=exited, 3=unstaking
    pending_withdrawal: Option<u64> // Timestamp when withdrawal can execute
}

SolverRegistry {
    id: UID,
    profiles: Table<address, SolverProfile>,
    stakes: Table<address, Balance<SUI>>,
    min_stake: u64,                 // Defaults to 1000 SUI
    slash_percentage: u8,           // Defaults to 20%
    withdrawal_cooldown: u64,       // Defaults to 7 days (ms)
    reward_percentage: u8,          // Defaults to 10% surplus share
    total_solvers: u64,
    admin: address
}
```

**Key Functions**:
- `register_solver(registry, stake, clock, ctx)` – Entry; enforces min stake and emits `SolverRegistered`.
- `increase_stake(registry, additional_stake, ctx)` – Entry; accumulates extra SUI into Balance.
- `initiate_withdrawal(registry, amount, clock, ctx)` / `complete_withdrawal(...)` – Entry; 7-day cooldown + Balance split/transfer.
- `record_batch_participation(registry, solver, batch_id, ...)` – Friend; backend updates metrics + recalculates reputation.
- `slash_solver(admin_cap, registry, solver, evidence, clock, ctx)` – Friend; burns slash amount and halves reputation.
- `distribute_batch_rewards(registry, batch_id, winner, surplus, reward_coin)` – Friend; transfers reward, emits event.
- `update_min_stake(admin_cap, registry, new_min_stake)` + other admin parameter setters.

### **3.2 SEAL POLICIES**

**Purpose**: Store policy references and access rules for Seal-encrypted data (intents, solver strategies, user histories). Enforcement relies on on-chain checks + off-chain Seal enforcement.

**State**:
```move
PolicyRegistry {
    id: UID,
    intent_policies: Table<vector<u8>, IntentPolicy>,
    strategy_policies: Table<vector<u8>, SolverStrategyPolicy>,
    history_policies: Table<vector<u8>, UserHistoryPolicy>,
    admin: address
}

IntentPolicy {
    policy_id: vector<u8>,
    batch_id: u64,
    user_address: address,
    solver_access_window: TimeWindow,
    router_access_enabled: bool,
    auto_revoke_time: u64,
    is_revoked: bool,
    access_condition: AccessCondition
}

SolverStrategyPolicy {
    policy_id: vector<u8>,
    solver_address: address,
    router_can_access: bool,
    admin_unlock_time: u64,
    is_public: bool,
    is_revoked: bool,
    access_condition: AccessCondition
}

UserHistoryPolicy {
    policy_id: vector<u8>,
    user_address: address,
    router_access_level: u8,
    user_can_revoke: bool,
    last_updated: u64,
    is_revoked: bool,
    access_condition: AccessCondition
}
```

**Key Functions**:
- `create_intent_policy(...)`, `create_solver_strategy_policy(...)`, `create_user_history_policy(...)` – Entry; create per-type policies and emit `PolicyCreated`.
- `revoke_policy(registry, policy_type, policy_id, ctx)` – Entry; owner/admin revocation with event.
- `auto_revoke_expired(registry, policy_type, policy_ids, clock)` – Entry; batch revoke after window expiry.
- `check_access(registry, solver_registry_ref, policy_type, policy_id, requester, role, attestation_flags, clock)` – View; validates solver status, stake, time windows, and TEE attestation metadata.

### **3.3 TEE VERIFIER**

**Purpose**: Maintain trusted measurement + attestation key for Router Optimizer enclave and log verified proofs emitted by backend.

**State**:
```move
TeeVerifier {
    id: UID,
    service_name: vector<u8>,
    measurement: vector<u8>,        // SHA256 of enclave code
    version: vector<u8>,
    attestation_pubkey: vector<u8>, // SGX/TEE public key
    last_rotation: u64,
    configured: bool,
    admin: address,
    records: Table<u64, AttestationRecord>
}

AttestationRecord {
    batch_id: u64,
    input_hash: vector<u8>,
    output_hash: vector<u8>,
    timestamp: u64,
    measurement: vector<u8>
}
```

**Verification Flow**:
1. `submit_attestation_record(...)` ensures verifier configured, signature verified off-chain, measurement matches, timestamp fresh (<5 minutes).
2. Store `AttestationRecord` keyed by batch and emit `AttestationVerified`.
3. `rotate_attestation_key(...)` allows admin to update measurement/pubkey; emits `TrustedMeasurementRotated`.

### **3.4 BATCH MANAGER**

**Purpose**: Minimal on-chain batch metadata tracker backing off-chain orchestration. No routing, matching, or scoring logic.

**State**:
```move
BatchRecord {
    batch_id: vector<u8>,
    epoch: u64,
    intent_count: u64,
    total_value_usd: u64,
    solver_count: u64,
    winning_solver: Option<address>,
    winning_solution_id: Option<vector<u8>>,
    total_surplus_generated: u64,
    status: u8,                    // 0=open,1=solving,2=ranking,3=executed
    created_at: u64,
    executed_at: Option<u64>
}

BatchManager {
    id: UID,
    current_epoch: u64,
    batch_duration_ms: u64,
    solver_window_ms: u64,
    records: Table<u64, BatchRecord>,
    active_batch_epoch: Option<u64>,
    admin: address
}
```

**Key Functions**:
- `start_new_batch(admin_cap, manager, batch_id, clock)` – Entry; increments epoch, creates record, emits `BatchStarted`.
- `record_intent(manager, epoch, additional_intents, additional_value)` – Friend; backend increments counts, emits `IntentRecorded`.
- `close_batch(manager, epoch)` – Friend; transitions to ranking state.
- `record_solution(manager, epoch)` – Friend; bumps solver count during ranking window.
- `set_winner(manager, epoch, winner, solution_id, surplus, clock)` – Friend; finalizes batch, emits `BatchWinnerSelected`.
- `get_current_batch(manager)` / `get_batch_stats(manager, epoch)` – View; return summary struct for UI/backend queries.

> **Note**: Optional future module – `multi_sig_coordinator` for coordinated PTB signing – remains scoped out until P2P coordination is prioritized.

---

## **4. BACKEND SERVICES SPECIFICATION**

### **4.1 SERVICE ARCHITECTURE**

```typescript
// Microservices in NestJS
1. Gateway Service       - API & WebSocket endpoints
2. Intent Service        - NLP integration & storage
3. Batch Service         - Epoch management
4. Execution Service     - PTB signing & submission
5. Archive Service       - Walrus data management
```

### **4.2 INTENT SERVICE**

**Endpoints**:
- `POST /intent/submit` - Natural language input
- `GET /intent/{id}` - Intent status
- `POST /intent/parse` - Test NLP parsing

**Flow**:
1. Receive natural language
2. Call Python NLP Parser
3. Encrypt with Seal (if private)
4. Store to Walrus
5. Add to current batch

### **4.3 BATCH SERVICE**

**Batch Lifecycle**:
```
OPEN (10s) → CLOSED → PUBLISHED → SOLVING (5s) → RANKING → READY → EXECUTED
```

**Redis Pub/Sub Channels**:
```
solver:batch:new        - New batch available
solver:solution:{id}    - Solution submission
router:ranking:{id}     - Ranking complete
```

### **4.4 DATA MODELS**

```typescript
interface Intent {
  intent_id: string;
  user_address: string;
  category: string;              // "swap", "lending", etc
  action: {
    type: string;
    params: Record<string, any>;
  };
  assets: {
    inputs: AssetSpec[];
    outputs: AssetSpec[];
  };
  constraints: {
    max_slippage_bps?: number;
    deadline_ms?: number;
  };
  execution: {
    urgency: "low" | "normal" | "high";
    privacy_level: "public" | "private";
  };
}

interface Solution {
  solution_id: string;
  batch_id: string;
  solver_address: string;
  ptb_hash: string;
  walrus_blob_id: string;
  outcomes: Outcome[];
  total_surplus_usd: string;
  estimated_gas: string;
  tee_attestation?: TEEAttestation;
}

interface RankedPTB {
  rank: number;
  solution_id: string;
  ptb_bytes: string;              // Ready to sign
  final_score: number;
  expected_outcomes: Outcome[];
  total_surplus_usd: string;
  why_ranked: Explanation;
  risk_score: number;
  warnings: string[];
}
```

---

## **5. AI/ML SPECIFICATION**

### **5.1 NLP PARSER**

**Technology**: Python FastAPI + Fine-tuned DistilBERT

**Input**: "Swap 100 SUI to USDC with max 0.5% slippage"

**Output**: Canonical Intent JSON

**Training Data**: 10k+ financial intent examples

### **5.2 ML MODELS (ONNX)**

**Three Core Models**:

1. **User Preference Model**
   - Input: User history + Solution characteristics
   - Output: Personalization score (0-1)

2. **Solution Ranker**
   - Input: Solution features + Historical outcomes
   - Output: Quality score (0-100)

3. **Fraud Detector**
   - Input: Solution anomalies
   - Output: Fraud probability (0-1)

### **5.3 FEATURE ENGINEERING**

```python
Features = {
    # Solution metrics
    'total_surplus_usd': float,
    'surplus_variance': float,
    'num_protocols_used': int,
    'p2p_match_ratio': float,
    
    # Solver reputation
    'solver_reputation_score': float,
    'solver_accuracy_history': float,
    
    # User preferences
    'user_preferred_protocols': list,
    'user_risk_tolerance': float,
}
```

### **5.4 TRAINING PIPELINE**

1. Collect execution outcomes → Walrus
2. Feature extraction
3. Model training (PyTorch)
4. Export to ONNX
5. Deploy to TEE

---

## **6. NAUTILUS TEE SPECIFICATION**

### **6.1 ROUTER OPTIMIZER**

**Technology**: Rust + Nautilus Enclave + ONNX Runtime

**Responsibilities**:
1. Load encrypted intents from Walrus
2. Decrypt with Seal (TEE has permission)
3. Run ML inference
4. Rank solutions
5. Build PTBs
6. Generate attestation

### **6.2 DATA FLOW IN TEE**

```rust
async fn rank_solutions(batch_id: String) -> RankedSolutions {
    // 1. Load & decrypt intents
    let intents = seal_client.decrypt_batch(encrypted_intents);
    
    // 2. Load solver solutions
    let solutions = walrus_client.get_solutions(batch_id);
    
    // 3. Load user histories (aggregated)
    let user_histories = load_user_histories(intents);
    
    // 4. ML scoring
    for solution in solutions {
        let features = extract_features(solution);
        let ml_score = ml_engine.predict(features);
        let personalization = calculate_personalization(solution, user_history);
    }
    
    // 5. Rank & build PTBs
    let ranked_ptbs = build_ranked_ptbs(scored_solutions);
    
    // 6. Generate attestation
    let attestation = enclave.create_attestation(
        input_hash, output_hash, timestamp
    );
    
    return RankedSolutions { ranked_ptbs, attestation };
}
```

### **6.3 ATTESTATION FORMAT**

```rust
Attestation {
    enclave_measurement: [u8; 32],  // SHA256 of code
    input_hash: [u8; 32],           // Hash of batch data
    output_hash: [u8; 32],          // Hash of ranked PTBs
    timestamp: u64,
    signature: [u8; 64],            // Intel SGX signature
}
```

---

## **7. SOLVER ECOSYSTEM**

### **7.1 SOLVER FREEDOM**

Solvers can implement ANY strategy:
- Pure P2P matching
- DEX aggregation
- Hybrid approaches
- Custom AI routing
- Order book making

### **7.2 SOLVER SDK**

```typescript
// @intenus/solver-sdk
class IntenusListener {
  onNewBatch(batch: Batch) { /* implement */ }
  submitSolution(solution: Solution) { /* SDK handles */ }
}
```

### **7.3 SOLUTION SUBMISSION**

```typescript
interface SolutionSubmission {
  solution_id: string;
  batch_id: string;
  solver_address: string;
  ptb_hash: string;
  walrus_blob_id: string;       // Full PTB stored
  outcomes: ExpectedOutcome[];
  total_surplus_usd: string;
  estimated_gas: string;
  strategy_summary?: {           // Optional disclosure
    p2p_matches: number;
    protocol_routes: string[];
  };
  tee_attestation?: TEEAttestation; // If high value
}
```

---

## **8. WALRUS & SEAL INTEGRATION**

### **8.1 WALRUS USAGE**

**Cost Savings**: 99.8% vs on-chain storage

**Storage Structure**:
```
/intents/{batch_id}/{intent_id}.json
/solutions/{batch_id}/{solution_id}.json
/executions/{batch_id}/{tx_digest}.json
/user_histories/{user_address}/aggregated.json
/training_data/batches/{epoch}/
```

### **8.2 SEAL ENCRYPTION**

**When to Encrypt**:
- Private intents (large trades)
- User history data
- Solver strategies
- Training datasets

**Access Control Timeline**:
```
Intent: User → Solvers (batch window) → Router (ranking) → Revoked
History: User (always) → Router (aggregated only)
Strategy: Solver (always) → Router (ranking) → Admin (30 days)
```

---

## **9. USER EXPERIENCE FLOW**

### **9.1 COMPLETE FLOW**

```
1. User: "Swap 100 SUI to USDC"
2. System: "✓ Intent parsed, waiting for batch..."
3. System: "✓ 5 solvers competing..."
4. System: "✓ AI ranking solutions..."
5. System: Shows top 3 PTBs with explanations
6. User: Selects & signs PTB
7. System: Executes on Sui
```

### **9.2 PTB PREVIEW**

```
🥇 Rank 1 - Score: 95.8
You'll receive: 99.85 USDC
Surplus: +$0.85 vs market
Gas: ~$0.02
Route: FlowX (1 hop)
Why: Best surplus + matches your preference
[Sign & Execute]
```

---

## **10. DEPLOYMENT PLAN**

### **Phase 1: Core Infrastructure (Weeks 1-2)**
- [ ] Deploy Smart Contracts on testnet
- [ ] Setup Kubernetes cluster
- [ ] Configure Redis & PostgreSQL
- [ ] Integrate Walrus & Seal

### **Phase 2: Backend Services (Weeks 3-4)**
- [ ] NestJS microservices
- [ ] NLP Parser integration
- [ ] Batch orchestration
- [ ] Solver SDK release

### **Phase 3: AI/ML Pipeline (Weeks 5-6)**
- [ ] Train NLP model
- [ ] Train ranking models
- [ ] Export to ONNX
- [ ] Setup training pipeline

### **Phase 4: TEE Integration (Weeks 7-8)**
- [ ] Nautilus enclave setup
- [ ] Router Optimizer in Rust
- [ ] Attestation verification
- [ ] End-to-end testing

### **Phase 5: Solver Onboarding (Weeks 9-10)**
- [ ] Documentation
- [ ] Reference implementation
- [ ] Solver registration
- [ ] Incentive program

---

## **11. TEAM RESPONSIBILITIES**

### **Smart Contract Team**
- Solver Registry
- Seal Policies
- TEE Verifier
- Batch Manager

### **Backend Team**
- NestJS services
- Redis/PostgreSQL
- Walrus integration
- API/WebSocket

### **AI Team**
- NLP Parser
- ML models (PyTorch → ONNX)
- Feature engineering
- Training pipeline

### **TEE Team**
- Router Optimizer (Rust)
- Nautilus setup
- ONNX inference
- PTB builder

### **Frontend Team**
- Chat interface
- PTB preview
- Wallet integration
- Solution cards

---

## **12. SUCCESS METRICS**

- Intent → Execution: <15 seconds
- Solver participation: 5+ active
- AI ranking accuracy: >85%
- User execution rate: >70%
- Cost savings: 20-40% vs direct routing

---

**This SDD is the single source of truth. All teams should refer to this document for implementation details.**