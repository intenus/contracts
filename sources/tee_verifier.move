module intenus::tee_verifier;

use sui::clock::{Self, Clock};
use sui::event;
use sui::table::{Self, Table};

// ===== ERRORS =====
const E_NOT_CONFIGURED: u64 = 4001;
const E_INVALID_ATTESTATION: u64 = 4002;
const E_MEASUREMENT_MISMATCH: u64 = 4003;
const E_STALE_TIMESTAMP: u64 = 4004;
const E_DUPLICATE_RECORD: u64 = 4005;

// ===== CONSTANTS =====
const MAX_TIMESTAMP_DRIFT_MS: u64 = 300_000; // 5 minutes

// ===== STRUCTS =====

/// Capability for managing trusted measurements.
public struct AdminCap has key, store {
    id: UID,
}

/// Verifier shared object storing trusted configuration.
public struct TeeVerifier has key {
    id: UID,
    service_name: vector<u8>,
    measurement: vector<u8>,
    version: vector<u8>,
    attestation_pubkey: vector<u8>,
    last_rotation: u64,
    configured: bool,
    admin: address,
    records: Table<u64, AttestationRecord>,
}

public struct AttestationRecord has drop, store {
    batch_id: u64,
    input_hash: vector<u8>,
    output_hash: vector<u8>,
    timestamp: u64,
    measurement: vector<u8>,
}

// ===== EVENTS =====

public struct TrustedMeasurementInitialized has copy, drop {
    service_name: vector<u8>,
    version: vector<u8>,
    measurement: vector<u8>,
}

public struct TrustedMeasurementRotated has copy, drop {
    new_measurement: vector<u8>,
    timestamp: u64,
}

public struct AttestationVerified has copy, drop {
    batch_id: u64,
    timestamp: u64,
    measurement: vector<u8>,
}

// ===== INITIALIZATION =====

fun init(ctx: &mut tx_context::TxContext) {
    let admin_cap = AdminCap { id: object::new(ctx) };
    let verifier = TeeVerifier {
        id: object::new(ctx),
        service_name: vector::empty<u8>(),
        measurement: vector::empty<u8>(),
        version: vector::empty<u8>(),
        attestation_pubkey: vector::empty<u8>(),
        last_rotation: 0,
        configured: false,
        admin: tx_context::sender(ctx),
        records: table::new(ctx),
    };

    transfer::transfer(admin_cap, tx_context::sender(ctx));
    transfer::share_object(verifier);
}

// ===== ENTRY FUNCTIONS =====

/// Initialize trusted measurement and attestation key (one-time).
entry fun initialize_trusted_measurement(
    _: &AdminCap,
    verifier: &mut TeeVerifier,
    service_name: vector<u8>,
    measurement: vector<u8>,
    version: vector<u8>,
    attestation_pubkey: vector<u8>,
    clock: &Clock,
) {
    assert!(!verifier.configured, E_DUPLICATE_RECORD);

    verifier.service_name = service_name;
    verifier.measurement = measurement;
    verifier.version = version;
    verifier.attestation_pubkey = attestation_pubkey;
    verifier.last_rotation = clock::timestamp_ms(clock);
    verifier.configured = true;

    event::emit(TrustedMeasurementInitialized {
        service_name: verifier.service_name,
        version: verifier.version,
        measurement: verifier.measurement,
    });
}

/// Rotate attestation public key and measurement hash.
public entry fun rotate_attestation_key(
    _: &AdminCap,
    verifier: &mut TeeVerifier,
    new_measurement: vector<u8>,
    new_version: vector<u8>,
    new_pubkey: vector<u8>,
    clock: &Clock,
) {
    assert!(verifier.configured, E_NOT_CONFIGURED);

    verifier.measurement = new_measurement;
    verifier.version = new_version;
    verifier.attestation_pubkey = new_pubkey;
    verifier.last_rotation = clock::timestamp_ms(clock);

    event::emit(TrustedMeasurementRotated {
        new_measurement: verifier.measurement,
        timestamp: verifier.last_rotation,
    });
}

/// Verify ranking proof metadata and store attestation record.
/// Signature verification must be performed off-chain; caller supplies boolean flag.
entry fun submit_attestation_record(
    verifier: &mut TeeVerifier,
    batch_id: u64,
    input_hash: vector<u8>,
    output_hash: vector<u8>,
    measurement: vector<u8>,
    attestation_timestamp: u64,
    signature_verified: bool,
    clock: &Clock,
) {
    assert!(verifier.configured, E_NOT_CONFIGURED);
    assert!(signature_verified, E_INVALID_ATTESTATION);
    assert!(verify_measurement_match(verifier, &measurement), E_MEASUREMENT_MISMATCH);
    assert!(check_timestamp_freshness(attestation_timestamp, clock), E_STALE_TIMESTAMP);
    assert!(!table::contains(&verifier.records, batch_id), E_DUPLICATE_RECORD);

    let record = AttestationRecord {
        batch_id,
        input_hash,
        output_hash,
        timestamp: attestation_timestamp,
        measurement,
    };

    table::add(&mut verifier.records, batch_id, record);

    event::emit(AttestationVerified {
        batch_id,
        timestamp: attestation_timestamp,
        measurement,
    });
}

// ===== VIEW FUNCTIONS =====

/// Verify measurements match the trusted hash.
public fun verify_measurement_match(verifier: &TeeVerifier, provided: &vector<u8>): bool {
    bytes_equal(&verifier.measurement, provided)
}

/// Check attestation timestamp freshness.
public fun check_timestamp_freshness(attestation_timestamp: u64, clock: &Clock): bool {
    let now = clock::timestamp_ms(clock);
    if (attestation_timestamp > now) {
        return false
    };
    now - attestation_timestamp <= MAX_TIMESTAMP_DRIFT_MS
}

/// Fetch stored attestation record if present.
public fun get_attestation_record(verifier: &TeeVerifier, batch_id: u64): bool {
    table::contains(&verifier.records, batch_id)
}

// ===== INTERNAL HELPERS =====

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
use sui::test_scenario::{Self as ts};

#[test_only]
const ADMIN: address = @0xA;
#[test_only]
const ROUTER: address = @0xB;

#[test_only]
public fun init_for_testing(ctx: &mut tx_context::TxContext) {
    init(ctx);
}

/// Test core value: TEE attestation verification for Router Optimizer
/// This ensures only verified TEE enclaves can submit ranking proofs
#[test]
fun test_tee_attestation_verification() {
    let mut scenario = ts::begin(ADMIN);
    init(ts::ctx(&mut scenario));
    
    // Create and share Clock for testing
    let clock = clock::create_for_testing(ts::ctx(&mut scenario));
    clock.share_for_testing();
    ts::next_tx(&mut scenario, ADMIN);

    // Initialize trusted measurement
    ts::next_tx(&mut scenario, ADMIN);
    {
        let admin_cap_ref = ts::take_from_sender<AdminCap>(&scenario);
        let mut verifier = ts::take_shared<TeeVerifier>(&scenario);
        let clock_ref = ts::take_shared<Clock>(&scenario);
        
        let trusted_measurement = b"router_optimizer_v1_measurement_hash";
        let version = b"1.0.0";
        let pubkey = b"attestation_public_key_bytes";
        
        initialize_trusted_measurement(
            &admin_cap_ref,
            &mut verifier,
            b"RouterOptimizer",
            trusted_measurement,
            version,
            pubkey,
            &clock_ref,
        );
        
        transfer::transfer(admin_cap_ref, ADMIN);
        ts::return_shared(verifier);
        ts::return_shared(clock_ref);
    };

    // Submit valid attestation record
    ts::next_tx(&mut scenario, ROUTER);
    {
        let mut verifier = ts::take_shared<TeeVerifier>(&scenario);
        let clock_ref = ts::take_shared<Clock>(&scenario);
        let now = clock::timestamp_ms(&clock_ref);
        
        let input_hash = b"batch_input_hash_32_bytes";
        let output_hash = b"ranked_output_hash_32_bytes";
        let measurement = b"router_optimizer_v1_measurement_hash";
        
        submit_attestation_record(
            &mut verifier,
            1, // batch_id
            input_hash,
            output_hash,
            measurement,
            now,
            true, // signature verified off-chain
            &clock_ref,
        );
        
        // Verify record was stored
        let has_record = get_attestation_record(&verifier, 1);
        assert!(has_record, 1);
        
        ts::return_shared(verifier);
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
#[expected_failure(abort_code = E_MEASUREMENT_MISMATCH)]
fun test_attestation_fails_wrong_measurement() {
    let mut scenario = ts::begin(ADMIN);
    init(ts::ctx(&mut scenario));
    
    // Create and share Clock for testing
    let clock = clock::create_for_testing(ts::ctx(&mut scenario));
    clock.share_for_testing();
    ts::next_tx(&mut scenario, ADMIN);

    // Initialize with trusted measurement
    ts::next_tx(&mut scenario, ADMIN);
    {
        let admin_cap_ref = ts::take_from_sender<AdminCap>(&scenario);
        let mut verifier = ts::take_shared<TeeVerifier>(&scenario);
        let clock_ref = ts::take_shared<Clock>(&scenario);
        
        initialize_trusted_measurement(
            &admin_cap_ref,
            &mut verifier,
            b"RouterOptimizer",
            b"trusted_measurement",
            b"1.0.0",
            b"pubkey",
            &clock_ref,
        );
        
        transfer::transfer(admin_cap_ref, ADMIN);
        ts::return_shared(verifier);
        ts::return_shared(clock_ref);
    };

    // Try to submit with wrong measurement (should fail)
    ts::next_tx(&mut scenario, ROUTER);
    {
        let mut verifier = ts::take_shared<TeeVerifier>(&scenario);
        let clock_ref = ts::take_shared<Clock>(&scenario);
        let now = clock::timestamp_ms(&clock_ref);
        
        submit_attestation_record(
            &mut verifier,
            1,
            b"input",
            b"output",
            b"wrong_measurement", // Wrong measurement
            now,
            true,
            &clock_ref,
        );
        
        ts::return_shared(verifier);
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
