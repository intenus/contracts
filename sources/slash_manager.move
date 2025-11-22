module intenus::slash_manager;

use intenus::tee_verifier::{Self, TeeVerifier};
use std::string;
use sui::clock::{Self, Clock};
use sui::display;
use sui::event;
use sui::package;
use sui::table::{Self, Table};
use sui::transfer::Receiving;
use sui::vec_map::{Self, VecMap};

// ===== ERRORS =====
const E_UNAUTHORIZED: u64 = 6001;
const E_INVALID_SEVERITY: u64 = 6003;
const E_APPEAL_ALREADY_FILED: u64 = 6004;
const E_APPEAL_NOT_FOUND: u64 = 6005;
const E_APPEAL_WINDOW_EXPIRED: u64 = 6006;
const E_INVALID_TEE_ATTESTATION: u64 = 6009;
const E_TRANSFER_REJECTED: u64 = 6010;

// ===== CONSTANTS =====
const SEVERITY_MINOR: u8 = 1;
const SEVERITY_SIGNIFICANT: u8 = 2;
const SEVERITY_MALICIOUS: u8 = 3;

const MINOR_SLASH_BPS: u64 = 500; // 5%
const SIGNIFICANT_SLASH_BPS: u64 = 2000; // 20%
const MALICIOUS_SLASH_BPS: u64 = 10000; // 100%

const APPEAL_WINDOW_MS: u64 = 86_400_000; // 24 hours

// ===== STRUCTS =====

/// Capability for admin operations
public struct AdminCap has key, store {
    id: UID,
}

/// TEE evidence for slashing
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

/// Soulbound NFT representing a slash (cannot be transferred)
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

public struct Appeal has key, store {
    id: UID,
    slash_id: ID,
    solver_address: address,
    reason: vector<u8>,
    counter_evidence: vector<u8>,
    created_at: u64,
    status: u8,
}

public struct SlashManager has key {
    id: UID,
    solver_slashes: Table<address, VecMap<ID, u8>>,
    appeals: Table<ID, ID>,
    total_slashes: u64,
    total_warnings_issued: u64,
    admin: address,
}

public struct SlashIndex has copy, drop, store {
    severity: u8,
    created_at: u64,
    appealed: bool,
    appeal_approved: bool,
}

public struct SLASH_MANAGER has drop {}

// ===== EVENTS =====

public struct SlashCreated has copy, drop {
    slash_id: ID,
    solver_address: address,
    batch_id: u64,
    solution_id: vector<u8>,
    severity: u8,
    reason: vector<u8>,
    slash_percentage_bps: u64,
    timestamp: u64,
}

public struct AppealFiled has copy, drop {
    slash_id: ID,
    appeal_id: ID,
    solver_address: address,
    timestamp: u64,
}

public struct AppealResolved has copy, drop {
    slash_id: ID,
    appeal_id: ID,
    solver_address: address,
    approved: bool,
    resolution_timestamp: u64,
}

public struct WarningIssued has copy, drop {
    solver_address: address,
    reason: vector<u8>,
    timestamp: u64,
}

public struct SlashRecordLock has drop {}

// ===== INITIALIZATION =====

fun init(witness: SLASH_MANAGER, ctx: &mut TxContext) {
    let admin_cap = AdminCap {
        id: object::new(ctx),
    };

    let manager = SlashManager {
        id: object::new(ctx),
        solver_slashes: table::new(ctx),
        appeals: table::new(ctx),
        total_slashes: 0,
        total_warnings_issued: 0,
        admin: tx_context::sender(ctx),
    };

    let publisher = package::claim(witness, ctx);
    let keys = vector[
        string::utf8(b"name"),
        string::utf8(b"description"),
        string::utf8(b"image_url"),
        string::utf8(b"severity"),
        string::utf8(b"reason"),
        string::utf8(b"percentage"),
        string::utf8(b"batch"),
        string::utf8(b"created_at"),
    ];
    let values = vector[
        string::utf8(b"Intenus Slash #{severity}"),
        string::utf8(b"This represents a slashing penalty for {reason}"),
        string::utf8(b"https://intenus.io/assets/slash_{severity}.png"),
        string::utf8(b"{severity}"),
        string::utf8(b"{reason}"),
        string::utf8(b"{slash_percentage_bps} bps"),
        string::utf8(b"{batch_id}"),
        string::utf8(b"{created_at}"),
    ];
    let mut display = display::new_with_fields<SlashRecord>(&publisher, keys, values, ctx);
    display::update_version(&mut display);

    transfer::transfer(admin_cap, tx_context::sender(ctx));
    transfer::public_transfer(publisher, tx_context::sender(ctx));
    transfer::public_transfer(display, tx_context::sender(ctx));
    transfer::share_object(manager);
}

// ===== ENTRY FUNCTIONS =====

/// Submit a slash with TEE evidence, create soulbound NFT and apply penalty
/// Note: Caller should verify solver exists before calling this function
public entry fun submit_slash(
    manager: &mut SlashManager,
    verifier: &TeeVerifier,
    evidence: SlashEvidence,
    clock: &Clock,
    ctx: &mut TxContext,
) {
    verify_tee_evidence(verifier, &evidence, clock);

    assert!(
        evidence.severity == SEVERITY_MINOR || 
            evidence.severity == SEVERITY_SIGNIFICANT || 
            evidence.severity == SEVERITY_MALICIOUS,
        E_INVALID_SEVERITY,
    );

    // Issue warning for first-time minor offenses
    if (
        evidence.severity == SEVERITY_MINOR && 
            !has_active_slashes(manager, evidence.solver_address)
    ) {
        issue_warning(
            manager,
            evidence.solver_address,
            evidence.reason_message,
            clock,
        );
        return
    };

    let slash_percentage_bps = calculate_slash_percentage(evidence.severity);
    let current_time = clock::timestamp_ms(clock);
    let slash_id = object::new(ctx);
    let slash_uid = object::uid_to_inner(&slash_id);

    let slash_nft = SlashRecord {
        id: slash_id,
        solver_address: evidence.solver_address,
        batch_id: evidence.batch_id,
        solution_id: evidence.solution_id,
        severity: evidence.severity,
        reason: evidence.reason_message,
        slash_percentage_bps,
        created_at: current_time,
        appealed: false,
        appeal_approved: false,
    };

    register_slash(
        manager,
        evidence.solver_address,
        slash_uid,
        evidence.severity,
    );

    transfer::transfer(slash_nft, evidence.solver_address);
    manager.total_slashes = manager.total_slashes + 1;

    event::emit(SlashCreated {
        slash_id: slash_uid,
        solver_address: evidence.solver_address,
        batch_id: evidence.batch_id,
        solution_id: evidence.solution_id,
        severity: evidence.severity,
        reason: evidence.reason_message,
        slash_percentage_bps,
        timestamp: current_time,
    });
}

public entry fun file_appeal(
    manager: &mut SlashManager,
    slash_record: &mut SlashRecord,
    appeal_reason: vector<u8>,
    counter_evidence: vector<u8>,
    clock: &Clock,
    ctx: &mut TxContext,
) {
    let sender = tx_context::sender(ctx);
    assert!(sender == slash_record.solver_address, E_UNAUTHORIZED);

    let current_time = clock::timestamp_ms(clock);
    assert!(current_time < slash_record.created_at + APPEAL_WINDOW_MS, E_APPEAL_WINDOW_EXPIRED);
    assert!(!slash_record.appealed, E_APPEAL_ALREADY_FILED);

    slash_record.appealed = true;

    let appeal_id = object::new(ctx);
    let slash_id = object::uid_to_inner(&slash_record.id);
    let appeal_uid = object::uid_to_inner(&appeal_id);

    let appeal = Appeal {
        id: appeal_id,
        slash_id: slash_id,
        solver_address: sender,
        reason: appeal_reason,
        counter_evidence,
        created_at: current_time,
        status: 0,
    };

    table::add(&mut manager.appeals, slash_id, appeal_uid);
    update_slash_index(manager, sender, slash_id, slash_record.severity, true, false);
    transfer::share_object(appeal);

    event::emit(AppealFiled {
        slash_id: slash_id,
        appeal_id: appeal_uid,
        solver_address: sender,
        timestamp: current_time,
    });
}

public entry fun resolve_appeal(
    _admin_cap: &AdminCap,
    manager: &mut SlashManager,
    slash_record: &mut SlashRecord,
    appeal: &mut Appeal,
    approved: bool,
    clock: &Clock,
) {
    let slash_id = object::uid_to_inner(&slash_record.id);
    assert!(appeal.slash_id == slash_id, E_APPEAL_NOT_FOUND);
    assert!(table::contains(&manager.appeals, slash_id), E_APPEAL_NOT_FOUND);

    appeal.status = if (approved) { 1 } else { 2 };
    slash_record.appeal_approved = approved;

    update_slash_index(
        manager,
        slash_record.solver_address,
        slash_id,
        slash_record.severity,
        true,
        approved,
    );

    event::emit(AppealResolved {
        slash_id,
        appeal_id: object::uid_to_inner(&appeal.id),
        solver_address: slash_record.solver_address,
        approved,
        resolution_timestamp: clock::timestamp_ms(clock),
    });
}

// ===== VIEW FUNCTIONS =====

public fun get_solver_slashes(manager: &SlashManager, solver: address): VecMap<ID, u8> {
    if (!table::contains(&manager.solver_slashes, solver)) {
        return vec_map::empty<ID, u8>()
    };
    *table::borrow(&manager.solver_slashes, solver)
}

/// Calculate total slash percentage for withdrawals (capped at 100%)
public fun calculate_total_slash_percentage(manager: &SlashManager, solver: address): u64 {
    if (!table::contains(&manager.solver_slashes, solver)) {
        return 0
    };

    let slashes = table::borrow(&manager.solver_slashes, solver);
    let mut total_bps = 0;
    let keys = vec_map::keys(slashes);
    let len = vector::length(&keys);

    let mut i = 0;
    while (i < len) {
        let slash_id = *vector::borrow(&keys, i);
        let severity = *vec_map::get(slashes, &slash_id);
        let appealed_and_approved = is_slash_appealed_and_approved(manager, slash_id);

        if (!appealed_and_approved) {
            total_bps = total_bps + calculate_slash_percentage(severity);
        };

        i = i + 1;
    };

    if (total_bps > 10000) { 10000 } else { total_bps }
}

public fun is_slash_appealed_and_approved(manager: &SlashManager, slash_id: ID): bool {
    if (!table::contains(&manager.appeals, slash_id)) {
        return false
    };
    // TODO: implement appeal status check
    false
}

public fun has_active_slashes(manager: &SlashManager, solver: address): bool {
    if (!table::contains(&manager.solver_slashes, solver)) {
        return false
    };

    let slashes = table::borrow(&manager.solver_slashes, solver);
    !vec_map::is_empty(slashes)
}


// ===== INTERNAL HELPERS =====

fun register_slash(manager: &mut SlashManager, solver: address, slash_id: ID, severity: u8) {
    if (!table::contains(&manager.solver_slashes, solver)) {
        table::add(&mut manager.solver_slashes, solver, vec_map::empty<ID, u8>());
    };

    let solver_slashes = table::borrow_mut(&mut manager.solver_slashes, solver);
    vec_map::insert(solver_slashes, slash_id, severity);
}

fun update_slash_index(
    manager: &mut SlashManager,
    solver: address,
    slash_id: ID,
    severity: u8,
    appealed: bool,
    appeal_approved: bool,
) {
    if (table::contains(&manager.solver_slashes, solver)) {
        let solver_slashes = table::borrow_mut(&mut manager.solver_slashes, solver);

        if (appealed && appeal_approved) {
            vec_map::remove(solver_slashes, &slash_id);
        } else if (vec_map::contains(solver_slashes, &slash_id)) {
            *vec_map::get_mut(solver_slashes, &slash_id) = severity;
        };
    };
}

fun verify_tee_evidence(verifier: &TeeVerifier, evidence: &SlashEvidence, clock: &Clock) {
    assert!(
        tee_verifier::verify_measurement_match(verifier, &evidence.tee_measurement),
        E_INVALID_TEE_ATTESTATION,
    );

    assert!(
        tee_verifier::check_timestamp_freshness(evidence.attestation_timestamp, clock),
        E_INVALID_TEE_ATTESTATION,
    );
}

fun calculate_slash_percentage(severity: u8): u64 {
    if (severity == SEVERITY_MINOR) {
        MINOR_SLASH_BPS
    } else if (severity == SEVERITY_SIGNIFICANT) {
        SIGNIFICANT_SLASH_BPS
    } else {
        MALICIOUS_SLASH_BPS
    }
}

fun issue_warning(manager: &mut SlashManager, solver: address, reason: vector<u8>, clock: &Clock) {
    manager.total_warnings_issued = manager.total_warnings_issued + 1;

    event::emit(WarningIssued {
        solver_address: solver,
        reason,
        timestamp: clock::timestamp_ms(clock),
    });
}

// ===== TEST HELPERS =====
#[test_only]
use sui::test_scenario::{Self as ts};

#[test_only]
const ADMIN: address = @0xA;
#[test_only]
const SOLVER: address = @0xB;
#[test_only]
const TEE_OPERATOR: address = @0xC;

#[test_only]
public fun init_for_testing(ctx: &mut TxContext) {
    init(SLASH_MANAGER {}, ctx);
}
