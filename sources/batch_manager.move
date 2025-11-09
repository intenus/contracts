module intenus::batch_manager {
    // ===== IMPORTS =====
    use sui::object;
    use sui::tx_context;
    use sui::transfer;
    use sui::table::{Self, Table};
    use sui::event;
    use sui::clock::{Self, Clock};
    use std::option::{Self, Option};
    use std::vector;

    // ===== ERRORS =====
    const E_BATCH_EXISTS: u64 = 5002;
    const E_BATCH_NOT_FOUND: u64 = 5003;
    const E_INVALID_STATUS: u64 = 5004;

    // ===== CONSTANTS =====
    const STATUS_OPEN: u8 = 0;
    const STATUS_SOLVING: u8 = 1;
    const STATUS_RANKING: u8 = 2;
    const STATUS_EXECUTED: u8 = 3;

    const DEFAULT_BATCH_DURATION_MS: u64 = 10_000;
    const DEFAULT_SOLVER_WINDOW_MS: u64 = 5_000;

    // ===== STRUCTS =====

    /// Capability for managing batch lifecycle.
    public struct AdminCap has key, store {
        id: object::UID,
    }

    public struct BatchRecord has store, drop {
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

    public struct BatchManager has key {
        id: object::UID,
        current_epoch: u64,
        batch_duration_ms: u64,
        solver_window_ms: u64,
        records: Table<u64, BatchRecord>,
        active_batch_epoch: Option<u64>,
        admin: address,
    }

    // ===== EVENTS =====

    public struct BatchStarted has copy, drop {
        batch_id: vector<u8>,
        epoch: u64,
        timestamp: u64,
    }

    public struct IntentRecorded has copy, drop {
        batch_id: vector<u8>,
        epoch: u64,
        new_intent_count: u64,
        total_value_usd: u64,
    }

    public struct BatchStatusUpdated has copy, drop {
        batch_id: vector<u8>,
        epoch: u64,
        status: u8,
    }

    public struct BatchWinnerSelected has copy, drop {
        batch_id: vector<u8>,
        epoch: u64,
        winning_solver: address,
        surplus: u64,
    }

    // ===== INITIALIZATION =====

    fun init(ctx: &mut tx_context::TxContext) {
        let admin_cap = AdminCap { id: object::new(ctx) };
        let manager = BatchManager {
            id: object::new(ctx),
            current_epoch: 0,
            batch_duration_ms: DEFAULT_BATCH_DURATION_MS,
            solver_window_ms: DEFAULT_SOLVER_WINDOW_MS,
            records: table::new(ctx),
            active_batch_epoch: option::none(),
            admin: tx_context::sender(ctx),
        };

        transfer::transfer(admin_cap, tx_context::sender(ctx));
        transfer::share_object(manager);
    }

    // ===== ENTRY FUNCTIONS =====

    /// Start a new batch for intent aggregation.
    public fun start_new_batch(
        _: &AdminCap,
        manager: &mut BatchManager,
        batch_id: vector<u8>,
        clock: &Clock
    ) {
        let next_epoch = manager.current_epoch + 1;
        assert!(
            !table::contains(&manager.records, next_epoch),
            E_BATCH_EXISTS
        );

        let record = BatchRecord {
            batch_id,
            epoch: next_epoch,
            intent_count: 0,
            total_value_usd: 0,
            solver_count: 0,
            winning_solver: option::none(),
            winning_solution_id: option::none(),
            total_surplus_generated: 0,
            status: STATUS_OPEN,
            created_at: clock::timestamp_ms(clock),
            executed_at: option::none(),
        };

        manager.current_epoch = next_epoch;
        manager.active_batch_epoch = option::some(next_epoch);
        table::add(&mut manager.records, next_epoch, record);

        event::emit(BatchStarted {
            batch_id,
            epoch: next_epoch,
            timestamp: clock::timestamp_ms(clock),
        });
    }

    /// Record intents aggregated off-chain.
    public(package) fun record_intent(
        manager: &mut BatchManager,
        epoch: u64,
        additional_intents: u64,
        additional_value_usd: u64
    ) {
        assert!(table::contains(&manager.records, epoch), E_BATCH_NOT_FOUND);
        let record = table::borrow_mut(&mut manager.records, epoch);
        assert!(record.status == STATUS_OPEN || record.status == STATUS_SOLVING, E_INVALID_STATUS);

        record.intent_count = record.intent_count + additional_intents;
        record.total_value_usd = record.total_value_usd + additional_value_usd;
        record.status = STATUS_SOLVING;

        event::emit(IntentRecorded {
            batch_id: record.batch_id,
            epoch,
            new_intent_count: record.intent_count,
            total_value_usd: record.total_value_usd,
        });
    }

    /// Close batch submissions and move to ranking.
    public(package) fun close_batch(
        manager: &mut BatchManager,
        epoch: u64
    ) {
        assert!(table::contains(&manager.records, epoch), E_BATCH_NOT_FOUND);
        let record = table::borrow_mut(&mut manager.records, epoch);
        assert!(record.status == STATUS_SOLVING || record.status == STATUS_OPEN, E_INVALID_STATUS);

        record.status = STATUS_RANKING;
        event::emit(BatchStatusUpdated {
            batch_id: record.batch_id,
            epoch,
            status: STATUS_RANKING,
        });
    }

    /// Record solver solution submission metadata.
    public(package) fun record_solution(
        manager: &mut BatchManager,
        epoch: u64
    ) {
        assert!(table::contains(&manager.records, epoch), E_BATCH_NOT_FOUND);
        let record = table::borrow_mut(&mut manager.records, epoch);
        assert!(record.status == STATUS_RANKING || record.status == STATUS_SOLVING, E_INVALID_STATUS);

        record.solver_count = record.solver_count + 1;
    }

    /// Mark winning solver and finalize batch execution.
    public(package) fun set_winner(
        manager: &mut BatchManager,
        epoch: u64,
        winner: address,
        winning_solution_id: vector<u8>,
        total_surplus_generated: u64,
        clock: &Clock
    ) {
        assert!(table::contains(&manager.records, epoch), E_BATCH_NOT_FOUND);
        let record = table::borrow_mut(&mut manager.records, epoch);
        assert!(record.status == STATUS_RANKING, E_INVALID_STATUS);

        record.winning_solver = option::some(winner);
        record.winning_solution_id = option::some(winning_solution_id);
        record.total_surplus_generated = total_surplus_generated;
        record.status = STATUS_EXECUTED;
        record.executed_at = option::some(clock::timestamp_ms(clock));

        if (option::contains(&manager.active_batch_epoch, &epoch)) {
            manager.active_batch_epoch = option::none();
        };

        event::emit(BatchWinnerSelected {
            batch_id: record.batch_id,
            epoch,
            winning_solver: winner,
            surplus: total_surplus_generated,
        });
    }

    // ===== VIEW FUNCTIONS =====

    public struct BatchSummary has copy, drop {
        batch_id: vector<u8>,
        epoch: u64,
        intent_count: u64,
        solver_count: u64,
        status: u8,
    }

    /// Get current active batch summary.
    public fun get_current_batch(manager: &BatchManager): Option<BatchSummary> {
        if (!option::is_some(&manager.active_batch_epoch)) {
            return option::none()
        };
        let epoch = *option::borrow(&manager.active_batch_epoch);
        if (!table::contains(&manager.records, epoch)) {
            return option::none()
        };
        let record = table::borrow(&manager.records, epoch);
        option::some(BatchSummary {
            batch_id: record.batch_id,
            epoch,
            intent_count: record.intent_count,
            solver_count: record.solver_count,
            status: record.status,
        })
    }

    /// Fetch statistics for a historical batch.
    public fun get_batch_stats(
        manager: &BatchManager,
        epoch: u64
    ): Option<BatchSummary> {
        if (!table::contains(&manager.records, epoch)) {
            return option::none()
        };
        let record = table::borrow(&manager.records, epoch);
        option::some(BatchSummary {
            batch_id: record.batch_id,
            epoch,
            intent_count: record.intent_count,
            solver_count: record.solver_count,
            status: record.status,
        })
    }

    // ===== TEST HELPERS =====

    #[test_only]
    public fun init_for_testing(ctx: &mut tx_context::TxContext) {
        init(ctx);
    }
}

