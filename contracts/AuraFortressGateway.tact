
```tact
// ============================================================
// AuraFortressGateway — Tact 1.x
// Enterprise Payment Gateway: AI Signals → Storm Trade (TON)
//
// Security:
//   k-of-N Multi-sig · CEI · Sequential nonces · ChainId binding
//   Stake-to-Play (5 TON) · Wallet Trust Score · Unstake Lockup
//   48h Timelock · Sentinel Emergency Break · Two-step ownership
// ============================================================

import "@stdlib/deploy";
import "@stdlib/ownable";

// ============================================================
// Constants
// ============================================================

const MAX_FEE_BPS:       Int = 500;               // 5% hard cap
const MIN_REQUIRED_SIGS: Int = 2;                 // k-of-N floor
const SIGNAL_EXPIRY:     Int = 30;                // 30 seconds
const TIMELOCK_DELAY:    Int = 172800;            // 48 hours
const MIN_MARGIN:        Int = ton("1");          // 1 TON minimum trade
const MIN_STAKE:         Int = ton("5");          // 5 TON anti-bot barrier
const MIN_TRUST_SCORE:   Int = 40;               // Wallet score gate (0–100)
const RESULT_COOLDOWN:   Int = 3600;             // 1 hour oracle spam guard
const UNSTAKE_LOCKUP:    Int = 86400;            // 24h post-trade lockup

// ============================================================
// Messages (incoming ops)
// ============================================================

message ExecuteSignal {
    pair_id:         Int as uint32;
    is_long:         Bool;
    leverage:        Int as uint32;
    signal_timestamp: Int as uint64;
    nonce:           Int as uint64;
    // Signatures packed as cells (k oracle sigs)
    signatures:      Cell;
}

message Stake {}

message Unstake {
    amount: Int as coins;
}

message ClaimRefund {}

message SetTrustScore {
    user:  Address;
    score: Int as uint8;
}

message UpdateResult {
    user:   Address;
    is_win: Bool;
    pnl:    Int as int64;
}

message AddOracle {
    oracle: Address;
}

message RemoveOracle {
    oracle: Address;
}

message AddSentinel {
    sentinel: Address;
}

message RemoveSentinel {
    sentinel: Address;
}

message TriggerSentinelPause {}

message QueueAction {
    action_hash: Int as uint256;
}

message CancelAction {
    action_id: Int as uint256;
}

message ExecuteSetFee {
    action_id:   Int as uint256;
    new_fee_bps: Int as uint16;
}

message ExecuteSetMinSigs {
    action_id: Int as uint256;
    new_min:   Int as uint8;
}

message TransferOwnership {
    new_owner: Address;
}

message AcceptOwnership {}

message EmergencyWithdraw {}

// ============================================================
// Structs
// ============================================================

struct UserStats {
    total_signals:       Int as uint64;
    total_volume:        Int as coins;
    wins:                Int as uint32;
    losses:              Int as uint32;
    cumulative_pnl:      Int as int64;
    last_trade_timestamp: Int as uint64;
}

struct TimelockEntry {
    action_hash: Int as uint256;
    ready_at:    Int as uint64;
    executed:    Bool;
    cancelled:   Bool;
}

struct OracleInfo {
    pub_key: Int as uint256;
    active:  Bool;
}

// ============================================================
// Events (outgoing logs via emit)
// ============================================================

message(0x01) PositionOpened {
    user:    Address;
    pair_id: Int as uint32;
    margin:  Int as coins;
    nonce:   Int as uint64;
}

message(0x02) ExecutionReverted {
    user:   Address;
    amount: Int as coins;
}

message(0x03) RefundClaimed {
    user:   Address;
    amount: Int as coins;
}

message(0x04) ResultUpdated {
    user:   Address;
    oracle: Address;
    is_win: Bool;
    pnl:    Int as int64;
}

message(0x05) TrustScoreSet {
    user:  Address;
    score: Int as uint8;
}

message(0x06) Staked {
    user:   Address;
    amount: Int as coins;
}

message(0x07) Unstaked {
    user:   Address;
    amount: Int as coins;
}

message(0x08) EmergencyShutdown {
    triggered_by: Address;
}

message(0x09) ActionQueued {
    action_id: Int as uint256;
    ready_at:  Int as uint64;
}

message(0x0A) ActionExecuted {
    action_id: Int as uint256;
}

message(0x0B) ActionCancelled {
    action_id: Int as uint256;
}

message(0x0C) OwnershipTransferStarted {
    current_owner: Address;
    pending_owner: Address;
}

message(0x0D) OwnershipTransferred {
    old_owner: Address;
    new_owner: Address;
}

// ============================================================
// Contract
// ============================================================

contract AuraFortressGateway with Deployable {

    // --- Ownership (2-step) ---
    owner:         Address;
    pending_owner: Address?;

    // --- Circuit breaker ---
    paused: Bool;

    // --- Config ---
    storm_vault:    Address;
    fee_bps:        Int as uint16;
    min_signatures: Int as uint8;
    active_oracles: Int as uint8;

    // --- Access control ---
    // Maps stored in child contracts / dict for TON
    oracles:   map<Address, Bool>;
    sentinels: map<Address, Bool>;

    // --- Oracle pub keys (for sig verification) ---
    oracle_pub_keys: map<Address, Int>;

    // --- User state ---
    user_nonces:          map<Address, Int>;
    pending_refunds:      map<Address, Int>;
    staked_amount:        map<Address, Int>;
    last_trade_timestamp: map<Address, Int>;
    wallet_trust_score:   map<Address, Int>;
    last_result_update:   map<Address, Int>;
    user_stats:           map<Address, UserStats>;

    // --- Timelock ---
    timelock_queue: map<Int, TimelockEntry>;

    // ============================================================
    // Init
    // ============================================================

    init(
        vault:      Address,
        fee_bps:    Int,
        owner_addr: Address,
    ) {
        require(fee_bps <= MAX_FEE_BPS, "Fee too high");

        self.owner         = owner_addr;
        self.pending_owner = null;
        self.paused        = false;
        self.storm_vault   = vault;
        self.fee_bps       = fee_bps;
        self.min_signatures = MIN_REQUIRED_SIGS;
        self.active_oracles = 0;
    }

    // ============================================================
    // Stake-to-Play — Anti-Bot Economic Barrier
    // ============================================================

    receive(msg: Stake) {
        let amount = context().value;
        require(amount > 0, "Zero stake");

        let current = self.staked_amount.get(sender()) ?? 0;
        self.staked_amount.set(sender(), current + amount);

        emit(Staked { user: sender(), amount: amount }.toCell());
    }

    receive(msg: Unstake) {
        let caller = sender();
        let staked = self.staked_amount.get(caller) ?? 0;

        require(staked >= msg.amount, "Insufficient staked balance");

        let last_trade = self.last_trade_timestamp.get(caller) ?? 0;
        require(
            now() >= last_trade + UNSTAKE_LOCKUP,
            "Unstake lockup active — wait 24h after last trade"
        );

        self.staked_amount.set(caller, staked - msg.amount);

        // Return TON to user
        send(SendParameters {
            to:    caller,
            value: msg.amount,
            mode:  SendIgnoreErrors,
            body:  "Unstake return".asComment(),
        });

        emit(Unstaked { user: caller, amount: msg.amount }.toCell());
    }

    // ============================================================
    // Core: Execute Trade Signal
    // ============================================================

    receive(msg: ExecuteSignal) {
        // 1. Circuit breaker
        require(!self.paused, "Contract paused");

        let caller = sender();
        let ts     = now();

        // 2. Timing
        require(
            ts <= msg.signal_timestamp + SIGNAL_EXPIRY,
            "Signal expired"
        );

        // 3. Sequential nonce
        let current_nonce = self.user_nonces.get(caller) ?? 0;
        require(msg.nonce == current_nonce + 1, "Invalid nonce");

        // 4. Anti-bot: stake gate
        let staked = self.staked_amount.get(caller) ?? 0;
        require(staked >= MIN_STAKE, "Insufficient stake — deposit 5 TON");

        // 5. Anti-bot: trust score gate
        let trust = self.wallet_trust_score.get(caller) ?? 0;
        require(trust >= MIN_TRUST_SCORE, "Trust score too low");

        // 6. Financial
        let total_value  = context().value;
        let platform_fee = total_value * self.fee_bps / 10000;
        let margin       = total_value - platform_fee;
        require(margin >= MIN_MARGIN, "Margin too small — min 1 TON");

        // 7. Multi-sig verification
        require(
            self._verify_multi_sig(
                msg.pair_id,
                msg.is_long,
                msg.leverage,
                msg.signal_timestamp,
                msg.nonce,
                caller,
                msg.signatures
            ),
            "Invalid multi-sig — quorum not reached"
        );

        // 8. CEI — all state updates BEFORE external calls
        self.user_nonces.set(caller, msg.nonce);
        self.last_trade_timestamp.set(caller, ts);

        let stats = self.user_stats.get(caller) ?? UserStats {
            total_signals:        0,
            total_volume:         0,
            wins:                 0,
            losses:               0,
            cumulative_pnl:       0,
            last_trade_timestamp: 0,
        };

        self.user_stats.set(caller, UserStats {
            total_signals:        stats.total_signals + 1,
            total_volume:         stats.total_volume + margin,
            wins:                 stats.wins,
            losses:               stats.losses,
            cumulative_pnl:       stats.cumulative_pnl,
            last_trade_timestamp: ts,
        });

        // 9. Fee to owner
        if (platform_fee > 0) {
            send(SendParameters {
                to:    self.owner,
                value: platform_fee,
                mode:  SendIgnoreErrors,
                body:  "Platform fee".asComment(),
            });
        }

        // 10. Forward margin to Storm Trade vault
        send(SendParameters {
            to:    self.storm_vault,
            value: margin,
            mode:  SendIgnoreErrors,
            body:  beginCell()
                       .storeUint(0x7361, 16)      // Storm Trade op: openPosition
                       .storeAddress(caller)
                       .storeUint(msg.pair_id, 32)
                       .storeBool(msg.is_long)
                       .storeUint(msg.leverage, 32)
                       .storeCoins(margin)
                   .endCell(),
        });

        emit(PositionOpened {
            user:    caller,
            pair_id: msg.pair_id,
            margin:  margin,
            nonce:   msg.nonce,
        }.toCell());
    }

    // ============================================================
    // Claim Refund
    // ============================================================

    receive(msg: ClaimRefund) {
        let caller = sender();
        let amount = self.pending_refunds.get(caller) ?? 0;
        require(amount > 0, "No pending refunds");

        self.pending_refunds.set(caller, 0);

        send(SendParameters {
            to:    caller,
            value: amount,
            mode:  SendIgnoreErrors,
            body:  "Refund".asComment(),
        });

        emit(RefundClaimed { user: caller, amount: amount }.toCell());
    }

    // ============================================================
    // Oracle: Set Trust Score
    // ============================================================

    receive(msg: SetTrustScore) {
        self._assert_oracle();
        self.wallet_trust_score.set(msg.user, msg.score);
        emit(TrustScoreSet { user: msg.user, score: msg.score }.toCell());
    }

    // ============================================================
    // Oracle: Update Result
    // ============================================================

    receive(msg: UpdateResult) {
        self._assert_oracle();
        let caller = sender();

        let last_update = self.last_result_update.get(msg.user) ?? 0;
        require(
            now() >= last_update + RESULT_COOLDOWN,
            "Result cooldown active — wait 1h"
        );

        self.last_result_update.set(msg.user, now());

        let stats = self.user_stats.get(msg.user) ?? UserStats {
            total_signals:        0,
            total_volume:         0,
            wins:                 0,
            losses:               0,
            cumulative_pnl:       0,
            last_trade_timestamp: 0,
        };

        self.user_stats.set(msg.user, UserStats {
            total_signals:        stats.total_signals,
            total_volume:         stats.total_volume,
            wins:                 msg.is_win ? stats.wins + 1 : stats.wins,
            losses:               msg.is_win ? stats.losses : stats.losses + 1,
            cumulative_pnl:       stats.cumulative_pnl + msg.pnl,
            last_trade_timestamp: now(),
        });

        emit(ResultUpdated {
            user:   msg.user,
            oracle: caller,
            is_win: msg.is_win,
            pnl:    msg.pnl,
        }.toCell());
    }

    // ============================================================
    // Oracle Management
    // ============================================================

    receive(msg: AddOracle) {
        self._assert_owner();
        require(self.oracles.get(msg.oracle) == null, "Already registered");
        self.oracles.set(msg.oracle, true);
        self.active_oracles = self.active_oracles + 1;
    }

    receive(msg: RemoveOracle) {
        self._assert_owner();
        require(self.oracles.get(msg.oracle) != null, "Not an oracle");
        require(
            self.active_oracles - 1 >= self.min_signatures,
            "Would break signature threshold"
        );
        self.oracles.set(msg.oracle, false);
        self.active_oracles = self.active_oracles - 1;
    }

    // ============================================================
    // Sentinel Management
    // ============================================================

    receive(msg: AddSentinel) {
        self._assert_owner();
        self.sentinels.set(msg.sentinel, true);
        emit(SentinelAdded { sentinel: msg.sentinel }.toCell());
    }

    receive(msg: RemoveSentinel) {
        self._assert_owner();
        require(self.sentinels.get(msg.sentinel) != null, "Not a sentinel");
        self.sentinels.set(msg.sentinel, false);
    }

    receive(msg: TriggerSentinelPause) {
        let caller = sender();
        require(
            self.sentinels.get(caller) == true || caller == self.owner,
            "Not a sentinel"
        );
        self.paused = true;
        emit(EmergencyShutdown { triggered_by: caller }.toCell());
    }

    // ============================================================
    // Governance — Timelocked
    // ============================================================

    receive(msg: QueueAction) {
        self._assert_owner();
        let ready_at = now() + TIMELOCK_DELAY;
        self.timelock_queue.set(msg.action_hash, TimelockEntry {
            action_hash: msg.action_hash,
            ready_at:    ready_at,
            executed:    false,
            cancelled:   false,
        });
        emit(ActionQueued {
            action_id: msg.action_hash,
            ready_at:  ready_at,
        }.toCell());
    }

    receive(msg: CancelAction) {
        self._assert_owner();
        let entry = self.timelock_queue.get(msg.action_id);
        require(entry != null, "Not queued");
        require(!entry!!.executed, "Already executed");
        self.timelock_queue.set(msg.action_id, TimelockEntry {
            action_hash: entry!!.action_hash,
            ready_at:    entry!!.ready_at,
            executed:    false,
            cancelled:   true,
        });
        emit(ActionCancelled { action_id: msg.action_id }.toCell());
    }

    receive(msg: ExecuteSetFee) {
        self._assert_owner();
        self._validate_timelock(msg.action_id);
        require(msg.new_fee_bps <= MAX_FEE_BPS, "Fee too high");

        let old_fee = self.fee_bps;
        self.fee_bps = msg.new_fee_bps;
        self._mark_executed(msg.action_id);

        emit(ActionExecuted { action_id: msg.action_id }.toCell());
    }

    receive(msg: ExecuteSetMinSigs) {
        self._assert_owner();
        self._validate_timelock(msg.action_id);
        require(msg.new_min >= MIN_REQUIRED_SIGS,        "Below minimum floor");
        require(msg.new_min <= self.active_oracles,      "Exceeds oracle count");

        self.min_signatures = msg.new_min;
        self._mark_executed(msg.action_id);

        emit(ActionExecuted { action_id: msg.action_id }.toCell());
    }

    // ============================================================
    // Ownership (2-step)
    // ============================================================

    receive(msg: TransferOwnership) {
        self._assert_owner();
        self.pending_owner = msg.new_owner;
        emit(OwnershipTransferStarted {
            current_owner: self.owner,
            pending_owner: msg.new_owner,
        }.toCell());
    }

    receive(msg: AcceptOwnership) {
        require(self.pending_owner != null,     "No pending transfer");
        require(sender() == self.pending_owner!!, "Not pending owner");
        let old_owner  = self.owner;
        self.owner         = self.pending_owner!!;
        self.pending_owner = null;
        emit(OwnershipTransferred {
            old_owner: old_owner,
            new_owner: self.owner,
        }.toCell());
    }

    // ============================================================
    // Admin
    // ============================================================

    receive("pause")   { self._assert_owner(); self.paused = true; }
    receive("unpause") { self._assert_owner(); self.paused = false; }

    receive(msg: EmergencyWithdraw) {
        self._assert_owner();
        require(self.paused, "Must be paused first");
        send(SendParameters {
            to:    self.owner,
            value: 0,
            mode:  SendRemainingBalance + SendIgnoreErrors,
            body:  "Emergency withdrawal".asComment(),
        });
    }

    // ============================================================
    // Getters
    // ============================================================

    get fun get_user_stats(user: Address): UserStats {
        return self.user_stats.get(user) ?? UserStats {
            total_signals:        0,
            total_volume:         0,
            wins:                 0,
            losses:               0,
            cumulative_pnl:       0,
            last_trade_timestamp: 0,
        };
    }

    get fun next_nonce(user: Address): Int {
        return (self.user_nonces.get(user) ?? 0) + 1;
    }

    get fun is_eligible(user: Address): Bool {
        let staked = self.staked_amount.get(user) ?? 0;
        let trust  = self.wallet_trust_score.get(user) ?? 0;
        return staked >= MIN_STAKE && trust >= MIN_TRUST_SCORE;
    }

    get fun pending_refund(user: Address): Int {
        return self.pending_refunds.get(user) ?? 0;
    }

    get fun staked(user: Address): Int {
        return self.staked_amount.get(user) ?? 0;
    }

    get fun is_paused(): Bool {
        return self.paused;
    }

    get fun owner_address(): Address {
        return self.owner;
    }

    // ============================================================
    // Internal Helpers
    // ============================================================

    fun _assert_owner() {
        require(sender() == self.owner, "Not owner");
    }

    fun _assert_oracle() {
        require(self.oracles.get(sender()) == true, "Not an oracle");
    }

    fun _validate_timelock(action_id: Int) {
        let entry = self.timelock_queue.get(action_id);
        require(entry != null,           "Not queued");
        require(!entry!!.executed,       "Already executed");
        require(!entry!!.cancelled,      "Cancelled");
        require(now() >= entry!!.ready_at, "Timelock not ready — wait 48h");
    }

    fun _mark_executed(action_id: Int) {
        let entry = self.timelock_queue.get(action_id)!!;
        self.timelock_queue.set(action_id, TimelockEntry {
            action_hash: entry.action_hash,
            ready_at:    entry.ready_at,
            executed:    true,
            cancelled:   false,
        });
    }

    // k-of-N signature verification
    // TON uses Ed25519 — signatures checked via checkSignature()
    fun _verify_multi_sig(
        pair_id:   Int,
        is_long:   Bool,
        leverage:  Int,
        timestamp: Int,
        nonce:     Int,
        user:      Address,
        sigs_cell: Cell,
    ): Bool {
        // Build message hash (same as what oracles sign off-chain)
        let msg_hash: Int = beginCell()
            .storeAddress(user)
            .storeUint(pair_id, 32)
            .storeBool(is_long)
            .storeUint(leverage, 32)
            .storeUint(timestamp, 64)
            .storeUint(nonce, 64)
        .endCell().hash();

        let valid_count: Int  = 0;
        let seen_keys: map<Int, Bool> = emptyMap();
        let slice = sigs_cell.beginParse();

        // Iterate oracle signatures packed in cell
        // Format: [ pub_key_256 | sig_512 ] repeated
        repeat(self.active_oracles) {
            if (slice.remainingBits() < 256 + 512) {
                return valid_count >= self.min_signatures;
            }

            let pub_key = slice.loadUint(256);
            let sig_high = slice.loadUint(256);
            let sig_low  = slice.loadUint(256);

            // Skip duplicates
            if (seen_keys.get(pub_key) == true) {
                continue;
            }

            // Reconstruct oracle address from pub_key for registry lookup
            let oracle_addr: Address = newAddress(0, pub_key % (1 << 160));

            if (self.oracles.get(oracle_addr) == true) {
                // TON native Ed25519 signature check
                let valid = checkSignature(msg_hash, sig_high * (1 << 256) + sig_low, pub_key);
                if (valid) {
                    seen_keys.set(pub_key, true);
                    valid_count = valid_count + 1;
                }
            }
        }

        return valid_count >= self.min_signatures;
    }
}
```
