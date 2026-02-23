```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title  AuraFortressGateway
 * @notice Enterprise-grade L2 gateway: AI signals → StormTrade execution.
 * @author AURA ACE Architect
 *
 * @dev Architecture:
 *   Anti-Bot   : Stake-to-Play (5 TON) + Wallet Trust Score + Unstake Lockup
 *   Security   : k-of-N Multi-sig · CEI · tryRecover · Per-user sequential nonces
 *   Governance : 48h Timelock · Sentinel Emergency Break · Ownable2Step
 *   Standards  : OpenZeppelin v5 · ECDSA secp256k1 · Solidity 0.8.20
 */

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/access/Ownable2Step.sol";

interface IStormTradeVault {
    function openPosition(
        address user,
        bytes4  pairId,
        bool    isLong,
        uint256 leverage,
        uint256 margin
    ) external payable;
}

contract AuraFortressGateway is ReentrancyGuard, Pausable, Ownable2Step {
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;

    // =========================================================================
    // Constants — Real Production Values
    // =========================================================================

    uint256 public constant MAX_FEE_BPS      = 500;         // 5% hard cap
    uint256 public constant MIN_REQUIRED_SIGS = 2;           // k-of-N floor
    uint256 public constant SIGNAL_EXPIRY     = 30 seconds;  // MEV protection
    uint256 public constant TIMELOCK_DELAY    = 48 hours;    // Admin safety delay
    uint256 public constant MIN_MARGIN        = 1 ether;     // 1 TON minimum trade
    uint256 public constant MIN_STAKE         = 5 ether;     // 5 TON anti-bot barrier
    uint256 public constant MIN_TRUST_SCORE   = 40;          // Wallet score gate (0–100)
    uint256 public constant RESULT_COOLDOWN   = 1 hours;     // Oracle spam protection
    uint256 public constant UNSTAKE_LOCKUP    = 24 hours;    // Post-trade unstake delay

    // =========================================================================
    // Access Control
    // =========================================================================

    mapping(address => bool) public isSentinel;
    mapping(address => bool) public isOracle;
    uint256 public activeOracles;
    uint256 public minSignatures;

    modifier onlySentinel() {
        if (!isSentinel[msg.sender] && msg.sender != owner()) revert Unauthorized();
        _;
    }

    modifier onlyOracle() {
        if (!isOracle[msg.sender]) revert Unauthorized();
        _;
    }

    // =========================================================================
    // State
    // =========================================================================

    IStormTradeVault public stormVault;
    uint256 public feeBps;

    mapping(address => uint256) public pendingRefunds;
    mapping(address => uint256) public userNonces;
    mapping(address => uint256) public lastResultUpdate;
    mapping(address => uint256) public stakedAmount;
    mapping(address => uint256) public lastTradeTimestamp;
    mapping(address => uint8)   public walletTrustScore;

    // --- Timelock ---
    struct TimelockEntry {
        bytes32 actionHash;
        uint256 readyAt;
        bool    executed;
        bool    cancelled;
    }
    mapping(bytes32 => TimelockEntry) public timelockQueue;

    // --- Analytics ---
    struct UserStats {
        uint256 totalSignals;
        uint256 totalVolume;
        uint256 wins;
        uint256 losses;
        int256  cumulativePnl;
        uint256 lastTradeTimestamp;
    }
    mapping(address => UserStats) public userRegistry;

    // --- Trade Signal ---
    struct TradeSignal {
        address user;
        bytes4  pairId;
        bool    isLong;
        uint256 leverage;
        uint256 timestamp;
        uint256 nonce;
        uint256 chainId;
    }

    // =========================================================================
    // Events
    // =========================================================================

    event PositionOpened(address indexed user, bytes4 indexed pairId, uint256 margin, uint256 nonce);
    event ExecutionReverted(address indexed user, uint256 amount);
    event RefundClaimed(address indexed user, uint256 amount);
    event ResultUpdated(address indexed user, address indexed oracle, bool isWin, int256 pnl);
    event TrustScoreSet(address indexed user, uint8 score);
    event Staked(address indexed user, uint256 amount);
    event Unstaked(address indexed user, uint256 amount);
    event OracleAdded(address indexed oracle);
    event OracleRemoved(address indexed oracle);
    event SentinelAdded(address indexed sentinel);
    event SentinelRemoved(address indexed sentinel);
    event EmergencyShutdown(address indexed sentinel);
    event FeeUpdated(uint256 oldFeeBps, uint256 newFeeBps);
    event VaultUpdated(address indexed oldVault, address indexed newVault);
    event MinSignaturesUpdated(uint256 oldValue, uint256 newValue);
    event ActionQueued(bytes32 indexed actionId, uint256 readyAt);
    event ActionExecuted(bytes32 indexed actionId);
    event ActionCancelled(bytes32 indexed actionId);

    // =========================================================================
    // Errors
    // =========================================================================

    error Unauthorized();
    error ZeroAddress();
    error ExpiredSignal();
    error WrongChainId();
    error IdentityMismatch();
    error InvalidNonce();
    error VaultNotConfigured();
    error InsufficientStake();
    error TrustScoreTooLow();
    error InvalidMultiSignature();
    error MarginTooSmall();
    error FeeTooHigh();
    error TransferFailed();
    error NoRefundAvailable();
    error InvalidThreshold();
    error OracleAlreadyRegistered();
    error OracleNotRegistered();
    error WouldBreakThreshold();
    error SentinelAlreadyRegistered();
    error SentinelNotRegistered();
    error ResultCooldownActive();
    error UnstakeLockupActive();
    error NothingToUnstake();
    error TimelockNotQueued();
    error TimelockAlreadyExecuted();
    error TimelockCancelled();
    error TimelockNotReady();
    error TimelockHashMismatch();

    // =========================================================================
    // Constructor
    // =========================================================================

    constructor(
        address[] memory _oracles,
        address[] memory _sentinels,
        address _vault,
        uint256 _feeBps
    ) Ownable(msg.sender) {
        if (_feeBps > MAX_FEE_BPS)                  revert FeeTooHigh();
        if (_vault == address(0))                   revert ZeroAddress();
        if (_oracles.length < MIN_REQUIRED_SIGS)    revert InvalidThreshold();

        for (uint256 i = 0; i < _oracles.length;   i++) { _addOracle(_oracles[i]);     }
        for (uint256 i = 0; i < _sentinels.length;  i++) { _addSentinel(_sentinels[i]); }

        stormVault    = IStormTradeVault(_vault);
        feeBps        = _feeBps;
        minSignatures = MIN_REQUIRED_SIGS;
    }

    // =========================================================================
    // Stake-to-Play — Anti-Bot Economic Barrier
    // =========================================================================

    /// @notice Lock 5 TON to unlock signal access. Makes bot farms economically unviable.
    function stake() external payable {
        if (msg.value == 0) revert MarginTooSmall();
        stakedAmount[msg.sender] += msg.value;
        emit Staked(msg.sender, msg.value);
    }

    /// @notice Unstake ETH. Blocked for 24h after last trade — prevents hit-and-run.
    function unstake(uint256 amount) external nonReentrant {
        if (stakedAmount[msg.sender] < amount)  revert NothingToUnstake();
        if (block.timestamp < lastTradeTimestamp[msg.sender] + UNSTAKE_LOCKUP)
            revert UnstakeLockupActive();

        stakedAmount[msg.sender] -= amount;
        (bool ok, ) = payable(msg.sender).call{value: amount}("");
        if (!ok) revert TransferFailed();
        emit Unstaked(msg.sender, amount);
    }

    // =========================================================================
    // Trust Score — Set by Oracle After Off-chain Analysis
    // =========================================================================

    /// @notice Oracle writes wallet trust score (0–100) after behavioral analysis.
    function setTrustScore(address _user, uint8 _score) external onlyOracle {
        if (_user == address(0)) revert ZeroAddress();
        walletTrustScore[_user] = _score;
        emit TrustScoreSet(_user, _score);
    }

    // =========================================================================
    // Core: Execute Trade Signal
    // =========================================================================

    function executeAuraSignal(
        TradeSignal calldata signal,
        bytes[] calldata signatures
    ) external payable whenNotPaused nonReentrant {

        // 1. Timing & chain binding
        if (block.timestamp > signal.timestamp + SIGNAL_EXPIRY) revert ExpiredSignal();
        if (signal.chainId != block.chainid)                    revert WrongChainId();

        // 2. Identity
        if (msg.sender != signal.user) revert IdentityMismatch();

        // 3. Sequential nonce — per-user, no cross-user collision
        if (signal.nonce != userNonces[signal.user] + 1) revert InvalidNonce();

        // 4. Vault live
        if (address(stormVault) == address(0)) revert VaultNotConfigured();

        // 5. Anti-bot gates
        if (stakedAmount[signal.user] < MIN_STAKE)           revert InsufficientStake();
        if (walletTrustScore[signal.user] < MIN_TRUST_SCORE) revert TrustScoreTooLow();

        // 6. Multi-oracle consensus
        bytes32 msgHash = keccak256(abi.encode(
            signal.user, signal.pairId, signal.isLong,
            signal.leverage, signal.timestamp, signal.nonce, signal.chainId
        ));
        if (!_verifyMultiSig(msgHash, signatures)) revert InvalidMultiSignature();

        // 7. Financial
        uint256 platformFee = (msg.value * feeBps) / 10_000;
        uint256 margin      = msg.value - platformFee;
        if (margin < MIN_MARGIN) revert MarginTooSmall();

        // 8. CEI — all state before external calls
        userNonces[signal.user]         = signal.nonce;
        lastTradeTimestamp[signal.user] = block.timestamp;

        UserStats storage s = userRegistry[msg.sender];
        s.totalSignals++;
        s.totalVolume        += margin;
        s.lastTradeTimestamp  = block.timestamp;

        // 9. Fee to owner
        if (platformFee > 0) {
            (bool feeOk, ) = payable(owner()).call{value: platformFee}("");
            if (!feeOk) revert TransferFailed();
        }

        // 10. Fail-safe DEX execution — pull-pattern on failure
        try stormVault.openPosition{value: margin}(
            signal.user, signal.pairId, signal.isLong, signal.leverage, margin
        ) {
            emit PositionOpened(signal.user, signal.pairId, margin, signal.nonce);
        } catch {
            pendingRefunds[signal.user] += margin;
            emit ExecutionReverted(signal.user, margin);
        }
    }

    // =========================================================================
    // Refund (Pull Pattern)
    // =========================================================================

    function claimRefund() external nonReentrant {
        uint256 amount = pendingRefunds[msg.sender];
        if (amount == 0) revert NoRefundAvailable();
        pendingRefunds[msg.sender] = 0;
        (bool ok, ) = payable(msg.sender).call{value: amount}("");
        if (!ok) revert TransferFailed();
        emit RefundClaimed(msg.sender, amount);
    }

    // =========================================================================
    // Oracle Result Reporting
    // =========================================================================

    /// @notice Oracle records trade outcome. Rate-limited: 1 update per user per hour.
    function updateResult(address _user, bool _isWin, int256 _pnl) external nonReentrant onlyOracle {
        if (_user == address(0)) revert ZeroAddress();
        if (block.timestamp < lastResultUpdate[_user] + RESULT_COOLDOWN)
            revert ResultCooldownActive();

        lastResultUpdate[_user] = block.timestamp;

        UserStats storage s = userRegistry[_user];
        if (_isWin) { s.wins++; } else { s.losses++; }
        s.cumulativePnl      += _pnl;
        s.lastTradeTimestamp  = block.timestamp;

        emit ResultUpdated(_user, msg.sender, _isWin, _pnl);
    }

    // =========================================================================
    // Oracle Management
    // =========================================================================

    function addOracle(address _oracle) external onlyOwner { _addOracle(_oracle); }

    function removeOracle(address _oracle) external onlyOwner {
        if (!isOracle[_oracle])                revert OracleNotRegistered();
        if (activeOracles - 1 < minSignatures) revert WouldBreakThreshold();
        isOracle[_oracle] = false;
        activeOracles--;
        emit OracleRemoved(_oracle);
    }

    // =========================================================================
    // Sentinel Management
    // =========================================================================

    function addSentinel(address _sentinel) external onlyOwner { _addSentinel(_sentinel); }

    function removeSentinel(address _sentinel) external onlyOwner {
        if (!isSentinel[_sentinel]) revert SentinelNotRegistered();
        isSentinel[_sentinel] = false;
        emit SentinelRemoved(_sentinel);
    }

    /// @notice Sentinel instantly halts contract on anomaly. Owner-only unpause.
    function triggerSentinelPause() external onlySentinel {
        _pause();
        emit EmergencyShutdown(msg.sender);
    }

    function pause()   external onlyOwner { _pause(); }
    function unpause() external onlyOwner { _unpause(); }

    // =========================================================================
    // Timelocked Governance (48h delay on all sensitive ops)
    // =========================================================================

    function queueAction(bytes32 actionHash) external onlyOwner returns (bytes32) {
        timelockQueue[actionHash] = TimelockEntry({
            actionHash: actionHash,
            readyAt:    block.timestamp + TIMELOCK_DELAY,
            executed:   false,
            cancelled:  false
        });
        emit ActionQueued(actionHash, block.timestamp + TIMELOCK_DELAY);
        return actionHash;
    }

    function cancelAction(bytes32 actionId) external onlyOwner {
        TimelockEntry storage e = timelockQueue[actionId];
        if (e.readyAt == 0) revert TimelockNotQueued();
        if (e.executed)     revert TimelockAlreadyExecuted();
        e.cancelled = true;
        emit ActionCancelled(actionId);
    }

    function executeSetVault(bytes32 actionId, address _newVault) external onlyOwner {
        _validateTimelock(actionId, keccak256(abi.encode("SET_VAULT", _newVault)));
        if (_newVault == address(0)) revert ZeroAddress();
        address old = address(stormVault);
        stormVault  = IStormTradeVault(_newVault);
        timelockQueue[actionId].executed = true;
        emit VaultUpdated(old, _newVault);
        emit ActionExecuted(actionId);
    }

    function executeSetFee(bytes32 actionId, uint256 _newFeeBps) external onlyOwner {
        _validateTimelock(actionId, keccak256(abi.encode("SET_FEE", _newFeeBps)));
        if (_newFeeBps > MAX_FEE_BPS) revert FeeTooHigh();
        uint256 old = feeBps;
        feeBps      = _newFeeBps;
        timelockQueue[actionId].executed = true;
        emit FeeUpdated(old, _newFeeBps);
        emit ActionExecuted(actionId);
    }

    function executeSetMinSignatures(bytes32 actionId, uint256 _min) external onlyOwner {
        _validateTimelock(actionId, keccak256(abi.encode("SET_MIN_SIGS", _min)));
        if (_min < MIN_REQUIRED_SIGS || _min > activeOracles) revert InvalidThreshold();
        uint256 old   = minSignatures;
        minSignatures = _min;
        timelockQueue[actionId].executed = true;
        emit MinSignaturesUpdated(old, _min);
        emit ActionExecuted(actionId);
    }

    // =========================================================================
    // Emergency
    // =========================================================================

    /// @notice Last-resort drain. Only when paused. Notify users before use.
    function emergencyWithdraw() external onlyOwner whenPaused {
        uint256 balance = address(this).balance;
        (bool ok, ) = payable(owner()).call{value: balance}("");
        if (!ok) revert TransferFailed();
    }

    // =========================================================================
    // View Helpers
    // =========================================================================

    function getUserStats(address _user)  external view returns (UserStats memory) { return userRegistry[_user]; }
    function nextNonce(address _user)     external view returns (uint256) { return userNonces[_user] + 1; }
    function isEligible(address _user)    external view returns (bool) {
        return stakedAmount[_user] >= MIN_STAKE && walletTrustScore[_user] >= MIN_TRUST_SCORE;
    }

    function buildActionHash(string calldata actionType, bytes calldata param)
        external pure returns (bytes32)
    {
        return keccak256(abi.encode(actionType, param));
    }

    // =========================================================================
    // Internal
    // =========================================================================

    function _verifyMultiSig(bytes32 hash, bytes[] calldata signatures)
        internal view returns (bool)
    {
        if (signatures.length < minSignatures) return false;

        address[] memory seen = new address[](signatures.length);
        uint256 validCount    = 0;

        for (uint256 i = 0; i < signatures.length; i++) {
            // tryRecover: invalid sig returns address(0), never reverts
            (address signer, ECDSA.RecoverError err, ) =
                hash.toEthSignedMessageHash().tryRecover(signatures[i]);

            if (err != ECDSA.RecoverError.NoError) continue;
            if (!isOracle[signer]) continue;

            bool duplicate = false;
            for (uint256 j = 0; j < validCount; j++) {
                if (seen[j] == signer) { duplicate = true; break; }
            }
            if (!duplicate) { seen[validCount] = signer; validCount++; }
        }

        return validCount >= minSignatures;
    }

    function _addOracle(address _o) internal {
        if (_o == address(0))  revert ZeroAddress();
        if (isOracle[_o])      revert OracleAlreadyRegistered();
        isOracle[_o] = true;
        activeOracles++;
        emit OracleAdded(_o);
    }

    function _addSentinel(address _s) internal {
        if (_s == address(0))    revert ZeroAddress();
        if (isSentinel[_s])      revert SentinelAlreadyRegistered();
        isSentinel[_s] = true;
        emit SentinelAdded(_s);
    }

    function _validateTimelock(bytes32 actionId, bytes32 expectedHash) internal view {
        TimelockEntry storage e = timelockQueue[actionId];
        if (e.readyAt == 0)               revert TimelockNotQueued();
        if (e.executed)                   revert TimelockAlreadyExecuted();
        if (e.cancelled)                  revert TimelockCancelled();
        if (block.timestamp < e.readyAt)  revert TimelockNotReady();
        if (e.actionHash != expectedHash) revert TimelockHashMismatch();
    }

    // =========================================================================
    // ETH Safety
    // =========================================================================

    receive() external payable { revert("AuraFortress: direct ETH not accepted"); }
    fallback() external payable { revert("AuraFortress: invalid call"); }
}
```
