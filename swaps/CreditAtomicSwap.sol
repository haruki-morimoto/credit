// SPDX-License-Identifier: Apache-2.0 OR MIT
pragma solidity ^0.8.24;

/// @title CreditAtomicSwap — Zero-Custody SHA-256 HTLC Counterpart for Credits (XCR)
/// @notice Enables trustless atomic swaps between ETH / ERC-20 tokens (USDC, USDT, WBTC) on any
///         EVM chain (Ethereum, Arbitrum, Base, Optimism) and Credits (`XCR`) with **zero wrapped
///         bridges, zero multisig custodians, and zero external Solidity dependencies**.
/// @dev Uses EVM precompile `0x02` (`sha256(abi.encodePacked(preimage))`) rather than `keccak256`
///      so the **exact same 32-byte preimage** unlocks both this contract and Credit's `HTLC`
///      (`credit-cli htlc-lock` / `htlc-claim`).
///
/// Cross-Chain Swap Safety Ordering:
/// 1. Taker (buying XCR with ETH/USDC) generates `(preimage, hashlock = sha256(preimage))` via
///    `credit-cli htlc-secret` and locks ETH/ERC-20 here with `expiry = now + 4 hours`.
/// 2. Maker (selling XCR) verifies the `Locked` event here, then locks `XCR` on Credit to the
///    identical `hashlock` with a **shorter** `expiry = now + 1 hour`.
/// 3. Taker claims `XCR` on Credit (`credit-cli htlc-claim --preimage <S>`), exposing `<S>`.
/// 4. Maker calls `claim(escrowId, S)` on this contract to sweep ETH/ERC-20! If abandoned, both
///    sides call `refund` after their respective `expiry` timestamps.
contract CreditAtomicSwap {
    uint8 private constant STATUS_EMPTY = 0;
    uint8 private constant STATUS_OPEN = 1;
    uint8 private constant STATUS_CLAIMED = 2;
    uint8 private constant STATUS_REFUNDED = 3;

    struct Escrow {
        address depositor;
        address recipient;
        address token; // `address(0)` for native ETH
        uint256 amount;
        bytes32 hashlock; // NIST SHA-256(preimage) matching Credit `Hash32`
        uint64 expiry;
        uint8 status;
    }

    uint256 private _reentrancyLock = 1;
    mapping(bytes32 => Escrow) public escrows;

    event Locked(
        bytes32 indexed escrowId,
        address indexed depositor,
        address indexed recipient,
        address token,
        uint256 amount,
        bytes32 sha256Hashlock,
        uint64 expiry,
        string xcrTargetHandleOrPocket
    );
    event Claimed(bytes32 indexed escrowId, bytes32 preimage);
    event Refunded(bytes32 indexed escrowId);

    error ReentrancyBlocked();
    error InvalidParameters();
    error EscrowAlreadyExists();
    error EscrowNotOpen();
    error InvalidSha256Preimage();
    error EscrowExpired();
    error EscrowNotYetExpired();
    error TransferFailed();

    modifier nonReentrant() {
        if (_reentrancyLock != 1) revert ReentrancyBlocked();
        _reentrancyLock = 2;
        _;
        _reentrancyLock = 1;
    }

    /// @notice Locks native ETH under a Credit-compatible `SHA-256` hashlock.
    function lockEth(
        address recipient,
        bytes32 sha256Hashlock,
        uint64 expiry,
        bytes32 salt,
        string calldata xcrTargetHandleOrPocket
    ) external payable nonReentrant returns (bytes32 escrowId) {
        if (
            recipient == address(0) ||
            msg.value == 0 ||
            sha256Hashlock == bytes32(0) ||
            expiry <= block.timestamp
        ) {
            revert InvalidParameters();
        }

        escrowId = keccak256(
            abi.encode(
                block.chainid,
                address(this),
                msg.sender,
                recipient,
                address(0),
                msg.value,
                sha256Hashlock,
                expiry,
                salt
            )
        );
        if (escrows[escrowId].status != STATUS_EMPTY) revert EscrowAlreadyExists();

        escrows[escrowId] = Escrow({
            depositor: msg.sender,
            recipient: recipient,
            token: address(0),
            amount: msg.value,
            hashlock: sha256Hashlock,
            expiry: expiry,
            status: STATUS_OPEN
        });

        emit Locked(
            escrowId,
            msg.sender,
            recipient,
            address(0),
            msg.value,
            sha256Hashlock,
            expiry,
            xcrTargetHandleOrPocket
        );
    }

    /// @notice Locks ERC-20 tokens (e.g. USDC / USDT / WBTC) under a Credit-compatible `SHA-256` hashlock.
    function lockErc20(
        address token,
        uint256 amount,
        address recipient,
        bytes32 sha256Hashlock,
        uint64 expiry,
        bytes32 salt,
        string calldata xcrTargetHandleOrPocket
    ) external nonReentrant returns (bytes32 escrowId) {
        if (
            token == address(0) ||
            recipient == address(0) ||
            amount == 0 ||
            sha256Hashlock == bytes32(0) ||
            expiry <= block.timestamp
        ) {
            revert InvalidParameters();
        }

        escrowId = keccak256(
            abi.encode(
                block.chainid,
                address(this),
                msg.sender,
                recipient,
                token,
                amount,
                sha256Hashlock,
                expiry,
                salt
            )
        );
        if (escrows[escrowId].status != STATUS_EMPTY) revert EscrowAlreadyExists();

        escrows[escrowId] = Escrow({
            depositor: msg.sender,
            recipient: recipient,
            token: token,
            amount: amount,
            hashlock: sha256Hashlock,
            expiry: expiry,
            status: STATUS_OPEN
        });

        _safeTransferFrom(token, msg.sender, address(this), amount);

        emit Locked(
            escrowId,
            msg.sender,
            recipient,
            token,
            amount,
            sha256Hashlock,
            expiry,
            xcrTargetHandleOrPocket
        );
    }

    /// @notice Claims locked ETH or ERC-20 by revealing the 32-byte `SHA-256` preimage before `expiry`.
    function claim(bytes32 escrowId, bytes32 preimage) external nonReentrant {
        Escrow storage e = escrows[escrowId];
        if (e.status != STATUS_OPEN) revert EscrowNotOpen();
        if (block.timestamp >= e.expiry) revert EscrowExpired();
        if (sha256(abi.encodePacked(preimage)) != e.hashlock) revert InvalidSha256Preimage();

        e.status = STATUS_CLAIMED;
        emit Claimed(escrowId, preimage);

        if (e.token == address(0)) {
            (bool ok, ) = e.recipient.call{value: e.amount}("");
            if (!ok) revert TransferFailed();
        } else {
            _safeTransfer(e.token, e.recipient, e.amount);
        }
    }

    /// @notice Refunds 100% of locked ETH or ERC-20 back to `depositor` once `block.timestamp >= expiry`.
    function refund(bytes32 escrowId) external nonReentrant {
        Escrow storage e = escrows[escrowId];
        if (e.status != STATUS_OPEN) revert EscrowNotOpen();
        if (block.timestamp < e.expiry) revert EscrowNotYetExpired();

        e.status = STATUS_REFUNDED;
        emit Refunded(escrowId);

        if (e.token == address(0)) {
            (bool ok, ) = e.depositor.call{value: e.amount}("");
            if (!ok) revert TransferFailed();
        } else {
            _safeTransfer(e.token, e.depositor, e.amount);
        }
    }

    function _safeTransfer(address token, address to, uint256 value) private {
        (bool ok, bytes memory ret) = token.call(
            abi.encodeWithSelector(0xa9059cbb, to, value)
        );
        if (!ok || (ret.length != 0 && !abi.decode(ret, (bool)))) revert TransferFailed();
    }

    function _safeTransferFrom(address token, address from, address to, uint256 value) private {
        (bool ok, bytes memory ret) = token.call(
            abi.encodeWithSelector(0x23b872dd, from, to, value)
        );
        if (!ok || (ret.length != 0 && !abi.decode(ret, (bool)))) revert TransferFailed();
    }
}
