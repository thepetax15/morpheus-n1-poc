// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title N1Harness
/// @notice Minimal harness replicating the EXACT vulnerable logic from
///         LumerinDiamond SessionRouter.sol (Morpheus-Lumerin-Node).
///         Diamond plumbing (storage slots, facets, bids, delegation registry)
///         is stubbed; the approval decode + signature verification + the
///         openSession check sequence are reproduced faithfully.
///
/// Source of truth:
///   recon/lumerin/Morpheus-Lumerin-Node/smart-contracts/contracts/diamond/facets/SessionRouter.sol
///   - _extractProviderApproval ......... lines 192-206 (copied VERBATIM)
///   - openSession check order .......... lines 83-120 (mirrored)
///   - _isValidProviderReceipt .......... lines 537-559 (core logic replicated)
///   - _validateDelegatee ............... DelegationStorage.sol:40-44
///     (delegatee_ == delegator_ passes -> self-call always allowed)
contract N1Harness {
    uint128 public constant SIGNATURE_TTL = 10 minutes;

    error SessionApprovedForAnotherChainId();
    error SessionApproveExpired();
    error SessionProviderSignatureMismatch();
    error SessionDuplicateApproval();
    error InsufficientRightsForOperation(address delegator, address delegatee);

    // bidId => provider (stub for _getBidsStorage().bids[bidId_].provider)
    mapping(bytes32 => address) public bidProvider;
    // mirrors sessionsStorage.isProviderApprovalUsed
    mapping(bytes => bool) public isProviderApprovalUsed;
    // user => sessions opened (mirrors sessionsStorage.userSessions)
    mapping(address => bytes32[]) public userSessions;

    function registerBid(bytes32 bidId_, address provider_) external {
        bidProvider[bidId_] = provider_;
    }

    // ---- VERBATIM from SessionRouter.sol:192-206 ----
    function _extractProviderApproval(bytes calldata providerApproval_) private view returns (bytes32) {
        (bytes32 bidId_, uint256 chainId_, , uint128 timestamp_) = abi.decode(
            providerApproval_,
            (bytes32, uint256, address, uint128)
        );

        if (chainId_ != block.chainid) {
            revert SessionApprovedForAnotherChainId();
        }
        if (block.timestamp > timestamp_ + SIGNATURE_TTL) {
            revert SessionApproveExpired();
        }

        return bidId_;
    }
    // ---- END VERBATIM ----

    // Core of _isValidProviderReceipt (SessionRouter.sol:537-559):
    // bytes32 receiptHash_ = ECDSA.toEthSignedMessageHash(keccak256(receipt_));
    // address user_ = ECDSA.recover(receiptHash_, signature_);
    // valid iff recovered == provider_ (delegation branch omitted: not needed for PoC)
    function _isValidProviderReceipt(
        address provider_,
        bytes calldata receipt_,
        bytes calldata signature_
    ) private pure returns (bool) {
        bytes32 receiptHash_ = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", keccak256(receipt_))
        );
        require(signature_.length == 65, "bad sig len");
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := calldataload(signature_.offset)
            s := calldataload(add(signature_.offset, 32))
            v := byte(0, calldataload(add(signature_.offset, 64)))
        }
        address recovered_ = ecrecover(receiptHash_, v, r, s);
        return recovered_ == provider_;
    }

    // Faithful mirror of openSession's check sequence (lines 83-120),
    // minus fund movement / session struct writes.
    function openSession(
        address user_,
        bytes calldata approvalEncoded_,
        bytes calldata signature_
    ) external returns (bytes32 sessionId_) {
        // _validateDelegatee(_msgSender(), user_, ...) — self-call passes
        if (msg.sender != user_) {
            revert InsufficientRightsForOperation(user_, msg.sender);
        }

        bytes32 bidId_ = _extractProviderApproval(approvalEncoded_); // <-- user address discarded

        address provider_ = bidProvider[bidId_];
        require(provider_ != address(0), "unknown bid");

        if (!_isValidProviderReceipt(provider_, approvalEncoded_, signature_)) {
            revert SessionProviderSignatureMismatch();
        }
        if (isProviderApprovalUsed[approvalEncoded_]) {
            revert SessionDuplicateApproval();
        }

        // NOTE: at no point is the decoded user address compared to user_.
        // The approval binds (bidId, chainId, SIGNED_USER, timestamp) but the
        // contract only enforces bidId/chainId/timestamp.

        sessionId_ = keccak256(abi.encode(user_, provider_, bidId_, block.timestamp));
        userSessions[user_].push(sessionId_);
        isProviderApprovalUsed[approvalEncoded_] = true;

        return sessionId_;
    }

    // Helper: decode the signed user address from approval bytes (what the
    // contract SHOULD check but doesn't).
    function decodeApprovedUser(bytes calldata approvalEncoded_) external pure returns (address) {
        (, , address user_, ) = abi.decode(approvalEncoded_, (bytes32, uint256, address, uint128));
        return user_;
    }
}
