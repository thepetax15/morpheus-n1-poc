# N-1 PoC: Provider Approval User Binding Not Enforced

## What it proves

`SessionRouter._extractProviderApproval` (LumerinDiamond, Morpheus) decodes the
provider's signed approval `(bidId, chainId, userAddress, timestamp)` but
**discards the user address** (empty destructuring slot). `openSession` never
validates `user_` against the signed address. Any signed approval becomes a
bearer token — first caller wins.

## How to run

```bash
cd ~/workspace/bugbounty/targets/selfhosted/morpheus/poc
export PATH="$HOME/.foundry/bin:$PATH"
forge test -vvv
```

Expected: **3/3 PASS**

| Test | What it shows |
|---|---|
| `test_N1_bobUsesAlicesApproval` | **THE BUG.** Provider signs approval for Alice; Bob calls `openSession(bob, ...)` with Alice's approval bytes → session opens for Bob. Alice's later attempt reverts `SessionDuplicateApproval`. |
| `test_N1_control_aliceUsesOwnApproval` | Control: intended flow works (Alice using her own approval). |
| `test_N1_control_forgedSignatureReverts` | Control: forged signatures still rejected — only the *binding* is missing, not signature validation. |

## Fidelity notes

- `src/N1Harness.sol::_extractProviderApproval` is copied **verbatim** from
  `SessionRouter.sol:192-206` (including the empty address slot, chainId check,
  SIGNATURE_TTL check).
- Signature verification replicates `_isValidProviderReceipt` core:
  `ECDSA.toEthSignedMessageHash(keccak256(receipt))` → `ecrecover` → compare to
  provider. (Delegation branch omitted — not needed for the PoC path.)
- `_validateDelegatee` self-call rule (`delegatee_ == delegator_` passes) is
  mirrored: Bob opening for Bob passes, matching real behavior.
- Approval bytes are built exactly like the off-chain helper
  (`utils/provider-helper.ts`): `abi.encode(bidId, chainId, user, timestamp)`.
- Diamond plumbing (storage slots, facets, bids, MOR token) is stubbed — the
  vulnerable decode/verify/check sequence is what matters and is faithful.

## Source of truth

- Finding: `~/workspace/bugbounty/targets/selfhosted/morpheus/LUMERIN-NEWMETHODS-2.md` (N-1)
- Escalation analysis: `~/workspace/bugbounty/targets/selfhosted/morpheus/N1-ESCALATION.md`
  (confirmed Low — cannot reach fund loss; 6 escalation angles tested)
- Real contract: `recon/lumerin/Morpheus-Lumerin-Node/smart-contracts/contracts/diamond/facets/SessionRouter.sol`
- Team's own test proving the bug: `test/diamond/facets/SessionRouter.test.ts:244-245`
  (approval for OWNER, session opened for SECOND — test PASSES)

## Status

- Submitted to devs@mor.org (2026-11-03) as Low severity.
- Fix: return the decoded user address from `_extractProviderApproval` and
  validate it against `user_`/`_msgSender()` in `openSession` (allowing both,
  since the delegation flow signs for the delegatee caller).
