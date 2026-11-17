# Relay bug bounty — proof-of-concept reproductions

Two independently reproducible PoCs for findings reported to Relay
(`support@relay.link`) on 2026-11-17. No live network, no keys, no
mainnet interaction anywhere. Everything runs locally.

## Finding 1 — P5-ORACLE-1 (S3): Solana double-claim via multi-orderId memo

`relay-protocol-oracle/src/services/attestation/vm/solana-vm/index.ts`,
`getSolverPaidAmount` (~line 550). If a fill tx's Memo instructions name
more than one orderId, the code only `logger.warn`s
("Transaction references multiple order ids; a fill should reference
exactly one") and still returns the recipient's **full balance delta** as
the paid amount. The code's own comment admits it: "a memo naming a
second order would let this one payment be claimed by that order too."

A solver holding two live orders (A, B) with the same Solana recipient,
currency and amount pays **once** in a tx whose memos name both orderIds,
then calls `attestSolverFill` for A and for B with the same tx. Both
succeed (idempotency keys differ per order), each minting that order's
full deposit to the solver. Loss: one full fill per event, repeatable.

This is a bypass of Zellic Oracle finding 3.5 (High), not a re-report:
the fix landed in every other VM — Bitcoin throws when
`opReturnCount !== 1`, XRP throws when `orderIdMemos.size > 1`,
TON/Lighter require an exact memo match, Hyperliquid binds one nonce to
one orderId, ETH/Tron require the tx input to end with the single
orderId — but Solana is the sole holdout, and the repo's own test
(`solana-vm.test.ts:1730`) enshrines the log-only behaviour.

**Run** (from this repo root):

```sh
mkdir -p repos
git clone https://github.com/relayprotocol/relay-protocol-oracle repos/relay-protocol-oracle
cd repos/relay-protocol-oracle && git checkout 55b22de && npm install --no-audit --no-fund && cd ../..
./repos/relay-protocol-oracle/node_modules/.bin/jest --config poc/p5-oracle/jest.config.js --runInBand
```

Expected: `Tests: 2 passed, 2 total` — the double-claim test (one
1,000,000,000-lamport payment attests two 1,000,000,000-lamport fills)
plus a control test (a tx naming only order A cannot attest order B).

**Fix (one sentence):** throw when `referencedOrderIds.size > 1`
("a fill must reference exactly one order id"), mirroring Bitcoin/XRP;
additionally bind the returned amount to the order's expected amount.

## Finding 2 — P4-F1 (S1): `BasicCallResolver.execute()` has no access control

`relay-settlement/smart-contracts/contracts/call-resolvers/BasicCallResolver.sol:75`.
`execute()` is `external` with no caller check at all: arbitrary
`calls[]` run as the resolver and `sweeps[]` send the resolver's full
Hub balance of any listed `tokenId` to any recipient. Sibling
`PoolDrawResolver.execute()` enforces `_requireExecutor()`; this one
does not. The deployed instance is shared
(`prod.json` `utils.basicCallResolver =
0xb24ac15b9da6d88e283ffe048befe02e188ea64e`), so any residue left in it
— unswept swap dust, a forgotten output token — is sweepable by the
first caller.

Honest scope: live loss is **$0 right now** — all 7 tokenIds that ever
flowed through the deployed resolver hold 0 (solvers sweep diligently).
This pays only when residue appears, hence S1, not S3/S4.

**Run** (from this repo root; Foundry 1.9.0, solc 0.8.28):

```sh
mkdir -p repos
git clone https://github.com/relayprotocol/relay-settlement repos/relay-settlement
git clone https://github.com/relayprotocol/relay-depository repos/relay-depository
git clone https://github.com/relayprotocol/relay-periphery repos/relay-periphery
cd repos/relay-settlement && git checkout b2f3e0e && cd ../..
cd repos/relay-depository && git checkout 458a64c && cd ../..
cd repos/relay-periphery && git checkout e221935 && cd ../..
cd poc/p4-access && forge test --match-test test_basicCallResolverSweepByAnyone -vv
```

Expected: `[PASS] test_basicCallResolverSweepByAnyone()` — a fresh EOA
with no roles sweeps the resolver's full 777,000 units of Hub credit to
itself.

**Fix (one sentence):** gate `execute()` on the Executor (mirror
`PoolDrawResolver._requireExecutor()`), or deploy one resolver per
solver instead of sharing a single instance.

## Researcher

aiueo — oxxx24434@gmail.com
