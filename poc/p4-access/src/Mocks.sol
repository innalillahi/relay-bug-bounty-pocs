// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {BuildPayloadParams, IPayloadBuilder} from "relay-settlement/RelayAllocator.sol";
import {RelayHub} from "relay-settlement/RelayHub.sol";

/// @notice Minimal ERC20 for PoC funding (mintable by anyone in tests).
contract MockERC20 {
  string public name = "Mock";
  string public symbol = "MOCK";
  uint8 public decimals = 18;
  uint256 public totalSupply;
  mapping(address => uint256) public balanceOf;
  mapping(address => mapping(address => uint256)) public allowance;
  event Transfer(address indexed from, address indexed to, uint256 amount);
  event Approval(address indexed owner, address indexed spender, uint256 amount);
  function mint(address to, uint256 amount) external {
    balanceOf[to] += amount;
    totalSupply += amount;
    emit Transfer(address(0), to, amount);
  }
  function transfer(address to, uint256 amount) external returns (bool) {
    balanceOf[msg.sender] -= amount;
    balanceOf[to] += amount;
    emit Transfer(msg.sender, to, amount);
    return true;
  }
  function approve(address spender, uint256 amount) external returns (bool) {
    allowance[msg.sender][spender] = amount;
    emit Approval(msg.sender, spender, amount);
    return true;
  }
  function transferFrom(address from, address to, uint256 amount) external returns (bool) {
    uint256 allowed = allowance[from][msg.sender];
    if (allowed != type(uint256).max) allowance[from][msg.sender] = allowed - amount;
    balanceOf[from] -= amount;
    balanceOf[to] += amount;
    emit Transfer(from, to, amount);
    return true;
  }
}

/// @notice Payload builder stub: returns a fixed payload and one hash to sign.
contract MockPayloadBuilder is IPayloadBuilder {
  function buildPayload(
    string calldata,
    bytes calldata,
    BuildPayloadParams calldata
  ) external pure returns (bytes memory payload) {
    return hex"deadbeef";
  }
  function hashesToSign(
    string calldata,
    bytes calldata,
    bytes calldata payload
  ) external pure returns (bytes32[] memory hashes) {
    hashes = new bytes32[](1);
    hashes[0] = keccak256(payload);
  }
  function curve() external pure returns (string memory) {
    return "Ecdsa";
  }
  function family() external pure returns (string memory) {
    return "EthereumVm";
  }
}

/// @notice Helper that holds OPERATOR_ROLE on a Hub and mints to aliases.
contract HubMinter {
  RelayHub public hub;
  constructor(RelayHub _hub) {
    hub = _hub;
  }
  function mintTo(address to, uint256 tokenId, uint256 amount) external {
    hub.mint(to, tokenId, amount);
  }
}

/// @notice Minimal idempotency source for RelayOracleIdempotencyStore tests.
contract MockIdempotencySource {
  function isExecuted(bytes32) external pure returns (bool) {
    return false;
  }
}
