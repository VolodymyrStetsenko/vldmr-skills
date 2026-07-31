// SPDX-License-Identifier: MIT
// Fixture for enumerate_evm.py — planted issues for the enumerator to surface.
pragma solidity ^0.8.20;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
}

contract Vault {
    mapping(address => uint256) public balances;
    uint256 public totalAssets;   // conservation seed: balances + totalAssets
    address public owner;
    uint256 public feeBps;

    constructor() { owner = msg.sender; }

    modifier onlyOwner() { require(msg.sender == owner, "not owner"); _; }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
        totalAssets += msg.value;
    }

    // Planted #1: reentrancy — external call before state update, no guard.
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient");
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
        balances[msg.sender] -= amount;
        totalAssets -= amount;
    }

    // Planted #2: permissionless state change (no access modifier).
    function setFee(uint256 _bps) external {
        feeBps = _bps;
    }

    // Properly guarded admin function (should NOT be flagged permissionless).
    function sweep(address token, uint256 amount) external onlyOwner {
        IERC20(token).transfer(owner, amount);
    }
}
