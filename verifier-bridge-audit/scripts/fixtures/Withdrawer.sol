// SPDX-License-Identifier: MIT
// Fixture for scan_verifier.py — a DELIBERATELY VULNERABLE consumer.
// Two planted issues: (1) no nullifier tracking -> proof replay;
// (2) recipient is a parameter not bound into the proof's public inputs.
pragma solidity ^0.8.20;

interface IVerifier {
    function verifyProof(
        uint256[2] calldata a,
        uint256[2][2] calldata b,
        uint256[2] calldata c,
        uint256[2] calldata input
    ) external view returns (bool);
}

contract Withdrawer {
    IVerifier public verifier;
    address public owner;

    constructor(IVerifier _v) {
        verifier = _v;
        owner = msg.sender;
    }

    // Planted issue #3: verifier is swappable with no timelock.
    function setVerifier(IVerifier _v) external {
        require(msg.sender == owner, "not owner");
        verifier = _v;
    }

    function withdraw(
        uint256[2] calldata a,
        uint256[2][2] calldata b,
        uint256[2] calldata c,
        uint256[2] calldata input,
        address payable recipient
    ) external {
        // Issue #1: no nullifier is recorded, so the same proof works forever.
        // Issue #2: `recipient` is not part of `input`, so anyone who sees the
        //           proof in the mempool can redirect funds to themselves.
        require(verifier.verifyProof(a, b, c, input), "invalid proof");
        recipient.transfer(1 ether);
    }
}
