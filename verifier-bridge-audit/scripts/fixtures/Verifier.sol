// SPDX-License-Identifier: MIT
// Fixture for scan_verifier.py — a minimal Groth16-style verifier surface.
pragma solidity ^0.8.20;

library Pairing {
    struct G1Point { uint256 X; uint256 Y; }
    struct G2Point { uint256[2] X; uint256[2] Y; }
}

contract Verifier {
    uint256 constant snark_scalar_field =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    struct VerifyingKey { Pairing.G1Point alpha1; Pairing.G2Point beta2; }

    function verifyProof(
        uint256[2] calldata a,
        uint256[2][2] calldata b,
        uint256[2] calldata c,
        uint256[2] calldata input
    ) public view returns (bool) {
        // pairing check elided for the fixture
        return true;
    }
}
