// SPDX-License-Identifier: MIT
// Fixture for enumerate_evm.py — planted OWASP SC03/SC04/SC10 issues so the new
// oracle / flash-loan / proxy detectors can be verified.
pragma solidity ^0.8.20;

interface IPair {
    function getReserves() external view returns (uint112, uint112, uint32);
}
interface IAggregator {
    function latestRoundData() external view returns (uint80, int256, uint256, uint256, uint80);
}
interface IERC20 {
    function balanceOf(address) external view returns (uint256);
    function transfer(address, uint256) external returns (bool);
}

contract DefiVault {
    IPair pair;
    IAggregator feed;
    IERC20 token;
    uint256 public totalShares;
    address public owner;

    // SC03 (planted): spot price straight from AMM reserves — manipulable in a block.
    function priceFromReserves() public view returns (uint256) {
        (uint112 r0, uint112 r1, ) = pair.getReserves();
        return uint256(r1) / uint256(r0);
    }

    // SC03 (planted): Chainlink read with no updatedAt/answeredInRound validation.
    function priceFromFeed() public view returns (int256) {
        (, int256 answer, , , ) = feed.latestRoundData();
        return answer;
    }

    // SC04 (planted): flash-loan callback with no initiator authentication.
    function onFlashLoan(address, address, uint256, uint256, bytes calldata) external returns (bytes32) {
        return keccak256("ERC3156FlashBorrower.onFlashLoan");
    }

    // SC04 (planted): share price derived from live balance — inflatable by donation.
    function sharePrice() public view returns (uint256) {
        return token.balanceOf(address(this)) / totalShares;
    }

    // SC10 (planted): upgrade authorization hook with no access control.
    function _authorizeUpgrade(address) internal {}

    // SC10 (planted): initializer without an `initializer` modifier — re-init risk.
    function initialize(address _owner) external {
        owner = _owner;
    }

    // SC10 (planted): reachable selfdestruct.
    function kill() external {
        selfdestruct(payable(owner));
    }
}
