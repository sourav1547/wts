// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";

import {BN254} from "../src/BN254.sol";

contract BN254Test is Test {
    function setUp() public {}

    function testBasicPairingProdCheck() public view {
        BN254.G1Point memory g1 = BN254.P1();
        BN254.G2Point memory g2 = BN254.P2();

        assert(BN254.pairing2(g1, g2, BN254.negate(g1), g2));
        assert(!BN254.pairing2(g1, g2, g1, g2));
    }
}
