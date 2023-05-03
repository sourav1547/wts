// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";

import {BN254} from "../src/BN254.sol";
import "../src/WTS.sol";

contract WTSTest is Test {
    WTS public wts;
    BN254.G1Point p1;
    BN254.G2Point p2;
    uint256 threshold;

    function setUp() public {
        uint64 nb_signers = 2000;

        threshold = 10;

        wts = new WTS();

        // Setup verification key
        p1 = BN254.P1();
        p2 = BN254.P2();

        wts.set_vk(p1, p2, p2, p2, p1, p1, p2, p2, p2, nb_signers);
        wts.set_proof(p1, p1, p2, p1, p2, p1, p1, p1, p1, threshold);
    }

    function testWTSVerify() public {
        bool res = wts.verify(p2, threshold);
        assert(res);
    }

    function testWTSVerifyOptimized() public {
        uint64 nb_signers = 2000;
        VerifierKey memory vk = wts.compute_vk(p1, p2, p2, p2, p1, p1, p2, p2, p2, nb_signers);
        wts.verify_optimized(p2, threshold, vk);
        //assert(res);
    }

    function testComputeVerifierKey() public {
        uint64 nb_signers = 2000;
        VerifierKey memory vk = wts.compute_vk(p1, p2, p2, p2, p1, p1, p2, p2, p2, nb_signers);
    }

    function testPairing2() public {
        bool res = BN254.pairing2(p1, p2, p1, p2);
    }

    function testPairing15() public {
        BN254.G1Point[15] memory left;
        BN254.G2Point[15] memory right;
        bool res = BN254.pairing15(left, right);
    }

    function testNegate() public {
        BN254.negate(p1);
    }

    function testInvertFieldElement() public {
        BN254.invert(657468767);
    }

    function testHashToField() public {
        wts.hash_to_field(p1, p1, 10, 0);
    }
}
