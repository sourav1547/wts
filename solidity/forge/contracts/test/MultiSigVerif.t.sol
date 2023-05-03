// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";

import {BN254} from "../src/BN254.sol";

import "../src/MultiSig.sol";

contract MultiSigTest is Test {
    MultiSig public mts;

    function setUp() public {
        mts = new MultiSig();
    }

    function testMultiSigVerif() public {
        bool res = mts.verify(BN254.P2(),BN254.P1());
    }

    function testKeyStorage() public {
        mts = new MultiSig();
    }
}
