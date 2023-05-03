// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {BN254} from "./BN254.sol";
import {Utils} from "./Utils.sol";

contract MultiSig {
    uint256 N_PK_MULTISIG = 2048;

    BN254.G1Point[2048] public_keys;

    constructor(){
        // Set the public keys to g1
        for(uint i=0;i<N_PK_MULTISIG;i++){
            public_keys[i] = BN254.P1();
        }
    }

    function verify(BN254.G2Point memory message, BN254.G1Point memory sig) public returns(bool) {
        BN254.G1Point memory pk = public_keys[0];
        for (uint i=1;i<N_PK_MULTISIG;i++){
            pk = BN254.add(pk,public_keys[i]);
        }
        return BN254.pairing2(BN254.negate(pk),message,sig,BN254.P2());
    }
}