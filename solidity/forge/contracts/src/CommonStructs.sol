// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {BN254} from "./BN254.sol";

/// The CRS for the verifier
struct VerifierKey {
    BN254.G1Point g1; // Not part of the paper because we are using a non symmetric pairing
    BN254.G1Point neg_g1; //g_1^{-1} : helper for faster proof verification
    uint256 one_over_n; // 1/n in Fr:  helper for faster proof verification
    BN254.G2Point g2; // g in the paper
    BN254.G2Point h2; // h in the paper, must be random, i.e. h=g^\alpha for some random \alpha
    BN254.G2Point v2; // v in the paper, must be random, i.e. h=g^\alpha for some random \alpha
    BN254.G1Point g_s; // the commitment to all the public keys, g_s in the paper
    BN254.G1Point g_w; // the commitment to all the weights, g_w in the paper
    BN254.G2Point g_tau; // g_tau in the paper
    BN254.G2Point h_tau; // g_tau in the paper
    BN254.G2Point g_Z_H; // commitment to vanishing polynomial g_{Z_H(\tau)} in the paper
    uint256 n; // MAX number of signers
}

/// Message and Proof
struct Proof {
    BN254.G1Point g_mu;
    BN254.G1Point g1_b;
    BN254.G2Point g2_b; // Not part of paper. Needed because we are working in a non symmetric pairing
    BN254.G1Point gq_b;
    BN254.G2Point sigma_bls;
    BN254.G1Point g1_q;
    BN254.G1Point g1_r;
    BN254.G1Point h1_p;
    BN254.G1Point v_mu;
    uint256 t_prime;
}
