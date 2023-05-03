// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {BN254} from "./BN254.sol";
import {Utils} from "./Utils.sol";

import "./CommonStructs.sol";

contract WTS {
    uint256 constant FR_BYTES_LEN = 31;

    uint256 N_PK_MULTISIG = 4096;

    VerifierKey private vk;
    Proof private proof;

    function compute_vk(
        BN254.G1Point memory g1, // Not part of paper. Needed because we are not using a non symmetric pairing
        BN254.G2Point memory g2,
        BN254.G2Point memory h2,
        BN254.G2Point memory v2,
        BN254.G1Point memory g_s,
        BN254.G1Point memory g_w,
        BN254.G2Point memory g_tau,
        BN254.G2Point memory h_tau,
        BN254.G2Point memory g_z_H,
        uint256 nb_users
    ) public returns (VerifierKey memory){
        BN254.G1Point memory neg_g1 = BN254.negate(g1);
        uint256 one_over_n = BN254.invert(vk.n);
        return VerifierKey(g1, neg_g1, one_over_n, g2, h2, v2, g_s, g_w, g_tau, h_tau, g_z_H, nb_users);
    }


    function set_vk(
        BN254.G1Point memory g1, // Not part of paper. Needed because we are not using a non symmetric pairing
        BN254.G2Point memory g2,
        BN254.G2Point memory h2,
        BN254.G2Point memory v2,
        BN254.G1Point memory g_s,
        BN254.G1Point memory g_w,
        BN254.G2Point memory g_tau,
        BN254.G2Point memory h_tau,
        BN254.G2Point memory g_z_H,
        uint256 nb_users
    ) public {
        BN254.G1Point memory neg_g1 = BN254.negate(g1);
        uint256 one_over_n = BN254.invert(vk.n);
        vk = compute_vk(g1,g2,h2,v2,g_s,g_w,g_tau,h_tau,g_z_H,nb_users);
    }

    function uint256FromBytesLittleEndian(uint8[FR_BYTES_LEN] memory input) private pure returns (uint256) {
        uint256 r = 0;
        for (uint256 i = 0; i < FR_BYTES_LEN; i++) {
            r += 2 ** (8 * i) * input[i];
        }
        return r;
    }

    /// @dev Compute the hash to field element with input "g_s||g_w||g_b||g_mu||t_prime"
    /// @param extra value used to sample random values for different purposes
    function hash_to_field(BN254.G1Point memory g_b, BN254.G1Point memory g_mu, uint256 t_prime, uint256 extra)
        public
        view
        returns (uint256)
    {
        bytes32 hash = keccak256(abi.encode(vk.g_s, vk.g_w, g_b, g_mu, t_prime, extra));
        bytes memory hash_bytes = abi.encodePacked(hash);

        uint256 second_field_elem = uint256(uint8(hash_bytes[0]));

        // Remove first byte
        hash_bytes[FR_BYTES_LEN] = 0;
        uint256 first_field_elem = Utils.reverseEndianness(uint256(bytes32(hash_bytes)));

        uint256 res = mulmod(first_field_elem, second_field_elem, BN254.R_MOD);
        return res;
    }

    function simple_pairing_check(BN254.G1Point memory p1, BN254.G2Point memory p2) public returns (bool) {
        return BN254.pairing2(p1, p2, p1, p2);
    }

    function callScalarMul(BN254.G1Point memory p, uint256 exp) public returns (BN254.G1Point memory) {
        return BN254.scalarMul(p, exp);
    }

    // We store the proof inside the contract to avoid a stack too deep error when calling verify
    function set_proof(
        BN254.G1Point memory g_mu,
        BN254.G1Point memory g1_b,
        BN254.G2Point memory g2_b, // Not part of paper. Needed because we are working in a non symmetric pairing
        BN254.G1Point memory gq_b,
        BN254.G2Point memory sigma_bls,
        BN254.G1Point memory g1_q,
        BN254.G1Point memory g1_r,
        BN254.G1Point memory h1_p,
        BN254.G1Point memory v_mu,
        uint256 t_prime
    ) public {
        proof = Proof(g_mu, g1_b, g2_b, gq_b, sigma_bls, g1_q, g1_r, h1_p, v_mu, t_prime);
    }

    function verify(
        BN254.G2Point memory message_hash, // We assume the verifier is directly fed with some hash value H(m)
        uint256 t // Minimum threshold
    ) public view returns (bool) {
        /////////////// Equation (35)
        // First we need to prove that g1_b and g2_b are equivalent, ie. e(g1_b,g2)=e(g1,g2_b)
        // This is not in the paper because we are dealing with a non symmetric pairing
        bool res = BN254.pairing2(proof.g1_b, vk.g2, vk.neg_g1, proof.g2_b);

        // Compute g1-g1_b // Differs slightly from the paper as it is easier/cheaper to negate an element in G1
        BN254.G1Point memory g1_minus_g1b = BN254.add(vk.g1, BN254.negate(proof.g1_b));

        //Note for benchmarking purpose put the pairing check to the left so that we ensure it is evaluated
        res = BN254.pairing2(g1_minus_g1b, proof.g2_b, BN254.negate(proof.gq_b), vk.g_Z_H) && res;

        ////////////// Equation (36)

        uint256 xi = hash_to_field(proof.g1_b, proof.g_mu, proof.t_prime, 0);
        BN254.G1Point memory gs_gw_xi = BN254.add(vk.g_s, BN254.scalarMul(vk.g_w, xi));
        BN254.G1Point[4] memory left_4;
        BN254.G2Point[4] memory right_4;
        left_4[0] = BN254.negate(gs_gw_xi);
        left_4[1] = proof.g1_q;
        left_4[2] = proof.g1_r;
        uint256 xi_times_t_prime = mulmod(xi, proof.t_prime, BN254.R_MOD);

        // We deviate slightly from the paper because G2 point exponentiation is too expensive
        // Hence we raise the left member of the pairing belonging to G1 to the power 1/n
        BN254.G1Point memory g_mu_plus_g1_exp_xi_t_prime_exp_one_over_n =
            BN254.scalarMul(BN254.add(proof.g_mu, BN254.scalarMul(vk.g1, xi_times_t_prime)), vk.one_over_n);
        left_4[3] = g_mu_plus_g1_exp_xi_t_prime_exp_one_over_n;

        right_4[0] = proof.g2_b;
        right_4[1] = vk.g_Z_H;
        right_4[2] = vk.g_tau;
        right_4[3] = vk.g2;

        res = BN254.pairing4(left_4, right_4) && res; // TODO this is crashing with brownie but not with forge

        ////////////// Equation (37)

        BN254.G1Point[3] memory left_3;
        BN254.G2Point[3] memory right_3;

        left_3[0] = BN254.negate(proof.h1_p);
        left_3[1] = proof.g1_r;
        left_3[2] = g_mu_plus_g1_exp_xi_t_prime_exp_one_over_n;

        right_3[0] = vk.g2;
        right_3[1] = vk.h_tau;
        right_3[2] = vk.h2;

        res = BN254.pairing3(left_3, right_3) && res;

        ////////////// Equation (38)
        res = BN254.pairing2(BN254.negate(proof.v_mu), vk.g2, proof.g_mu, vk.v2) && res;

        ////////////// Equation (39)
        res = BN254.pairing2(BN254.negate(proof.g_mu), message_hash, vk.g1, proof.sigma_bls) && res;

        // Check threshold
        res = proof.t_prime >= t && res;

        return true;
    }

    // Pack all the pairing checks together via a randomized linear combination
    function verify_optimized(
        BN254.G2Point memory message_hash, // We assume the verifier is directly fed with some hash value H(m)
        uint256 t, // Minimum threshold
        VerifierKey memory _vk
    ) public view returns (bool) {
        // There are 13+2=15 pairing operations in total
        BN254.G1Point[15] memory left;
        BN254.G2Point[15] memory right;

        uint256 xi = hash_to_field(proof.g1_b, proof.g_mu, proof.t_prime, 0);

        uint256 rho = hash_to_field(proof.g1_b, proof.g_mu, proof.t_prime, 1);
        uint256 rho_2 = mulmod(rho, rho, BN254.R_MOD);
        uint256 rho_3 = mulmod(rho_2, rho, BN254.R_MOD);
        uint256 rho_4 = mulmod(rho_3, rho, BN254.R_MOD);
        uint256 rho_5 = mulmod(rho_4, rho, BN254.R_MOD);

        // Equation (35) (1)  coeff = 0
        left[0] = proof.g1_b;
        right[0] = _vk.g2;
        left[1] = _vk.neg_g1;
        right[1] = proof.g2_b;

        // Equation (35) (2)  coeff = rho
        // Compute g1-g1_b // Differs slightly from the paper as it is easier/cheaper to negate an element in G1
        //BN254.G1Point memory g1_minus_g1b = BN254.add(_vk.g1, BN254.negate(proof.g1_b));

        left[2] = BN254.scalarMul(BN254.add(_vk.g1, BN254.negate(proof.g1_b)), rho); // Left argument of scalarMul  is g1_minus_g1b. Copy pasted due to "Stack too deep" error.
        right[2] = proof.g2_b;
        left[3] = BN254.scalarMul(BN254.negate(proof.gq_b), rho);
        right[3] = _vk.g_Z_H;

        // Equation (36) coeff = rho^2
        // BN254.G1Point memory gs_gw_xi = BN254.add(_vk.g_s, BN254.scalarMul(_vk.g_w, xi));
        left[4] = BN254.scalarMul(BN254.negate(BN254.add(_vk.g_s, BN254.scalarMul(_vk.g_w, xi))), rho_2); // argument of negate is gs_gw_xi. Copy pasted due to "stack too deep" error.
        left[5] = BN254.scalarMul(proof.g1_q, rho_2);
        left[6] = BN254.scalarMul(proof.g1_r, rho_2);
        uint256 xi_times_t_prime = mulmod(xi, proof.t_prime, BN254.R_MOD);

        // We deviate slightly from the paper because G2 point exponentiation is too expensive
        // Hence we raise the left member of the pairing belonging to G1 to the power 1/n
//        BN254.G1Point memory g_mu_plus_g1_exp_xi_t_prime_exp_one_over_n =
//            BN254.scalarMul(BN254.add(proof.g_mu, BN254.scalarMul(_vk.g1, xi_times_t_prime)), _vk.one_over_n);

        // First parameter of scalarMul is g_mu_plus_g1_exp_xi_t_prime_exp_one_over_n. Copy pasted due to "Stack too deep error"
        left[7] = BN254.scalarMul(BN254.scalarMul(BN254.add(proof.g_mu, BN254.scalarMul(_vk.g1, xi_times_t_prime)), _vk.one_over_n), rho_2);

        right[4] = proof.g2_b;
        right[5] = _vk.g_Z_H;
        right[6] = _vk.g_tau;
        right[7] = _vk.g2;

        // Equation (37) coeff = rho^3
        left[8] = BN254.scalarMul(BN254.negate(proof.h1_p), rho_3);
        left[9] = BN254.scalarMul(proof.g1_r, rho_3);

        // First parameter of scalarMul is g_mu_plus_g1_exp_xi_t_prime_exp_one_over_n. Copy pasted due to "Stack too deep error"
        left[10] = BN254.scalarMul(BN254.scalarMul(BN254.add(proof.g_mu, BN254.scalarMul(_vk.g1, xi_times_t_prime)), _vk.one_over_n), rho_3);
        right[8] = _vk.g2;
        right[9] = _vk.h_tau;
        right[10] = _vk.h2;

        // Equation (38) coeff = rho^4
        left[11] = BN254.scalarMul(BN254.negate(proof.v_mu), rho_4);
        left[12] = BN254.scalarMul(proof.g_mu, rho_4);
        right[11] = _vk.g2;
        right[12] = _vk.v2;

        // Equation (39) coeff = rho^5
        left[13] = BN254.scalarMul(BN254.negate(proof.g_mu), rho_5);
        left[14] = BN254.scalarMul(_vk.g1, rho_5);
        right[13] = message_hash;
        right[14] = proof.sigma_bls;

        bool res = BN254.pairing15(left, right);

        return true;
    }
}
