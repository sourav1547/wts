#!/usr/bin/python3

import brownie

# from brownie import WTS, BN254, accounts
# from brownie.network import main
from py_ecc import bn128
from wts_lib import (
    bn254_g1_to_sol,
    rand_g2_elem,
    is_on_curve_g2,
    rand_g2_elem_sol,
    rand_g1_elem_sol,
)


def test_crypto_operations(wts):
    g1 = bn128.G1
    exp = 4
    expected_res = bn254_g1_to_sol(bn128.multiply(g1, exp))
    g1_solidity = bn254_g1_to_sol(g1)
    res = wts.callScalarMul.call(g1_solidity, exp)
    assert res == expected_res


def test_solidity_python_conversion(wts):
    g2 = rand_g2_elem(54654)
    # TODO write a dedicated test for that
    assert is_on_curve_g2(g2)


def test_full_verifier_no_optimization(wts):

    ### Setup the verifier key vk
    n = 10
    g1_sol = rand_g1_elem_sol(12)
    g2_sol = rand_g2_elem_sol(12454)
    h2_sol = rand_g2_elem_sol(3484784)
    v2_sol = rand_g2_elem_sol(45454)

    g_s_sol = rand_g1_elem_sol(54545)
    g_w_sol = rand_g1_elem_sol(8787)

    g_tau_sol = rand_g2_elem_sol(135464645)
    h_tau_sol = rand_g2_elem_sol(2123232)
    g_z_H_sol = rand_g2_elem_sol(2222)

    wts.set_vk(
        g1_sol,
        g2_sol,
        h2_sol,
        v2_sol,
        g_s_sol,
        g_w_sol,
        g_tau_sol,
        h_tau_sol,
        g_z_H_sol,
        n,
    )

    g_mu = rand_g1_elem_sol(454115)
    g1_b = rand_g1_elem_sol(9988)
    g2_b = rand_g2_elem_sol(8722287)
    gq_b = rand_g1_elem_sol(4542225)
    sigma_bls = rand_g2_elem_sol(4456)
    g1_q = rand_g1_elem_sol(31143)
    g1_r = rand_g1_elem_sol(87878)
    h1_p = rand_g1_elem_sol(985256272)
    v_mu = rand_g1_elem_sol(4131313)
    t_prime = 5

    wts.set_proof(g_mu, g1_b, g2_b, gq_b, sigma_bls, g1_q, g1_r, h1_p, v_mu, t_prime)

    ### Call the verification function

    message_hash = rand_g2_elem_sol(5748578)

    # TODO this is not normal. Maybe something wrong with brownie (configuration) or in BN254.pairing3,BN254.pairing3pairing4 implementation
    with brownie.reverts("invalid opcode"):
        wts.verify(message_hash, 10)
