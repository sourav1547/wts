import random
from py_ecc import bn128

r = 21888242871839275222246405745257275088548364400416034343698204186575808495617


def bn254_g1_to_sol(p):
    return [int(p[0]), int(p[1])]


def bn254_g2_to_sol(p):
    p0 = p[0]
    p1 = p[1]
    return [int(p0.coeffs[0]), int(p0.coeffs[1]), int(p1.coeffs[0]), int(p1.coeffs[1])]


def rand_g1_elem(seed=None):
    random.seed(seed)
    g1 = bn128.G1
    exp = random.randint(
        0, 21888242871839275222246405745257275088548364400416034343698204186575808495617
    )
    res = bn128.multiply(g1, exp)
    return res


def rand_g1_elem_sol(seed=None):
    elem = rand_g1_elem(seed)
    return bn254_g1_to_sol(elem)


def rand_g2_elem(seed=None):
    random.seed(seed)
    g2 = bn128.G2
    exp = random.randint(
        0, 21888242871839275222246405745257275088548364400416034343698204186575808495617
    )
    res = bn128.multiply(g2, exp)
    return res


def rand_g2_elem_sol(seed=None):
    elem = rand_g2_elem(seed)
    return bn254_g2_to_sol(elem)


def is_on_curve_g1(p):
    return bn128.is_on_curve(p, bn128.b)


def is_on_curve_g2(p):
    return bn128.is_on_curve(p, bn128.b2)
