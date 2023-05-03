# From https://eips.ethereum.org/EIPS/eip-1108
def pairing_cost(k):
    return 34000 * k + 45000


ECC_ADD = 150
ECC_MUL = 6000
ECC_NEGATE = 5000  # Measured
FIELD_INVERT = 2000  # Measured


def total_cost():

    cost = 0

    # Equation (35)
    cost += (
        2 * pairing_cost(2) + ECC_ADD + 3 * ECC_NEGATE
    )  # Note: one extra pairing compared to the paper because BN254 is an asymmetric pairing

    # Equation (36)
    cost += pairing_cost(4) + 2 * ECC_ADD + 2 * ECC_MUL + ECC_NEGATE + FIELD_INVERT

    # Equation (37)
    cost += pairing_cost(3) + ECC_ADD + ECC_MUL + ECC_NEGATE

    # Equation (38)
    cost += pairing_cost(2) + ECC_NEGATE

    # Equation (39)
    cost += pairing_cost(2) + ECC_NEGATE


    return cost


def total_cost_optimized():

    cost = 0
    cost += 3 * ECC_ADD
    cost += 7 * ECC_NEGATE
    cost += 15 * ECC_MUL
    cost += FIELD_INVERT
    cost += pairing_cost(15)



    return cost


if __name__ == "__main__":
    print("**** BN 254 ****")
    print("Total cost: " + str(total_cost()))
    print(
        "Total cost optimized (random linear comb on G_T elements): "
        + str(total_cost_optimized())
    )
