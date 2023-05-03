# From https://eips.ethereum.org/EIPS/eip-2537

from enum import Enum


class Groups(Enum):
    G1 = 1
    G2 = 2


def pairing_cost(k):
    return 43000 * k + 65000


G1_ECC_ADD = 500
G1_ECC_MUL = 12000

G2_ECC_ADD = 800
G2_ECC_MUL = 45000


def multi_exp_cost(k, group):
    discount = [
        [1, 1200],
        [2, 888],
        [3, 764],
        [4, 641],
        [5, 594],
        [6, 547],
        [7, 500],
        [8, 453],
        [9, 438],
        [10, 423],
        [11, 408],
        [12, 394],
        [13, 379],
        [14, 364],
        [15, 349],
        [16, 334],
        [17, 330],
        [18, 326],
        [19, 322],
        [20, 318],
        [21, 314],
        [22, 310],
        [23, 306],
        [24, 302],
        [25, 298],
        [26, 294],
        [27, 289],
        [28, 285],
        [29, 281],
        [30, 277],
        [31, 273],
        [32, 269],
        [33, 268],
        [34, 266],
        [35, 265],
        [36, 263],
        [37, 262],
        [38, 260],
        [39, 259],
        [40, 257],
        [41, 256],
        [42, 254],
        [43, 253],
        [44, 251],
        [45, 250],
        [46, 248],
        [47, 247],
        [48, 245],
        [49, 244],
        [50, 242],
        [51, 241],
        [52, 239],
        [53, 238],
        [54, 236],
        [55, 235],
        [56, 233],
        [57, 232],
        [58, 231],
        [59, 229],
        [60, 228],
        [61, 226],
        [62, 225],
        [63, 223],
        [64, 222],
        [65, 221],
        [66, 220],
        [67, 219],
        [68, 219],
        [69, 218],
        [70, 217],
        [71, 216],
        [72, 216],
        [73, 215],
        [74, 214],
        [75, 213],
        [76, 213],
        [77, 212],
        [78, 211],
        [79, 211],
        [80, 210],
        [81, 209],
        [82, 208],
        [83, 208],
        [84, 207],
        [85, 206],
        [86, 205],
        [87, 205],
        [88, 204],
        [89, 203],
        [90, 202],
        [91, 202],
        [92, 201],
        [93, 200],
        [94, 199],
        [95, 199],
        [96, 198],
        [97, 197],
        [98, 196],
        [99, 196],
        [100, 195],
        [101, 194],
        [102, 193],
        [103, 193],
        [104, 192],
        [105, 191],
        [106, 191],
        [107, 190],
        [108, 189],
        [109, 188],
        [110, 188],
        [111, 187],
        [112, 186],
        [113, 185],
        [114, 185],
        [115, 184],
        [116, 183],
        [117, 182],
        [118, 182],
        [119, 181],
        [120, 180],
        [121, 179],
        [122, 179],
        [123, 178],
        [124, 177],
        [125, 176],
        [126, 176],
        [127, 175],
        [128, 174],
    ]

    # LEN_PER_PAIR = {Groups.G1: 160, Groups.G2: 288}
    # LEN_INPUT = 256

    if k == 0:
        return 0
    multiplier = 1000
    multiplication_cost = {Groups.G1: G1_ECC_MUL, Groups.G2: G2_ECC_MUL}

    gas_cost = (k * multiplication_cost[group] * discount[k][1]) / multiplier

    return gas_cost


def total_cost():

    cost = 0

    # Equation (35)
    cost += (
            2 * pairing_cost(2)
            + G1_ECC_ADD  # + 3 * ECC_NEGATE // Not taken into account
    )  # Note: one extra pairing compared to the paper because BLS12381 is an asymmetric pairing

    # Equation (36)
    cost += (
            pairing_cost(4)
            + 2 * G1_ECC_ADD
            + 2 * G1_ECC_MUL
        # + ECC_NEGATE  Ignored
        # + FIELD_INVERT Ignored
    )

    # Equation (37)
    cost += (
            pairing_cost(3) + G1_ECC_ADD + G1_ECC_MUL
    )  # + 2 * ECC_NEGATE Ignored

    # Equation (38)
    cost += pairing_cost(2)  # + ECC_NEGATE Ignored

    # Equation (39)
    cost += pairing_cost(2)  # + ECC_NEGATE Ignored

    return cost


def total_cost_optimized_section_4_8():

    cost = 0

    # Equation (42)
    cost += G2_ECC_ADD + 2 * G2_ECC_MUL
    cost += pairing_cost(3)

    # Equation (43)
    # cost += 2*G1_ECC_ADD_COST +2 * G1_ECC_MUL_COST // This gives slightly higher gas compared to the multiexp below
    cost += multi_exp_cost(3, Groups.G1)
    cost += G2_ECC_MUL
    cost += 2 * (G1_ECC_ADD + G1_ECC_MUL)
    cost += 2 * G2_ECC_ADD + G2_ECC_MUL
    cost += pairing_cost(5)

    # BLS sig verification
    cost += pairing_cost(2)

    # Cost in group operations
    # 2 G1
    # 5 G1 mul
    # 3 G2
    # 4 G2 mul
    # P(5) + P(3) + P(2)

    return cost


if __name__ == "__main__":
    print("**** BLS 12381 ****")
    print("Total cost: " + str(total_cost()))
    print(
        "Total cost optimized (section 4.8): " + str(total_cost_optimized_section_4_8())
    )
