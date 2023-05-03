# Solidity implementation of the WTS scheme

## Development environment

* [Install NIX](https://nixos.org/download.html).
For multi user installation:

```bash
sh <(curl -L https://nixos.org/nix/install) --daemon
```

Then run `nix develop` when entering this directory to install all the dependencies.
Note: some error messages will pop up, but everything should work.

## Run the tests 

```bash
run_tests.sh
```
## Benchmarks

Benchmarks can be obtained by running the following script.
```bash
run_benchmarks.sh
```

**Note:** the benchmark for the test function `testWTSVerifyOptimized`
    also takes into account the cost for computing the verifier key.
So to measure the gas cost for verifying a signature one must rest the gas 
    of the function `testComputeVerifierKey`.
This is needed due to a current limitation of forge, see https://ethereum.stackexchange.com/questions/132323/transaction-gas-cost-in-foundry-forge-unit-tests
 for a possible workaround.

## Notes about the implementation

We implement the verifier (see [WTS.sol](brownie/contracts/WTS.sol)) in solidity over the BN254 curve.
We provide two versions: the first version (see function `verifier`) follows the protocol described in
Figure 2 of the paper with some slight changes due to the fact that the BN254 pairing is asymmetric.
The second version (see function `verify_optimized`) is an optimization obtained by:
* Using a random linear combination of all equations involved in the non-optimized solution.
* Reducing several pairing checks to a single pairing check with 15 pairs, taking advantage
  of the gas formula from [EIP-1108](https://eips.ethereum.org/EIPS/eip-1108):
  `pairing_cost(k) = 34,000 k + 45,000`.
