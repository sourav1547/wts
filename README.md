## Threshold Sigantures from Inner Product Argument: Succinct, Weighted, Multi-threshold
This repository implements a new threshold signature scheme with succinct signature size and verification time, which also supports arbitrary weight distribution and multiple thresholds.

### Code structure 
The repository contains implementation of the following:
1. Our threhsold signature scheme in `wts/src/`
2. Solidity implementation of the verifier `wts/solidity/`

We will benchmark the following other approaches.
1. Compact certificate of knowledge by Micali et al.  `wts/bench/compactcert/`
2. BLS threshold signature and multisignature `wts/bench/multsig/`
3. Generic SNARK `wts/bench/snark/`
4. Generalized Inner Product Argument (GIPA) `wts/gipa/`

NOTE: Our implementation of GIPA is very preliminary and it does not implement all parts of the GIPA protocol.


### Dependencies and Installation
This library uses `go` version `1.19.x` or higher. The library has been tested with `Ubuntu` and `Mac-OS`.

You can test your installation by running the following command inside the `wts/src/` folder:
```
go test -run=TestWTS
```

### Running Tests and Benchmarks
Implementation of each appraoch has its own testcases and bechmakrs, typically in files named as `[APPROACH]_test.go`. For example the functions to test and benchmark our threshold signature are included in the `wts/src/wts_test.go`. 

### Benchmarking our approach
IMPORTANT: `cd` to `wts/src/` 

Benchmark with specific nubmer of signers. Recommened to start with smaller values of such as 128, 256, etc. Here the flag `-signers` indicate the number of signers. 

NOTE: We have only tested with values of `n` that are powers of two. Also, when you run with larger `n`, it will take several minutes as
    - Generating the CRS takes time, and
    - We generate the signing keys of all the sigers sequentially.

```
go test -v  -bench=BenchmarkWTS -run=^# -signers=[NUM_OF_SIGNERS] -benchtime=10s -timeout 20m
```

### Benchmarking BLS threshold signature and BLS Multisig
IMPORTANT: `cd` to `wts/bench/multisig/` 

1. Run the full BLS multisignature benchmark reported in the paper
```
go test -v  -bench=BenchmarkMultSigUW -run=^# -benchtime=10s -timeout 30m
```

2. Run the full BLS threshold signature benchmark reported in the paper
```
go test -v  -bench=BenchmarkBLSUW -run=^# -benchtime=10s -timeout 30m
```

3. Benchmark BLS threshold signature with `t=32768` and `t=65536`
```
go test -v  -bench=BenchmarkBLSLarge -run=^# -benchtime=10s -timeout 30m
```

NOTE: For benchmarking the SNARK please refer to `bench/snark/README.md`
