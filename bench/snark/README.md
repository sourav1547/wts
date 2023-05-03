## Benchmarking the SNARK based scheme

### Code strcutre
The `basic_test.go` consists of one example that tests a SNARK circuit verification for one signer.

The `smts.go, smts_test.go` and `merkle.go` are taken from https://github.com/rsinha/mts. These files consists of the SNARK circuit with multiple signers.


### Running basic tests
`cd` to `wts/bench/snark` and then use the following commands.

1. To run the Groth16 prover `go test -v -run=TestEDDSAGroth16`
2. To run the Plonk prover `go test -v -run=TestEDDSAPlonk`


### Benchmarking SNARK prover
To benchmark both Groth16 and Plonk prover, `cd` to `wts/bench/snark` and run the following command.
```
go test -v  -bench=BenchmarkSNARK -run=^# -benchtime=10s -timeout=20m
```

By default, it runs the SNARK prover with 8 signers i.e., `n=8`. The number of signers is specified by the variable `NUM_NODES` in `smts_test.go`. To change the number of signers, update `NUM_NODES` with approriate signers.
