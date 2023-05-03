#!/bin/bash
FILENAME=current_benchmarks.txt
FULL_FILENAME=$ROOT/$FILENAME

# Copy files to forge directory
cp $ROOT/brownie/contracts/*.sol $ROOT/forge/contracts/src

cd $ROOT/benchmarks

echo "git rev:" > $FULL_FILENAME
echo `git rev-parse HEAD` >> $FULL_FILENAME

echo  >> $FULL_FILENAME
echo "***  Estimations ***" >> $FULL_FILENAME

python ballpark_bls12381.py >> $FULL_FILENAME
python ballpark_bn254.py >> $FULL_FILENAME

echo  >> $FULL_FILENAME

echo "***  Implementation ***" >> $FULL_FILENAME

cd $ROOT/forge/contracts
forge snapshot
cat .gas-snapshot | grep "WTSVerif" >> $FULL_FILENAME


cd $ROOT

echo
echo "//////// Benchmark report can be found at current_benchmarks.txt //////"
echo