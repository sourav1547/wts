#!/bin/bash

# Copy files to forge directory
cp $ROOT/brownie/contracts/*.sol $ROOT/forge/contracts/src

# Run brownie tests
cd $ROOT/brownie
brownie test


# Run forge tests
cd $ROOT/forge/contracts
forge test

cd $ROOT
