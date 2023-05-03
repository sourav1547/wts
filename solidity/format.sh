#!/bin/bash

black .
forge fmt brownie/contracts/

cd forge/contracts
forge fmt
cd ../..