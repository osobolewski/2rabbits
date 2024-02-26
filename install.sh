#!/bin/bash

git submodule update --init &&
./gen_test_keys.sh &&
cd dependencies/Format-Preserving-Encryption/ &&
make &&
echo Install done