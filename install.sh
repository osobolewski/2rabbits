#!/bin/bash

git submodule add https://github.com/0NG/Format-Preserving-Encryption.git dependencies/Format-Preserving-Encryption &&
./gen_test_keys.sh &&
echo Install done