# 2rabbits
A Proof of Concept implementation of the Advanced Rejection Sampling Algorithm for covert information leakage.

# Building

Run the `install.sh` script;

Next, build with cmake:
```bash
cmake --build ./build --config Debug --target all --
```

# Tests

To run tests, first build the binaries and cd into the bin folder

```bash
cd ./bin
```

Then run the test binaries with no arguments (they can take some time):

```bash
./test* 
```

Make sure that the keys are generated in the `{root-git}/keys` directory!