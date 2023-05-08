# How to run examples:

1. Working environment

Prepare elements regtest working environment as described in https://elementsproject.org/elements-code-tutorial/working-environment

Note that node 1 in this environment should have enough regtest L-BTC to run the examples

2. Secp256k1-zkp

clone secp256k1-zkp from https://github.com/BlockstreamResearch/secp256k1-zkp

configure it with:

`./configure --enable-experimental --enable-module-generator --enable-module-rangeproof --enable-module-surjectionproof --enable-module-ecdh --enable-module-recovery --enable-experimental --enable-module-extrakeys --enable-module-schnorrsig`

and build it.

3. python-bitcointx

clone python-bitcointx from https://github.com/Simplexum/python-bitcointx

Install it into your python environment

4. python-elementstx

clone python-elementstx from https://github.com/simplexum/python-elementstx

and then switch to `taproot` branch (`git checkout taproot` in repo dir)

Install it into your python environment

5. Run

Within the python environment with these two libs installed, and secp256k1-zkp available, run

`PYTHON_BITCOINTX_ALLOW_LIBSECP256K1_EXPERIMENTAL_MODULES_USE=1 LD_LIBRARY_PATH=/path/to/secp256k1-zkp/.libs/ ./mint.py ~/elementsdir1/`

(the above the command is to run `mint.py` example, but the same should work for other examples, if there are any)

`~/elementsdir1` is from the elements regtest working environment set up at step 1.
