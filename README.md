# IN603 - Cryptography: Man in the middle attack on a block cipher

## PRESENT24 block cipher specifications
The block cipher implemented in this project is a scaled-down version of
PRESENT, a lightweight cipher designed in 2007 by Bogdanov et al. and
standardized in the ISO/IEC 29192-2:2019. The version implemented here
(PRESENT24) will take an input message of 24 bits and will produce
a 24 bits ciphertext.

PRESENT is part of the SPN (Substitution-Permutation Network) ciphers family.
It is the second main structure type for designing block ciphers, the other
being Feistel Networks.

The concept behind SPN ciphers is simple, each round is composed of three layers:
- A XOR of the subkey to the register.
- A substitution to ensure confusion.
- A permutation to ensure diffusion.

This implementation of present will perform ten rounds.

## Usage
To build the executable, please use the provided Makefile:
```
make
```
You can then run the program with the following:
```
./present24 -[d | e] KEY
```
