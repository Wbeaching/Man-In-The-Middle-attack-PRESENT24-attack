# IN603 - Cryptography: Man in the middle attack on a block cipher

## PRESENT24 block cipher specifications
The block cipher implemented in this project is a scaled-down version of
`PRESENT`, a lightweight cipher designed in 2007 by Bogdanov et al. and
standardized in the ISO/IEC 29192-2:2019. The version implemented here
(`PRESENT24`) will take an input message of 24 bits and will produce
a 24 bits ciphertext.

`PRESENT` is part of the SPN (Substitution-Permutation Network) ciphers family.
It is the second main structure type for designing block ciphers, the other
being Feistel Networks.

The concept behind SPN ciphers is simple, each round is composed of three layers:
- A XOR of the subkey to the register.
- A substitution to ensure confusion.
- A permutation to ensure diffusion.

The implementation of `PRESENT24` will perform ten rounds.

## Usage
To build the executable, please use the provided Makefile:
```
make
```

You can then run the program with one of the following options:
- With `-e`, you need to provide a 24 bits message as well as a 24 bits key, like so
```
./present24 -e MESSAGE KEY
```
- With `-d`, you need to provide a 24 bits cipher as well as a 24 bits key, like so
```
./present24 -d CIPHER KEY
```
- With `-a`, you need to provide two 24 bits messages as well as two 24 bits ciphers, like so
```
./present24 -a MESSAGE1 CIPHER1 MESSAGE2 CIPHER2
```
