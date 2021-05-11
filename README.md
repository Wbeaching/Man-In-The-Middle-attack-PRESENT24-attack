# Cryptography: Man In The Middle attack on a block cipher
by Theophile Molinatti and Gabriel Dos Santos

## PRESENT24 block cipher specifications
The block cipher implemented in this project is a scaled-down version of
`PRESENT`, a lightweight cipher designed in 2007 by Bogdanov et al. and
standardized in the ISO/IEC 29192-2:2019. The version implemented here
(`PRESENT24`) will take an input message of 24 bits and will produce
a 24 bits ciphertext.

`PRESENT` is part of the Substitution-Permutation Network (SPN) ciphers family.
It is the second main structure type for designing block ciphers, the other
being Feistel Networks.

The concept behind SPN ciphers is simple, each round is composed of three layers:
- A XOR of the subkey to the register.
- A substitution to ensure confusion.
- A permutation to ensure diffusion.

This implementation of `PRESENT24` will perform eleven rounds.


## Usage
### Pre-requisites
Even though the application has been written to be able to run on any operating
system, we **strongly** advise you to run it on a Linux-based OS (with kernel
2.6.28 or higher).

As the provided Makefile uses compiler-specific optimization flags, you will
need to have the GNU C Compiler (`gcc`) installed on your system to able to
compile the source code (version 7.0 or higher).


### Compilation
To build the executable, please use the provided Makefile:
```
make
```


### Execution
You can then run the program with one of the following options:
- `-e` lets you use encryption mode, provided a message and a key (24 bits each).
```
./present24 -e MESSAGE KEY
```

- `-d` lets you use decryption mode, provided a cipher and a key (24 bits each).
```
./present24 -d CIPHER KEY
```

- `-a` lets you use attack mode on `2PRESENT24`.
The attack option takes two pairs of plain and cipher texts as inputs, *(m1, c1)* and *(m2, c2)*.
You can also provide the extra `-t` option to set the numbers of threads used to run the application.
```
./present24 -a MESSAGE1 CIPHER1 MESSAGE2 CIPHER2 [-t NB_THREADS]
```
If the `-t` option is not specified, the program will run with 4 threads by default.


The Makefile also comes with pre-made commands to ***test*** the application. These are the following:
- `make encrypt` runs PRESENT24 on the 4 test vectors provided in the subject.
- `make decrypt` runs PRESENT24 on the 4 test vectors provided in the subject.
- `make attack_theophile` runs the attack on PRESENT24 with Theophile's pairs of plain/cipher texts.
- `make attack_gabriel` runs the attack on PRESENT24 with Gabriel's pairs of plain/cipher texts.

Feel free to run it with values of your own!


## Performance analysis
### Compiler optimization flags
For this project, we used the widely available GNU C Compiler (`gcc`) which
provides numerous optimization flags that helped us get faster execution times.
We will hereafter describe some of them:
- `-O3` enables all of the optimizations that `gcc` provides, apart from floating
point arithmetic (which is not relevant in our case).
The compiler cannot guarantee that the requested flags will be applied as 
the source code may not be optimized enough to allow `gcc` to recognize code patterns.
However, the code outputting the `-O3` option may be suitable for enhancements that
were not available before.
- `-march=native` and `-mtune=native` enable architecture specific optimizations 
that will allow the compiler to generate code that uses specific instructions 
(e.g. **SSE** and/or **AVX** instructions used for vectorization, if they are available).
- `-finline-functions` enables function in-lining whenever it is possible
which gives better execution times as it removes the call to the function
by copying its code when needed. 
This works especially well for small functions that are called often or in a loop.
The use of this flag is paired with the presence of the keyword `inline` in
the C source code which helps the compiler do better work.
- Loop optimization flags such as `-funroll-loops` or `-ftree-loop-vectorize`
are requested to ensure that the code is as optimized as possible, in case
the compiler could not apply them on the first pass with `-O3`.

<p align="center">
  <img src="https://user-images.githubusercontent.com/55387403/117890864-37822480-b2b6-11eb-8875-c74b5e0f3140.png">
</p>

### The permutation layer
The [permutation box](https://en.wikipedia.org/wiki/Permutation_box) (P-box) is arguably
the optimization that has the most significant impact on performance.
Because it is so heavily used throughout the attack, both during encryption and decryption, 
it can become the bottleneck of the application if not carefully implemented.

The naive approach we first took was to use a static array that transposes
every bits. In conjonction, we used a `for` loop to permute each bit of the input text to its final position.
However, using a loop means that we need to perform as many iterations as they are bits
in the block, each of them having to compute multiple memory addresses which
are known to be very expensive operations.

Using the performance analysis and optimization framework developed at UVSQ,
[MAQAO](http://www.maqao.org/) (Modular Assembly Quality Analyzer and Optimizer), we noticed that
over 50% of the execution time was spent in the P-box layer, so we decided to
take another approach.

Instead of using of arrays and loops, we implemented the entire P-box manually 
by directly placing the bits of the input message to their final position
using masks and shifts. This method also reduces the number of memory accesses, 
thus drastically improving performance and delivering an **overall speedup of 3.6**.


### Choosing the sorting algorithm
To be able to perform a binary search on the dictionaries, we first need to sort them.
As advised by Mrs Christina BOURA, we started by implementing a **quick sort algorithm**, 
as it often yields very good results on any type of data, averaging a time complexity of *O(nlog(n))*.

Nonetheless, we decided to switch to a **radix sort algorithm** which is more efficient on the type of data we are dealing with.
Indeed, radix sort is noticeably better at sorting numbers, with an average time complexity of *(O(nk))*, making it very fitting in our case.

We achieved execution times, on the sorting part, up to **9.6 times faster** (allowing for an overall acceleration of 1.26).


### Parallelizing the attack
The last and probably most important optimization we made is to make the attack parallel.
Thanks to Mr [Salah IBN AMAR](https://github.com/yaspr) (teacher-researcher in HPCS and at the Li-PaRAD and Exascale Computing Research labs),
we had the opportunity to measure the performances of our program on super-calculators,
comparing the execution time with different numbers of threads.
We ran the benchmarks on the following machines:
- an AMD Zen2 (EPYC 7302), 64 cores.
- an Intel Skylake (Xeon Platinum 8170), 52 cores.
- an Intel Tigerlake (i5-1135G7), 4 cores.
- an AMD Zen3 (Ryzen 7 3800X), 8 cores.

<p align="center">
  <img src="https://user-images.githubusercontent.com/55387403/117891025-7dd78380-b2b6-11eb-9aaa-c23c4a2adcab.png">
</p>
