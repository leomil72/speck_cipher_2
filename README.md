
# SPECK64/128 BLOCK CIPHER
  

## What is it?
Speck cipher is a lightweight, easy to implement, relatively fast, simple
block cipher developed by NSA and released into the public domain in 2013.
It's aimed to software implementations and it's been developed primary for
IoT applications but, due to its simplicity and relatively robustness, it
can be used for a wide range of applications.

The code has been translated from the C reference source released by
NSA itself. Surely, it can be optimized and improved but, as it is, it's
a good starting point.
https://nsacyber.github.io/simon-speck/implementations/ImplementationGuide1.1.pdf

## Speck64/128 block cipher
The Speck64/128 is a block cipher, meaning that it works with fixed-width
blocks of data to be encrypted/decrypted. The "64/128" in its name stands
for the main characteristics of the algorithm: the block is 64 bits wide
while the key is 128 bits wide. The algorithms is based on the so-called
ARX scheme. ARX stands for Add-Rotate-Xor, indicating the 3 main operations
involed, the modular addition, the fixed rotation amounts, and the XOR.
Due to the limitations of the Dart language (it doesn't have any unsigned
integer type nor the ability to choose between different variable widths,
ie. 32- or 64-bits), and to keep the implementation as simple as possible,
I opted to implement the 64/128 version of the cipher that is based on
unsigned 32-bit variables, so that I could use the signed 64-bit integer
of Dart, keeping only the first 32 bits of its native data type.
