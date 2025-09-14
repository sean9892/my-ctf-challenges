# Write-Up for `Elliptic Power of CRC`

CRC is just a rolling hash over a finite field.

With an unknown fixed prefix/suffix, CRC can be expressed as following:

$$
CRC(x) = U \oplus F(x)
$$

Here $U$ is a fixed unknown value and $F$ is a known linear function.

CRC hash results are given as an element of elliptic curve and there's no easy and feasible DLOG algorithm on given curve.

So we take the following strategy: The goal is to get a plaintext which outputs CRC hash value whose bits are all zero or all one.

The idea is, when CRC(x) differs only one bit(let it $i$-th LSB) from CRC(y), CRC(x) is one of CRC(y)-$2^i$ or CRC(y)+$2^i$.

Thus we can find whether each bit is equal to the LSB or not if we flip every bit of CRC hash.

This let the attacker unify the value of every CRC bit, and there are only two possible values, $0$ or $2^{64}-1$.