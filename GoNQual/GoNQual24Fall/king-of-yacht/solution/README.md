# Write-Up for `King of Yacht`
Basically, `0xdeadbeef` is an unaccomplishable score in Yacht.

So we need to exploit some of given game, and it is the save-file format in this challenge.

The tag of each value field is a kind of discrete-logarithm based signature.

However, its modulus is a power of 2, which allows user to solve discrete logarithm in tiny subgroups.

Solver exploits this property to recover each bit of the exponent from lsb, and make the tag of total score with value `0xdeadbeef`.

Here, since the multiplicative order of any odd numbers over mod $2^k$ is $2^{k-2}$, there might exist some lost bits.

Therefore we need to brute-force them by simply put those candidates to load menu.