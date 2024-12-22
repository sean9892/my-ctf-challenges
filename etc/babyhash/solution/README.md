# Write-Up for `BabyHash`
If we remove all characters except `0` from `message`, each block except the last one is a full block filled with `0`, and we can reduce the number of candidates of the last block to `BSIZE`.

So the number of `0` is trivially obtainable.

Here, we query to get a hashed value $H_1$ made from a message only left `0` and `1`.

We find that the number of candidates of each block is $2^{BSIZE}$, which is $2^{26}$ in the given problem, and this is feasible amount to brute-force.

So rainbow-table method is able to recover the original `output` value in the current query. This allows us to recover every subsequence consisted of two hex digits.

Here, the very first hex digit comes in front of every other hex digit, which let us find it.

Using this property, we subsequently recover the prefix of message and delete the first one from our subsequences to fully get the `message`.

The algorithm above also can be interpreted as a linear order recovering with given partial orders. It can be solved with BFS on DAG.

But it is quite messy to be implemented in python as 2024 HSPACE CTF participants failed to debug in competition duration.