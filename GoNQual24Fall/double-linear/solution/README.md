# Write-Up for `Double Linear`

In this write-up, `AES'` refers the custom implementation given in this challenge.

The security level of AES is highly dependent on its S-Box.

However, that of AES' is fully linear and you can check it by the following code:

```
sage: from sage.crypto.sbox import SBox
sage: SBox(sbox).nonlinearity()
0
```

Thus every operation including keyed permutation and sbox in AES' is linear, which lays a huge problem.

The linearity of full AES' implies the existence of $128\times129$ matrix $M$ such that:

$$
M\times(x\vert\vert 1) = AES^\prime(x)
$$

From this, we can find:

$$
\forall x,y\in {\mathbb{F}_2}^{128}\\
\begin{align}
AES^\prime(x)+AES^\prime(y) &=& M\times((x\vert\vert 1)+(y\vert\vert 1))\\
&=& M\times((x+y)\vert\vert 0)
\end{align}
$$

