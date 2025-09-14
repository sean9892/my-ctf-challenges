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

The linearity of full AES' implies the existence of the $128\times129$ matrix $E$ such that:

$$
E(x\Vert 1) = AES^\prime(x)
$$

From this, we can find for all $x,y\in{\mathbb{F}_2}^{128}$,

$$
\begin{align}
AES^\prime(x)+AES^\prime(y) &=& E((x\Vert 1)+(y\Vert 1))\\
&=& E((x+y)\Vert 0)
\end{align}
$$

Thus $E^\prime$, which is $E$ removed its last column, is an invertible matrix satisfying $AES^\prime(x)+AES^\prime(y)=E^\prime(x+y)$.

Trivially multiplication over a polynomail ring ${\mathbb{F}_2}/f(x)$ is a linear transformation, i.e. there exists the corresponding $128\times 128$ matrix $M$.

So, we can recover the seed $s$ by the following calculation where $o_1$ and $o_2$ are two given ciphertext.

$$
s = (M+I_{128})^{-1}M^{-100}{E^\prime}^{-1}(o_1+o_2)
$$