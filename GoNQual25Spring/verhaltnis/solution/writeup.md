# Verhältnis writeup

1. **Prerequisite** - Lattice Reduction, HNP-2H (hard only)
2. **Objective** - small integer ratio recovery with noise

## Write-up for Easy mode

It is well-known that the following lattice $\mathcal{L}(B)$ is capable to recover small integer ratio $z=\frac{a}{b}$ over finite field $\mathbb{F}_q$, with appropriately given weight.

$$
B = \begin{bmatrix}
1&0&z\\
0&1&-1\\
0&0&p
\end{bmatrix}
$$

Solving SVP on $\mathcal{L}(B)$ gives a short vector $(b,a,0)$.

## Write-up for Hard mode

When you try to adapt the same strategy for the easy mode, one thing obstacles it is the mask, which doesn't allow you to get full information of $z$.

Unknown bits of $z$ are separated in two continuous part, which resembles to **HNP-2H**.

Typical approach for HNP-2H is to solve SVP on the following auxilary lattice $\mathcal{L}(A)$ to find proper constant $C$ to treat unknown bits to a single integer.

$$
A = \begin{bmatrix}
E_2p&0\\
E_22^{b_2}&E_1
\end{bmatrix}
$$

This lattice gives a short vector $v=(E_2(C2^{b_2}\mod p),E_1C)$.

Rationalizing this procedure is as the following:

$$
\begin{matrix}
&\Vert v\Vert_2 \le \frac{2}{\sqrt{3}}\sqrt{\det B}=\frac{2}{\sqrt{3}}\sqrt{E_1E_2N}\\
\Rightarrow&\vert \Delta e_1 C2^{b_1}+\Delta e_2C\mod N\vert\\
\le&\vert\Delta e_1\vert\vert C2^{b_1}\mod N\vert+\vert\Delta e_2\vert\vert C\vert\\
\le&E_1\vert C2^{b_1}\mod N\vert+E_2\vert C\vert\\
\le&\Vert v\Vert_2+\Vert v\Vert_2\\\le&\frac{4}{\sqrt{3}}\sqrt{E_1E_2N}
\end{matrix}$$

The first inequality came from Gaussian Heuristic.

Therefore, By multiplying $C$ to masked $z$ we could get a $z^\prime$ which can be written as $z^\prime \equiv_p C\frac{a}{b}+e$.

Note that $e$ satisfies $\vert e\vert\le \frac{4}{\sqrt{3}}\sqrt{E_1E_2N} = E_c$.

In a similar fashion for the easy mode, we could consider the following lattice.

$$
B = \begin{bmatrix}
E_c&0&z^\prime\\
0&E_c&-C\\
0&0&p
\end{bmatrix}
$$

This lattice contains a vector $(b,a,be)$, but this is not short enough to induced by a lattice reduction.

However, experimental result shows us that the lattice above gives a short vector $(b,0,bz^\prime\mod p)$. So we now consider the following sublattice of $\mathcal{L}(B)$, since this short vector doesn't need all those three basis vectors.

$$
B^{\prime} = \begin{bmatrix}
E_c&z^\prime\\
0&p
\end{bmatrix}
$$

From here, the only matter is to recover $a$. Let's focus on $bz^\prime\mod p=(Ca+be)\mod p$.

Note that $C$ is much smaller than $p$, which is less than $2^{630}$ with high probability.

Therefore we can assume $(Ca+be)\mod p=(Ca+be)$. Since we know $b$ now, it holds that $(bz^\prime\mod p)\mod b=(Ca\mod b)$ and this is computable.

This means we can find $a\mod b$. $a$ and $b$ are both 128 bits primes, thus $\frac{b}{2}\le a\le 2b$; which means $\left\lfloor\frac{a}{b}\right\rfloor\in\{0,1,2\}$.