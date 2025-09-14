import os
os.environ["TERM"] = "linux"

from pwn import *
from sage.all import *
from tqdm import *

LOCAL = True
if LOCAL:
    r = process(["python3","../deploy/prob.py"],level="info")
else:
    assert NotImplementedError

def readParam(r,name):
    r.recvuntil(f"{name} = ".encode())
    return int(r.recvline().strip().decode())

# set difficulty
r.sendlineafter(b"Difficulty > ",b"hard")

BITS = 1024
p = readParam(r,"p")
print(f"{p = }")

def solve(r):
    mask = readParam(r,"mask")
    masked = readParam(r,"verhaltnis")

    bitmask = f'{mask:01024b}'[::-1]
    b1 = bitmask.index("1")-1
    b2 = bitmask.index("0",b1+1)
    b3 = BITS
    E1 = 2**b1
    E2 = 2**(b3-b2-1)
    assert E1*E2*4 == 2**(BITS//4)

    # 2Hole
    M = Matrix(ZZ,[
        [     E2*p,  0],
        [ E2*2**b2, E1]
    ])
    reduced = M.LLL()
    C = reduced[0,1]//E1
    Ec = 2*ceil(reduced[0].norm())

    # recover b
    approx = C*(masked+E1+E2*2**b2)%p
    B = Matrix(ZZ,[
        [Ec,  approx],
        [ 0,       p]
    ])
    reduced = B.LLL()
    b,err = reduced[0]
    b //= Ec
    if b<0:
        b,err = -b,-err
    
    # recover a
    a_mod_b = err%b*pow(C,-1,b)%b
    for k in range(3):
        a = k*b+a_mod_b
        if is_prime(a):
            break
    frac = a*pow(b,-1,p)%p
    assert masked == frac&mask

    r.sendlineafter(b"a > ",str(a).encode())
    r.sendlineafter(b"b > ",str(b).encode())

for _ in trange(100):
    solve(r)

r.interactive()