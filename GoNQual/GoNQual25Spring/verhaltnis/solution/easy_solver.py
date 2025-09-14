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
r.sendlineafter(b"Difficulty > ",b"easy")

BITS = 1024
p = readParam(r,"p")
print(f"{p = }")

def solve(r):
    verhaltnis = readParam(r,"verhaltnis")

    T = 2**BITS
    M = matrix(ZZ,[
        [1,0,T*verhaltnis],
        [0,1,-T],
        [0,0,T*p]
    ])
    reduced = M.LLL()
    b,a,_ = reduced[0]
    if a<0:
        a,b = -a,-b
    assert _ == 0
    assert a*pow(b,-1,p)%p == verhaltnis
    r.sendlineafter(b"a > ",str(a).encode())
    r.sendlineafter(b"b > ",str(b).encode())

for _ in trange(100):
    solve(r)

r.interactive()