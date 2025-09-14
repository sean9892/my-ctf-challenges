from sage.all import *
import os
os.environ["TERM"] = "linux"
from pwn import *
from tqdm import *
import hashlib
from multiprocessing import Process,Manager
from fastecdsa.curve import Curve
from fastecdsa.point import Point

def bf(prf,target,st,ed,sig,ret,lock):
    for guess in trange(st,ed):
        if guess%512 == 0:
            with lock:
                if sig.value:
                    return
        m = f"{prf}{guess:07x}".encode()
        if hashlib.sha256(m).hexdigest() == target:
            with lock:
                ret.value = guess
                sig.value = 1
            return
    return

def solvePoW(prf,target):
    with Manager() as manager:
        sig = manager.Value('i',0)
        ret = manager.Value('i',0)
        lock = manager.Lock()
        N = 8
        M = 16**7
        piv = [i*M//N for i in range(N)]+[M]
        prcs = [Process(target=bf,args=(prf,target,st,ed,sig,ret,lock))for st,ed in zip(piv,piv[1:])]
        for prc in prcs:
            prc.start()
        for prc in prcs:
            prc.join()
        print(ret.value)
        return f"{ret.value:07x}"


LOCAL = True
if LOCAL:
    r = process(["python3","prob.py"],level="info")
else:
    #nc host3.dreamhack.games 19630
    HOST = "host3.dreamhack.games"
    PORT = 19630
    r = remote(HOST,PORT)

if not LOCAL:
    r.recvuntil(b"SHA-256(")
    prf = r.recv(32-7).decode()
    r.recvuntil(b" == ")
    target = r.recvline().strip().decode()
    powans = solvePoW(prf,target)
    r.sendlineafter(b"PoW: ",powans.encode())
    print("[+] PoW solved")

def oracle(r,val,expect_correct=False):
    r.sendlineafter(b"> ",val.hex().encode())
    res = r.recvline().decode().strip()
    if expect_correct:
        if "{" in res and "}" in res:
            print(res)
            exit(0)
    else:
        xx,yy = map(int,res.split())
        return Point(xx,yy,curve=curve)

p = 264197489212474837735311395665505550899
a = 131045900645592496086677816508366009300
b = 196333825747140175125267026866682422975
odr = 4984858287027827126613148017654791359
gx = 51478926227802965891885295159827422324
gy = 145473956779033440999665031477366742425
curve = Curve(
    "MyNIST128",
    p,a,b,odr,
    gx,gy
)
G = curve.G

F = GF(2)
R = F["x"]
x = R.gen()
g = '11001001011011000101011110010101110101111000011100001111010000101'
g = R(list(map(int,g)))
RR = R.quotient(g)
xbar = RR.gen()

def RR2bytes(val):
    l = list(val)
    l = l[::-1]
    l = list(map(int,l))
    res = 0
    for i in range(0,len(l),8):
        res <<= 8
        for j in range(8):
            res += l[i+j]*(2**j)
    res = res.to_bytes(8,"big")
    return res

zenc = oracle(r,b"\x00"*8)
neg1 = xbar**63
all1 = RR([1]*64)

def solve(Ls):
    f = neg1*xbar**(-8*Ls-64)
    fv = RR2bytes(f)
    off1 = oracle(r,fv)
    abar = zenc-off1
    
    l = [1]
    fff = 0
    ifff = f
    for i in range(1,64):
        ff = xbar**(63-i)*xbar**(-8*Ls-64)
        ffv = RR2bytes(ff)
        v = oracle(r,ffv)
        if zenc-v == 2**i*abar:
            l.append(1)
            ifff += ff
        else:
            l.append(0)
            fff += ff
    fffv = RR2bytes(fff)
    ifffv = RR2bytes(ifff)
    oracle(r,fffv,True)
    oracle(r,ifffv,True)

for Ls in trange(100,1000):
    solve(Ls)
