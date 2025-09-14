from fastcrc import crc64
from fastecdsa.curve import Curve

import os
import random

PREFIX = os.urandom(random.randint(100, 1000))
SUFFIX = os.urandom(random.randint(100, 1000))
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
BITS = odr.bit_length()

def PoW():
    import hashlib
    DIFFICULTY = 7
    message = os.urandom(16).hex()
    res = hashlib.sha256(message.encode()).hexdigest()

    print(f"SHA-256({message[:-DIFFICULTY]} + xxxxxx) == {res}")
    inp = input("Solve PoW: ")
    assert len(inp) == DIFFICULTY

    if hashlib.sha256( (message[:-DIFFICULTY] + inp).encode() ).hexdigest() == res:
        return
    
    print("Wrong PoW")
    exit(1)

def read_flag():
    with open("flag","r") as f:
        print(f.read())


def main():
    a = int.from_bytes(os.urandom((BITS + 7) // 8), 'little') % odr
    assert a not in [0, 1, odr - 1]
    P = a*G

    while True:
        inp = bytes.fromhex(input('> ').strip())
        crc_res = crc64.xz(PREFIX + inp + SUFFIX)
        Q = crc_res*P

        if Q._is_identity():
            read_flag()
            break
        print(Q.x,Q.y)

if __name__ == "__main__":
    PoW()
    main()