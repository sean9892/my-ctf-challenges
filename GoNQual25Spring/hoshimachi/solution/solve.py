from pwn import *
from tqdm import *

def solve(hint):
    tap = [0, 1, 3, 4, 8, 17, 18, 21, 22, 25, 27, 29, 31, 32, 33, 34, 35, 36, 39, 42, 47, 48, 49, 50, 51, 52, 54, 55]
    ll = []
    for i in range(3):
        res = sum(hint[i+j]for j in tap)%2
        ll.append(res)
    return ll

LOCAL = True
if LOCAL:
    r = process(["python3","../deploy/prob.py"])
else:
    HOST = ""
    PORT = 0
    r = remote(HOST,PORT)

for _ in trange(100):
    hint = eval(r.recvline().strip().decode())
    res = solve(hint)
    r.sendline(("".join(map(str,res))).encode())
r.interactive()