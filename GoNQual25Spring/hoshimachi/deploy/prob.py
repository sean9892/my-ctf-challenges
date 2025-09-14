from Crypto.Random.random import randrange
from secret import flag
import hashlib

class LFSR:
    def __init__(self,tap,state):
        self.tap = tap
        self.state = state[:]
        for _ in range(1000):
            self.next()
    
    def next(self):
        state = self.state[:]
        nxt = sum(state[i]for i in self.tap)%2
        out = state[0]
        self.state = state[1:]+[nxt]
        return out

def gen_state(n):
    return [randrange(2)for _ in range(n)]

def stream(s1,s2,n):
    return [(s1.next()+s2.next())%2 for _ in range(n)]

tap1 = tuple([0, 1, 2, 4, 5, 7, 9, 11, 13, 15, 17, 18, 23, 25, 28, 31])
tap2 = tuple([0, 2, 5, 8, 12, 16, 18, 19, 20, 21, 22, 25, 27, 29, 30, 31])
def challenge():
    state1 = gen_state(32)
    state2 = gen_state(32)

    stream1 = LFSR(tap1,state1)
    stream2 = LFSR(tap2,state2)

    hint = stream(stream1,stream2,58)
    print(hint)
    answer = [stream1.next()for _ in range(3)]
    guess = list(map(int,input()))
    return answer == guess

for _ in range(100):
    if not challenge():
        break
else:
    print(flag)