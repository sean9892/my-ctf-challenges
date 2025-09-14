from Crypto.Util.number import getPrime
from Crypto.Random.random import randrange
from secret import easy_flag,hard_flag

# Pre-Challenge settings
diff = input("Difficulty > ")
assert diff in ["easy","hard"]
diff = ["easy","hard"].index(diff)
flag = [easy_flag,hard_flag][diff]

# ============== Challenge starts from here ==============

BITS = 1024
p = getPrime(BITS)
print(f"{p = }")

# Only used in hard mode
def genMask(cnt):
        L1 = randrange(1,cnt-1)
        L2 = cnt-L1
        l = [str(int(L1<=i<BITS-L2)) for i in range(BITS)]
        assert l.count('0') == cnt
        return int(''.join(l),2)

def challenge(diff):
    mask = genMask(BITS//4)
    a,b = [getPrime(BITS//8)for _ in range(2)]
    frac = a*pow(b,-1,p)%p
    # You'll get the masked one in hard mode
    verhaltnis = [frac,(frac&mask)][diff]
    if diff:
        print(f"{mask = }")
    print(f"{verhaltnis = }")
    guess_a = int(input("a > "))
    guess_b = int(input("b > "))
    return (a,b) == (guess_a,guess_b)

# Succeed 100 times in a row to get a flag
for _ in range(100):
    if not challenge(diff):
        break
else:
    print(flag)