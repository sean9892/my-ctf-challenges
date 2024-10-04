from Crypto.Util.number import bytes_to_long as b2l
from Crypto.Cipher import AES
import hashlib
import os

def h(m,alg=hashlib.md5):
    if type(m) == int:
        m = int.to_bytes(m,length=4,byteorder='big')
    return b2l(alg(m).digest())|1

def long_tokenize(m,key,alg=hashlib.md5,size=32):
    if type(m) == int:
        m = int.to_bytes(m,length=4,byteorder='big')
    aeskey = hashlib.md5(m).digest()
    exponent = b2l(AES.new(aeskey,AES.MODE_ECB).encrypt(key))
    tag = pow(h(m,alg=alg),exponent,2**size)
    tag = int.to_bytes(tag,length=size//8,byteorder='big')
    return m+tag

save = "4b4f59534400003ffd1845830100000001195179d900000002cf6e054100000009a5e3a16100000008a2fdd72100000005738c83450000000092acfc8900000000798fd161000000086d656c71000000006201e3c9000000003246230900000000af047a29000000001f921d910000000d7fa31d1b0000002ead518f9f916304cbcc46c4d0b0f62756cf8093ddf935a26590b3edd624805098f091bfe3bab6c926e41388a81bdd8a779fbb05917fbff383aa8dd82891d80a57"
save = bytes.fromhex(save)

data = save[-68:]
val = data[:4]
aeskey = hashlib.md5(val).digest()
tag = data[4:]
val = b2l(val)
tag = b2l(tag)
v = h(val,alg=hashlib.sha512)

# base 5
def dlog(base,tar):
    MOD = 2**512
    o = 512
    while True:
        if pow(base,2**o,MOD) == 1:
            o -= 1
        else:
            o += 1
            break
    t = tar
    l = ''
    res = 0
    for i in range(o):
        r = pow(t,2**(o-i-1),MOD)
        if r == 1:
            l += '0'
        else:
            t = t*pow(base,-2**i,MOD)%MOD
            l += '1'
            res += 2**i
    assert int(l[::-1],2) == res
    if pow(base,res,MOD) == tar:
        return o,res
    else:
        return o,None

cipher = AES.new(aeskey,AES.MODE_CBC)
o,ekey = dlog(v,tag)

oo = 512
for t in range(max(2**(oo-o),1)):
    cipher = AES.new(aeskey,AES.MODE_ECB)
    k = t*2**o+ekey
    assert k == (t*2**o)|ekey
    k = int.to_bytes(k,length=64,byteorder='big')
    k = cipher.decrypt(k)
    #print(k.hex())
    print(save[:-68].hex()+long_tokenize(0xdeadbeef,k,alg=hashlib.sha512,size=512).hex())