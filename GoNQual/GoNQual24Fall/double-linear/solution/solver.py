from sage.all import *
from Crypto.Util.number import bytes_to_long
import hashlib
import os

def long_to_bytes(x):
    return int.to_bytes(x,length=16,byteorder='big')

def gmul(a,b,modulus):
    r = 0
    while b:
        if b&1:
            r ^= a
        a <<= 1
        b >>= 1
        if a&(1<<128):
            a ^= modulus
    return r

def gpow(a,n,modulus):
    r = 1
    while n:
        if n&1:
            r = gmul(r,a,modulus)
        n>>=1
        a = gmul(a,a,modulus)
    return r

s_box = (192, 45, 69, 168, 109, 128, 232, 5, 97, 140, 228, 9, 204, 33, 73, 164, 237, 0, 104, 133, 64, 173, 197, 40, 76, 161, 201, 36, 225, 12, 100, 137, 18, 255, 151, 122, 191, 82, 58, 215, 179, 94, 54, 219, 30, 243, 155, 118, 63, 210, 186, 87, 146, 127, 23, 250, 158, 115, 27, 246, 51, 222, 182, 91, 78, 163, 203, 38, 227, 14, 102, 139, 239, 2, 106, 135, 66, 175, 199, 42, 99, 142, 230, 11, 206, 35, 75, 166, 194, 47, 71, 170, 111, 130, 234, 7, 156, 113, 25, 244, 49, 220, 180, 89, 61, 208, 184, 85, 144, 125, 21, 248, 177, 92, 52, 217, 28, 241, 153, 116, 16, 253, 149, 120, 189, 80, 56, 213, 46, 195, 171, 70, 131, 110, 6, 235, 143, 98, 10, 231, 34, 207, 167, 74, 3, 238, 134, 107, 174, 67, 43, 198, 162, 79, 39, 202, 15, 226, 138, 103, 252, 17, 121, 148, 81, 188, 212, 57, 93, 176, 216, 53, 240, 29, 117, 152, 209, 60, 84, 185, 124, 145, 249, 20, 112, 157, 245, 24, 221, 48, 88, 181, 160, 77, 37, 200, 13, 224, 136, 101, 1, 236, 132, 105, 172, 65, 41, 196, 141, 96, 8, 229, 32, 205, 165, 72, 44, 193, 169, 68, 129, 108, 4, 233, 114, 159, 247, 26, 223, 50, 90, 183, 211, 62, 86, 187, 126, 147, 251, 22, 95, 178, 218, 55, 242, 31, 119, 154, 254, 19, 123, 150, 83, 190, 214, 59)

inv_s_box = (17, 200, 73, 144, 222, 7, 134, 95, 210, 11, 138, 83, 29, 196, 69, 156, 120, 161, 32, 249, 183, 110, 239, 54, 187, 98, 227, 58, 116, 173, 44, 245, 212, 13, 140, 85, 27, 194, 67, 154, 23, 206, 79, 150, 216, 1, 128, 89, 189, 100, 229, 60, 114, 171, 42, 243, 126, 167, 38, 255, 177, 104, 233, 48, 20, 205, 76, 149, 219, 2, 131, 90, 215, 14, 143, 86, 24, 193, 64, 153, 125, 164, 37, 252, 178, 107, 234, 51, 190, 103, 230, 63, 113, 168, 41, 240, 209, 8, 137, 80, 30, 199, 70, 159, 18, 203, 74, 147, 221, 4, 133, 92, 184, 97, 224, 57, 119, 174, 47, 246, 123, 162, 35, 250, 180, 109, 236, 53, 5, 220, 93, 132, 202, 19, 146, 75, 198, 31, 158, 71, 9, 208, 81, 136, 108, 181, 52, 237, 163, 122, 251, 34, 175, 118, 247, 46, 96, 185, 56, 225, 192, 25, 152, 65, 15, 214, 87, 142, 3, 218, 91, 130, 204, 21, 148, 77, 169, 112, 241, 40, 102, 191, 62, 231, 106, 179, 50, 235, 165, 124, 253, 36, 0, 217, 88, 129, 207, 22, 151, 78, 195, 26, 155, 66, 12, 213, 84, 141, 105, 176, 49, 232, 166, 127, 254, 39, 170, 115, 242, 43, 101, 188, 61, 228, 197, 28, 157, 68, 10, 211, 82, 139, 6, 223, 94, 135, 201, 16, 145, 72, 172, 117, 244, 45, 99, 186, 59, 226, 111, 182, 55, 238, 160, 121, 248, 33)


def sub_bytes(s):
    for i in range(4):
        for j in range(4):
            s[i][j] = s_box[s[i][j]]


def inv_sub_bytes(s):
    for i in range(4):
        for j in range(4):
            s[i][j] = inv_s_box[s[i][j]]


def shift_rows(s):
    s[0][1], s[1][1], s[2][1], s[3][1] = s[1][1], s[2][1], s[3][1], s[0][1]
    s[0][2], s[1][2], s[2][2], s[3][2] = s[2][2], s[3][2], s[0][2], s[1][2]
    s[0][3], s[1][3], s[2][3], s[3][3] = s[3][3], s[0][3], s[1][3], s[2][3]


def inv_shift_rows(s):
    s[0][1], s[1][1], s[2][1], s[3][1] = s[3][1], s[0][1], s[1][1], s[2][1]
    s[0][2], s[1][2], s[2][2], s[3][2] = s[2][2], s[3][2], s[0][2], s[1][2]
    s[0][3], s[1][3], s[2][3], s[3][3] = s[1][3], s[2][3], s[3][3], s[0][3]

def add_round_key(s, k):
    for i in range(4):
        for j in range(4):
            s[i][j] ^= k[i][j]


# learned from https://web.archive.org/web/20100626212235/http://cs.ucsb.edu/~koc/cs178/projects/JT/aes.c
xtime = lambda a: (((a << 1) ^ 0x1B) & 0xFF) if (a & 0x80) else (a << 1)


def mix_single_column(a):
    # see Sec 4.1.2 in The Design of Rijndael
    t = a[0] ^ a[1] ^ a[2] ^ a[3]
    u = a[0]
    a[0] ^= t ^ xtime(a[0] ^ a[1])
    a[1] ^= t ^ xtime(a[1] ^ a[2])
    a[2] ^= t ^ xtime(a[2] ^ a[3])
    a[3] ^= t ^ xtime(a[3] ^ u)


def mix_columns(s):
    for i in range(4):
        mix_single_column(s[i])


def inv_mix_columns(s):
    # see Sec 4.1.3 in The Design of Rijndael
    for i in range(4):
        u = xtime(xtime(s[i][0] ^ s[i][2]))
        v = xtime(xtime(s[i][1] ^ s[i][3]))
        s[i][0] ^= u
        s[i][1] ^= v
        s[i][2] ^= u
        s[i][3] ^= v

    mix_columns(s)


r_con = (
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
    0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A,
    0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97, 0x35, 0x6A,
    0xD4, 0xB3, 0x7D, 0xFA, 0xEF, 0xC5, 0x91, 0x39,
)


def bytes2matrix(text):
    """ Converts a 16-byte array into a 4x4 matrix.  """
    return [list(text[i:i+4]) for i in range(0, len(text), 4)]

def matrix2bytes(matrix):
    """ Converts a 4x4 matrix into a 16-byte array.  """
    return bytes(sum(matrix, []))

def xor_bytes(a, b):
    """ Returns a new byte array with the elements xor'ed. """
    return bytes(i^j for i, j in zip(a, b))

def inc_bytes(a):
    """ Returns a new byte array with the value increment by 1 """
    out = list(a)
    for i in reversed(range(len(out))):
        if out[i] == 0xFF:
            out[i] = 0
        else:
            out[i] += 1
            break
    return bytes(out)

def pad(plaintext):
    """
    Pads the given plaintext with PKCS#7 padding to a multiple of 16 bytes.
    Note that if the plaintext size is a multiple of 16,
    a whole block will be added.
    """
    padding_len = 16 - (len(plaintext) % 16)
    padding = bytes([padding_len] * padding_len)
    return plaintext + padding

def unpad(plaintext):
    """
    Removes a PKCS#7 padding, returning the unpadded text and ensuring the
    padding was correct.
    """
    padding_len = plaintext[-1]
    assert padding_len > 0
    message, padding = plaintext[:-padding_len], plaintext[-padding_len:]
    assert all(p == padding_len for p in padding)
    return message

def split_blocks(message, block_size=16, require_padding=True):
        assert len(message) % block_size == 0 or not require_padding
        return [message[i:i+16] for i in range(0, len(message), block_size)]


class AES:
    """
    Class for AES-128 encryption with CBC mode and PKCS#7.

    This is a raw implementation of AES, without key stretching or IV
    management. Unless you need that, please use `encrypt` and `decrypt`.
    """
    rounds_by_key_size = {16: 10, 24: 12, 32: 14}
    def __init__(self, master_key):
        """
        Initializes the object with a given key.
        """
        assert len(master_key) in AES.rounds_by_key_size
        self.n_rounds = AES.rounds_by_key_size[len(master_key)]
        self._key_matrices = self._expand_key(master_key)

    def _expand_key(self, master_key):
        """
        Expands and returns a list of key matrices for the given master_key.
        """
        # Initialize round keys with raw key material.
        key_columns = bytes2matrix(master_key)
        iteration_size = len(master_key) // 4

        i = 1
        while len(key_columns) < (self.n_rounds + 1) * 4:
            # Copy previous word.
            word = list(key_columns[-1])

            # Perform schedule_core once every "row".
            if len(key_columns) % iteration_size == 0:
                # Circular shift.
                word.append(word.pop(0))
                # Map to S-BOX.
                word = [s_box[b] for b in word]
                # XOR with first byte of R-CON, since the others bytes of R-CON are 0.
                word[0] ^= r_con[i]
                i += 1
            elif len(master_key) == 32 and len(key_columns) % iteration_size == 4:
                # Run word through S-box in the fourth iteration when using a
                # 256-bit key.
                word = [s_box[b] for b in word]

            # XOR with equivalent word from previous iteration.
            word = xor_bytes(word, key_columns[-iteration_size])
            key_columns.append(word)

        # Group key words in 4x4 byte matrices.
        return [key_columns[4*i : 4*(i+1)] for i in range(len(key_columns) // 4)]

    def encrypt_block(self, plaintext):
        """
        Encrypts a single block of 16 byte long plaintext.
        """
        assert len(plaintext) == 16

        plain_state = bytes2matrix(plaintext)

        add_round_key(plain_state, self._key_matrices[0])

        for i in range(1, self.n_rounds):
            sub_bytes(plain_state)
            shift_rows(plain_state)
            mix_columns(plain_state)
            add_round_key(plain_state, self._key_matrices[i])

        sub_bytes(plain_state)
        shift_rows(plain_state)
        add_round_key(plain_state, self._key_matrices[-1])

        return matrix2bytes(plain_state)

    def decrypt_block(self, ciphertext):
        """
        Decrypts a single block of 16 byte long ciphertext.
        """
        assert len(ciphertext) == 16

        cipher_state = bytes2matrix(ciphertext)

        add_round_key(cipher_state, self._key_matrices[-1])
        inv_shift_rows(cipher_state)
        inv_sub_bytes(cipher_state)

        for i in range(self.n_rounds - 1, 0, -1):
            add_round_key(cipher_state, self._key_matrices[i])
            inv_mix_columns(cipher_state)
            inv_shift_rows(cipher_state)
            inv_sub_bytes(cipher_state)

        add_round_key(cipher_state, self._key_matrices[0])

        return matrix2bytes(cipher_state)

    def encrypt(self,plaintext):
        return self.encrypt_block(plaintext)
    def decrypt(self,ciphertext):
        return self.decrypt_block(ciphertext)

    def encrypt_cbc(self, plaintext, iv):
        """
        Encrypts `plaintext` using CBC mode and PKCS#7 padding, with the given
        initialization vector (iv).
        """
        assert len(iv) == 16

        plaintext = pad(plaintext)

        blocks = []
        previous = iv
        for plaintext_block in split_blocks(plaintext):
            # CBC mode encrypt: encrypt(plaintext_block XOR previous)
            block = self.encrypt_block(xor_bytes(plaintext_block, previous))
            blocks.append(block)
            previous = block

        return b''.join(blocks)

    def decrypt_cbc(self, ciphertext, iv):
        """
        Decrypts `ciphertext` using CBC mode and PKCS#7 padding, with the given
        initialization vector (iv).
        """
        assert len(iv) == 16

        blocks = []
        previous = iv
        for ciphertext_block in split_blocks(ciphertext):
            # CBC mode decrypt: previous XOR decrypt(ciphertext)
            blocks.append(xor_bytes(previous, self.decrypt_block(ciphertext_block)))
            previous = ciphertext_block

        return unpad(b''.join(blocks))

    def encrypt_pcbc(self, plaintext, iv):
        """
        Encrypts `plaintext` using PCBC mode and PKCS#7 padding, with the given
        initialization vector (iv).
        """
        assert len(iv) == 16

        plaintext = pad(plaintext)

        blocks = []
        prev_ciphertext = iv
        prev_plaintext = bytes(16)
        for plaintext_block in split_blocks(plaintext):
            # PCBC mode encrypt: encrypt(plaintext_block XOR (prev_ciphertext XOR prev_plaintext))
            ciphertext_block = self.encrypt_block(xor_bytes(plaintext_block, xor_bytes(prev_ciphertext, prev_plaintext)))
            blocks.append(ciphertext_block)
            prev_ciphertext = ciphertext_block
            prev_plaintext = plaintext_block

        return b''.join(blocks)

    def decrypt_pcbc(self, ciphertext, iv):
        """
        Decrypts `ciphertext` using PCBC mode and PKCS#7 padding, with the given
        initialization vector (iv).
        """
        assert len(iv) == 16

        blocks = []
        prev_ciphertext = iv
        prev_plaintext = bytes(16)
        for ciphertext_block in split_blocks(ciphertext):
            # PCBC mode decrypt: (prev_plaintext XOR prev_ciphertext) XOR decrypt(ciphertext_block)
            plaintext_block = xor_bytes(xor_bytes(prev_ciphertext, prev_plaintext), self.decrypt_block(ciphertext_block))
            blocks.append(plaintext_block)
            prev_ciphertext = ciphertext_block
            prev_plaintext = plaintext_block

        return unpad(b''.join(blocks))

    def encrypt_cfb(self, plaintext, iv):
        """
        Encrypts `plaintext` with the given initialization vector (iv).
        """
        assert len(iv) == 16

        blocks = []
        prev_ciphertext = iv
        for plaintext_block in split_blocks(plaintext, require_padding=False):
            # CFB mode encrypt: plaintext_block XOR encrypt(prev_ciphertext)
            ciphertext_block = xor_bytes(plaintext_block, self.encrypt_block(prev_ciphertext))
            blocks.append(ciphertext_block)
            prev_ciphertext = ciphertext_block

        return b''.join(blocks)

    def decrypt_cfb(self, ciphertext, iv):
        """
        Decrypts `ciphertext` with the given initialization vector (iv).
        """
        assert len(iv) == 16

        blocks = []
        prev_ciphertext = iv
        for ciphertext_block in split_blocks(ciphertext, require_padding=False):
            # CFB mode decrypt: ciphertext XOR decrypt(prev_ciphertext)
            plaintext_block = xor_bytes(ciphertext_block, self.encrypt_block(prev_ciphertext))
            blocks.append(plaintext_block)
            prev_ciphertext = ciphertext_block

        return b''.join(blocks)

    def encrypt_ofb(self, plaintext, iv):
        """
        Encrypts `plaintext` using OFB mode initialization vector (iv).
        """
        assert len(iv) == 16

        blocks = []
        previous = iv
        for plaintext_block in split_blocks(plaintext, require_padding=False):
            # OFB mode encrypt: plaintext_block XOR encrypt(previous)
            block = self.encrypt_block(previous)
            ciphertext_block = xor_bytes(plaintext_block, block)
            blocks.append(ciphertext_block)
            previous = block

        return b''.join(blocks)

    def decrypt_ofb(self, ciphertext, iv):
        """
        Decrypts `ciphertext` using OFB mode initialization vector (iv).
        """
        assert len(iv) == 16

        blocks = []
        previous = iv
        for ciphertext_block in split_blocks(ciphertext, require_padding=False):
            # OFB mode decrypt: ciphertext XOR encrypt(previous)
            block = self.encrypt_block(previous)
            plaintext_block = xor_bytes(ciphertext_block, block)
            blocks.append(plaintext_block)
            previous = block

        return b''.join(blocks)

    def encrypt_ctr(self, plaintext, iv):
        """
        Encrypts `plaintext` using CTR mode with the given nounce/IV.
        """
        assert len(iv) == 16

        blocks = []
        nonce = iv
        for plaintext_block in split_blocks(plaintext, require_padding=False):
            # CTR mode encrypt: plaintext_block XOR encrypt(nonce)
            block = xor_bytes(plaintext_block, self.encrypt_block(nonce))
            blocks.append(block)
            nonce = inc_bytes(nonce)

        return b''.join(blocks)

    def decrypt_ctr(self, ciphertext, iv):
        """
        Decrypts `ciphertext` using CTR mode with the given nounce/IV.
        """
        assert len(iv) == 16

        blocks = []
        nonce = iv
        for ciphertext_block in split_blocks(ciphertext, require_padding=False):
            # CTR mode decrypt: ciphertext XOR encrypt(nonce)
            block = xor_bytes(ciphertext_block, self.encrypt_block(nonce))
            blocks.append(block)
            nonce = inc_bytes(nonce)

        return b''.join(blocks)

def xor(a,b):
    return bytes([x^y for x,y in zip(a,b)])

h = bytes.fromhex("4a9512df638c4cbca0f92559c9b36bac2a4825d2")
o1 = 177195144995750726318273206936212136323
o2 = 317085017408315050929696020333851440979

zero = AES(b'\x00'*16).encrypt(b'\x00'*16)
one_hot = [int('0'*i+'1'+'0'*(127-i),2).to_bytes(length=16,byteorder='big')for i in range(128)]

# basis
key_bits = [xor(AES(key).encrypt(b'\x00'*16),zero)for key in one_hot]
pt_bits = [xor(AES(b'\x00'*16).encrypt(pt),zero)for pt in one_hot]

# linearity test
for _ in range(100):
    key = os.urandom(16)
    pt = os.urandom(16)

    real = AES(key).encrypt(pt)
    res = zero
    key = bin(int(key.hex(),16))[2:].zfill(128)
    pt = bin(int(pt.hex(),16))[2:].zfill(128)
    for i in range(128):
        if key[i]=='1':
            res = xor(res,key_bits[i])
    for i in range(128):
        if pt[i]=='1':
            res = xor(res,pt_bits[i])
    assert real.hex() == res.hex()

# make an nullkey-AES-encrypt matrix
F = GF(2)
M = [
    list(map(int,bin(int(b.hex(),16))[2:].zfill(128))) for b in pt_bits
]
M = Matrix(F,M)
assert M.is_invertible()

# make an a-multiplication matrix
a = 147997703104811623749917045359722760002
ainv = 196472080169844450408961296658609113784
b = 92108264673406768891610745079292891113
modulus = 551856765943438970981690959177069078957
assert gmul(a,ainv,modulus) == 1
mul_basis = [gmul(a,2**(127-i),modulus) for i in range(128)]
A = [
    list(map(int,bin(x)[2:].zfill(128))) for x in mul_basis
]
A = Matrix(F,A).transpose()

t = int(AES(b'\x00'*16).decrypt(xor(bytes.fromhex(hex(o1^o2)[2:].zfill(32)),zero)).hex(),16)
t = gmul(gpow(ainv,100,modulus),t,modulus)^b

tv = vector(F,list(map(int,bin(t)[2:].zfill(128))))
sv = (A+Matrix.identity(A.nrows()))**-1*tv
seed = int(''.join(list(map(str,list(sv)))),2)

flag = "DH{"+hex(seed)[2:].zfill(32)+"}"
print(flag)
print(hashlib.sha1(bytes.fromhex(flag[3:-1])).hexdigest())

# DH{cdd5805a3072ebb3f13f7ce1563c0865}