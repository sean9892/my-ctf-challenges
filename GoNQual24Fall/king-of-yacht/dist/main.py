from Crypto.Util.number import bytes_to_long, getRandomRange
from Crypto.Cipher import AES
import hashlib

from board import process_wall
from board import board
from board import walls,die,blank_die
from board import score_filler,die_filler,chosen_die_filler

from secret import privkeys

def h(m,alg=hashlib.md5):
    if type(m) == int:
        m = int.to_bytes(m,length=4,byteorder='big')
    return bytes_to_long(alg(m).digest())|1

def long_tokenize(m,key,alg=hashlib.md5,size=32):
    if type(m) == int:
        m = int.to_bytes(m,length=4,byteorder='big')
    aeskey = hashlib.md5(m).digest()
    exponent = bytes_to_long(AES.new(aeskey,AES.MODE_ECB).encrypt(key))
    tag = pow(h(m,alg=alg),exponent,2**size)
    tag = int.to_bytes(tag,length=size//8,byteorder='big')
    return m+tag

def f1(x):
    return 1*x.count(1)
def f2(x):
    return 2*x.count(2)
def f3(x):
    return 3*x.count(3)
def f4(x):
    return 4*x.count(4)
def f5(x):
    return 5*x.count(5)
def f6(x):
    return 6*x.count(6)

# Three-Of-A-Kind
def ftok(x):
    cnts = [x.count(i)for i in range(1,7)]
    res = 0
    if 3 in cnts:
        i3 = cnts.index(3)+1
        res = 3*i3
    elif 4 in cnts:
        i4 = cnts.index(4)+1
        res = 3*i4
    elif 5 in cnts:
        i5 = cnts.index(5)+1
        res = 3*i5
    return res

# Four-Of-A-Kind
def ffok(x):
    cnts = [x.count(i)for i in range(1,7)]
    res = 0
    if 4 in cnts:
        i4 = cnts.index(4)+1
        res = 4*i4
    elif 5 in cnts:
        i5 = cnts.index(5)+1
        res = 4*i5
    return res

# Full House
def ffh(x):
    cnts = [x.count(i)for i in range(1,7)]
    res = 0
    if 2 in cnts and 3 in cnts:
        i2 = cnts.index(2)+1
        i3 = cnts.index(3)+1
        res = 2*i2+3*i3
    elif 5 in cnts:
        i5 = cnts.index(5)+1
        res = 5*i5
    return res

# Little Straight
def fls(x):
    return 30*int(sorted(x) == [1,2,3,4,5])

# Big Straight
def fbs(x):
    return 30*int(sorted(x) == [2,3,4,5,6])

# Yacht
def fy(x):
    cnts = [x.count(i)for i in range(1,7)]
    return 50*int(5 in cnts)

# Choice
def fc(x):
    return sum(x)

class Game:
    def __init__(self):
        filled = '00000010000000'
        score = [0 for _ in range(13)]
        fs = [f1,f2,f3,f4,f5,f6,ftok,ffok,ffh,fls,fbs,fy,fc]
        total = 0

        self.filled = filled
        self.score = score
        self.fs = fs
        self.total = total
    
    def menu(self):
        filled = self.filled
        score = self.score
        fs = self.fs
        total = self.total

        menu_board = board[:]
        # die wall
        for let in '!@#$%':
            menu_board = process_wall(menu_board,blank_die,let)
        # score filler
        for let,(val,f) in zip(score_filler,zip(score[:6]+[total]+score[6:],filled)):
            menu_board = menu_board.replace(let,f'{(val if f=="1" else "---"):3}')
        # die filler / chosen die filler
        for i in range(5):
            menu_board = menu_board.replace(die_filler[i],' ')
            menu_board = menu_board.replace(chosen_die_filler[i],'-')
        print(menu_board)

        # print options
        print("1. Play")
        print("2. Save")
        print("3. Load")
        options = [self.phase_play,self.phase_save,self.phase_load]
        while True:
            inp = input("Menu >>> ")
            if inp in ['1','2','3']:
                options[['1','2','3'].index(inp)]()
                break
    
    def roll_dice(self,chosen,roll):
        filled = self.filled
        score = self.score
        fs = self.fs
        total = self.total

        print("Rolling die...")
        rolled = [getRandomRange(1,6)for _ in range(roll)]
        roll_board = board[:]

        # score filler
        for let,(val,f) in zip(score_filler,zip(score[:6]+[total]+score[6:],filled)):
            roll_board = roll_board.replace(let,f'{(val if int(f) else "---"):3}')

        # show chosen
        for i,c in enumerate(chosen):
            roll_board = roll_board.replace(chosen_die_filler[i],str(c))
        for i in range(len(chosen),5):
            roll_board = roll_board.replace(chosen_die_filler[i],'-')

        # show rolled
        for i,c in enumerate(rolled):
            roll_board = roll_board.replace(die_filler[i],str(c))
            roll_board = process_wall(roll_board,die,'!@#$%'[i])
        for i in range(roll,5):
            roll_board = roll_board.replace(die_filler[i],' ')
            roll_board = process_wall(roll_board,blank_die,'!@#$%'[i])
        
        print(roll_board)
        inp = input("Choose die (separate with comma) >>> ")
        return chosen+list(map((lambda x:rolled[int(x)]),inp.split(",")))

    def phase_play(self):
        filled = self.filled
        score = self.score
        fs = self.fs
        total = self.total

        chosen = []
        while len(chosen) < 5:
            chosen = self.roll_dice(chosen,5-len(chosen))
        while True:
            inp = int(input("Choose category (0~12) >>> "))
            idx = inp
            if inp > 12 or inp < 0:
                continue
            if inp >= 6:
                idx += 1
            if filled[idx] == '0':
                filled = filled[:idx]+'1'+filled[idx+1:]
                self.filled = filled
                s = fs[inp](chosen)
                score[inp] = s
                self.score[inp] = s
                total += s
                self.total += s
                break

    def phase_save(self):
        filled = self.filled
        score = self.score
        fs = self.fs
        total = self.total

        filled_flag = int(filled,2)
        longs = [filled_flag]+score+[total]
        assert len(longs) == 15
        tokenized = [long_tokenize(long,key)for key,long in zip(privkeys[:14],longs[:14])]+[long_tokenize(longs[14],privkeys[14],alg=hashlib.sha512,size=512)]
        save_data = b'KOYSD'+b''.join(tokenized)

        print("Here is your save data in hex:",save_data.hex())

    def phase_load(self):
        save_data = input("Load >>> ")
        try:
            save_data = bytes.fromhex(save_data)

            assert save_data.startswith(b"KOYSD")
            save_data = save_data[5:]

            # parse tokens
            tokenized = []
            for i in range(0,14*8,8):
                tokenized.append(save_data[i:i+8])
            tokenized.append(save_data[14*8:])
            
            # verify tokens
            vals = []
            for key,token in zip(privkeys[:14],tokenized[:14]):
                val = token[:4]
                vals.append(bytes_to_long(val))
                tag = token[4:]
                assert token == long_tokenize(val,key)
            token = tokenized[-1]
            key = privkeys[-1]
            val = token[:4]
            vals.append(bytes_to_long(val))
            tag = token[4:]
            assert token == long_tokenize(val,key,alg=hashlib.sha512,size=512)

            self.filled = bin(vals[0])[2:].zfill(14)
            self.score = vals[1:14]
            self.total = vals[14]
        except ValueError:
            print("loading terminated unexpectedly")
        except AssertionError:
            print("loading terminated unexpectedly")
        else:
            print("loading successfully done")

if __name__ =='__main__':
    g = Game()
    while g.filled != '1'*14:
        g.menu()
    if g.total == 0xdeadbeef:
        with open("flag.txt","r") as f:
            print(f.read())
