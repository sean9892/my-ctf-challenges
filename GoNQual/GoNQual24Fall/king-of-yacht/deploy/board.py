def process_wall(board,lets,wc):
  res = ""
  b = board.split("\n")
  for i in range(len(b)):
    for j in range(len(b[0])):
      if b[i][j] == wc:
        d = 0
        for idx,chg in enumerate([(-1,0),(0,-1),(0,1),(1,0)]):
          d *= 2
          ni = i+chg[0]
          nj = j+chg[1]
          if 0<=ni<len(b) and 0<=nj<len(b[0]) and b[ni][nj] == wc:
            d += 1
        res += lets[d]
      else:
        res += b[i][j]
    res += '\n'
  return res.strip()

walls = [None]*16
#2
walls[6] = "═"
walls[9] = "║"
walls[3] = "╔"
walls[10] = "╚"
walls[5] = "╗"
walls[12] = "╝"
#3
walls[7] = "╦"
walls[13] = "╣"
walls[14] = "╩"
walls[11] = "╠"
#4
walls[15] = "╬"

die = [None]*16
#2
die[6] = "━"
die[9] = "┃"
die[3] = "┏"
die[10] = "┗"
die[5] = "┓"
die[12] = "┛"

blank_die = ' '*16

board = """
qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq
q Ones   q    ααα    q TOK    q    ββα    q                                   q
qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq               !!!!!               q
q Twos   q    ααβ    q FOK    q    βββ    q       @@@@@   ! à !               q
qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq       @ á @   !!!!!               q
q Threes q    ααγ    q FH     q    ββγ    q       @@@@@           %%%%%       q
qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq                       % ä %       q
q Fours  q    ααδ    q SS     q    ββδ    q     $$$$$             %%%%%       q
qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq     $ ã $       #####             q
q Fives  q    ααε    q LS     q    ββε    q     $$$$$       # â #             q
qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq                 #####             q
q Sixes  q    ααζ    q Yacht  q    ββζ    q                                   q
qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq
q Total  q ααη /  63 q Chance q    ββη    q À q Á q Â q Ã q Ä q King Of Yacht q
qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq
""".strip()
board = process_wall(board,walls,'q')

score_filler = ['ααα','ααβ','ααγ','ααδ','ααε','ααζ','ααη',
                'ββα','βββ','ββγ','ββδ','ββε','ββζ','ββη']
die_filler = 'àáâãä'
chosen_die_filler = 'ÀÁÂÃÄ'

if __name__ == '__main__':
  for i in range(6):
    test_board = board[:]
    for j in range(i):
      test_board = process_wall(test_board,die,'!@#$%'[j])
    for j in range(i,5):
      test_board = process_wall(test_board,blank_die,'!@#$%'[j])
    print(test_board)
