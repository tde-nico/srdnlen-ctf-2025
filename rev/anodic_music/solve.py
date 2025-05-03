from string import printable
from hashlib import md5

with open('hardcore.bnk', 'rb') as f:
	data = f.read()

hashes = [data[i*16:(i+1)*16] for i in range(len(data)//16)]

flag = 'srdnlen{'

def dfs(flag):
	if len(flag) == 63:
		exit(0)

	for c in printable[:-6]:
		tmp = flag + c
		digest = md5(tmp.encode()).digest()
		if digest not in hashes:
			print(tmp)
			dfs(tmp)


dfs(flag)

# srdnlen{Mr_Evrart_is_helping_me_find_my_flag_af04993a13b8eecd}