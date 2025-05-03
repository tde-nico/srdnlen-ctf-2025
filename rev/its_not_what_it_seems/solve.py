from pwn import xor
from Crypto.Util.number import long_to_bytes

a = [
	0x3B2E252C2E243233,
	0x32341F327336732E,
	0x1F7328141F347535,
	0x2E35261F2E71742D,
	0x3D2E707134232E35,
]

a = b''.join([long_to_bytes(i) for i in a[::-1]])
print(a)

print(xor(a, 0x40)[::-1])

# srdnlen{n3v3r_tru5t_Th3_m41n_fununct10n}
# srdnlen{n3v3r_tru5t_Th3_m41n_funct10n}

