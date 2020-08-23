#: GoogleCTF: Android - Check if valid flag

def m0(a, b):
	if a == 0:
		return [0,1]
	
	r = m0(b % a, a)
	return [r[1] - ((b / a) * r[0]), r[0]]

#: fake flag ha-ha funny google
flag_hex = [65, 112, 112, 97, 114, 101, 110, 116, 108, 121, 32, 116, 104, 105, 115, 32, 105, 115, 32, 110, 111, 116, 32, 116, 104, 101, 32, 102, 108, 97, 103, 46, 32, 87, 104, 97, 116, 39, 115, 32, 103, 111, 105, 110, 103, 32, 111, 110, 63]
fake_flag = ''.join([chr(x) for x in flag_hex])

magic = [40999019, 2789358025L, 656272715, 18374979, 3237618335L, 1762529471, 685548119, 382114257, 1436905469, 2126016673, 3318315423L, 797150821]

#: flag checker reversed
flag = 'CTF{y0u_c4n_k3ep_y0u?_m4gic_1_h4Ue_laser_b3ams!}'

for i in range(0, len(flag) / 4):
	value = (((ord(flag[(i * 4) + 3]) << 24) | (ord(flag[(i * 4) + 2]) << 16)) | (ord(flag[(i * 4) + 1]) << 8)) | ord(flag[(i * 4)])

	if (m0(value, 4294967296)[0] % 4294967296 + 4294967296) % 4294967296 == magic[i]:
		print(flag[(i * 4) : (i * 4) + 4])
