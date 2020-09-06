#: GoogleCTF: Android - Flag Bruteforce

import sys

#: final check function from decompiled apk
def m0(a, b):
	if a == 0:
		return [0,1]
	
	r = m0(b % a, a)
	return [r[1] - ((b / a) * r[0]), r[0]]

magic = [40999019, 2789358025L, 656272715, 18374979, 3237618335L, 1762529471, 685548119, 382114257, 1436905469, 2126016673, 3318315423L, 797150821]

#: run bruteforced string for validation
def validate_brute(index_3, index_2, index_1, index_0):

	value = (((ord(index_3) << 24) | (ord(index_2) << 16)) | (ord(index_1) << 8)) | ord(index_0)

	#: fancy output 
	sys.stdout.write('[i] Trying key: {}{}{}{}\r'.format(index_0, index_1, index_2, index_3))
	sys.stdout.flush()

	return value

#: May be more efficient this time around
flag = ['*'] * 48
possible_alphakeys = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890?!_{}"
for index_3 in possible_alphakeys:

	for index_2 in possible_alphakeys:

		for index_1 in possible_alphakeys:

			for index_0 in possible_alphakeys:

				possible_value = validate_brute(index_3, index_2, index_1, index_0)
				possible_magic = (m0(possible_value, 4294967296)[0] % 4294967296 + 4294967296) % 4294967296
				
				for m in magic:
					if possible_magic == m:
						flag[magic.index(m) * 4 : (magic.index(m) * 4) + 4] = index_0, index_1, index_2, index_3
						found = True

				sys.stdout.write('[*] Flag: {} '.format(''.join(flag)))
				sys.stdout.flush()
						
	