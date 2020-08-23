#: GoogleCTF: Android - Flag Bruteforce

from itertools import permutations

#: final check function from decompiled apk
def m0(a, b):
	if a == 0:
		return [0,1]
	
	r = m0(b % a, a)
	return [r[1] - ((b / a) * r[0]), r[0]]

magic = [40999019, 2789358025L, 656272715, 18374979, 3237618335L, 1762529471, 685548119, 382114257, 1436905469, 2126016673, 3318315423L, 797150821]
solved = []

#: I don't know how long it will take, but all that I know is I must bruteforce
#: Forgive me, I dunno z3
possibilities = permutations('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!?_{}', 4)
for p in possibilities:
	index_0, index_1, index_2, index_3 = p
	value = (((ord(index_3) << 24) | (ord(index_2) << 16)) | (ord(index_1) << 8)) | ord(index_0)

	found = False

	for m in magic:
		if (m0(value, 4294967296)[0] % 4294967296 + 4294967296) % 4294967296 == m:
			solved.append([index_0, index_1, index_2, index_3, m])
			found = True


	if not found:
		print('[{} {} {} {}]: wrong'.format(index_0, index_1, index_2, index_3))

print(solved)

