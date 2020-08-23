from itertools import permutations

def m0(a, b):
	if a == 0:
		return [0,1]
	
	r = m0(b % a, a)
	return [r[1] - ((b / a) * r[0]), r[0]]

magic = [40999019, 2789358025L, 656272715, 18374979, 3237618335L, 1762529471, 685548119, 382114257, 1436905469, 2126016673, 3318315423L, 797150821]
solved = []

possibilities = permutations('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!?_{}', 4)
for p in possibilities:
	i1, i2, i3, i4 = p
	value = (((ord(i4) << 24) | (ord(i3) << 16)) | (ord(i2) << 8)) | ord(i1)

	found = False

	for m in magic:
		if (m0(value, 4294967296)[0] % 4294967296 + 4294967296) % 4294967296 == m:
			solved.append([i1, i2, i3, i4, m])
			found = True


	if not found:
		print('[{} {} {} {}]: wrong'.format(i1, i2, i3, i4))

print(solved)

