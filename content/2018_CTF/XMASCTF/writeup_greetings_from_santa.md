## XMASCTF: Greetings from Santa
##### *tl;dr: buffer overflow to control instruction pointer, call eax*
#### This was an interesting challenge, although I didn't solve any of these challenges during the duration of the CTF, which was around christmas time last year, I'm hosting them locally in hopes of being able to learn new things. We are given only the challenge binary, so first thing to do is to check the properties and security measures:
```
$ file chall 
chall: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-, for GNU/Linux 3.2.0, BuildID[sha1]=5c2946ef557ee008fc18faeea0796165b43b8234, stripped

$ checksec chall
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```
#### We're dealing with a stripped binary, which means that it's a bit harder to disassemble and reverse engineer compared to non-stripped ones, but nonetheless we can still do it. To disassemble and debug the binary we'll be using gdb and decompile it using ghidra to get a clearer understanding on it. 
