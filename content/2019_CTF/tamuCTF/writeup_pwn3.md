## pwn3
#### Making it a habit that whenever there's a pwn chall, we need to check the security measures first using the *checksec* utility from pwntools:
```
$ checksec pwn3
    Arch:     i386-32-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      PIE enabled
    RWX:      Has RWX segments
```
#### As we can see, the output is different from the previous pwn challenges. This binary has no canary and has NX disasbled - meaning we can execute code on the stack. More details [here](http://blog.siphos.be/2011/07/high-level-explanation-on-some-binary-executable-security/). Basically, no canary means that we can do some kind of a buffer overflow on the stack, since no measures are put in place to determine whether some part of it is overwritten. NX, short-hand for 'non-executable', is disabled meaning segments of the binary are not only writeable, but also executable. We run the binary to have an initial look at what it does:
```
$ ./pwn3
  Take this, you might need it on your journey 0xff92adce!
```
#### From what we see, it prints out that string and waits for user input afterwards. The printed string comes with some kind of an address (which changes everytime the binary is executed) which will be useful later on. We then fire up gdb to look at the inner workings of the challenge. 
```
$ gdb ./pwn3
  gdb-peda$ disas main
   [...]
   0x00000612 <+47>:	add    esp,0x10
   0x00000615 <+50>:	call   0x59d <echo>
   0x0000061a <+55>:	mov    eax,0x0
   0x0000061f <+60>:	lea    esp,[ebp-0x8]
   [...]
```
#### The call to a function called ```echo``` is interesting, let's have a deeper look at it by disassembling the function:
```
gdb-peda$ disas echo
  Dump of assembler code for function echo:
     0x0000059d <+0>:	  push   ebp
     0x0000059e <+1>:	  mov    ebp,esp
     0x000005a0 <+3>:	  push   ebx
     0x000005a1 <+4>:	  sub    esp,0x134
     0x000005a7 <+10>:	call   0x4a0 <__x86.get_pc_thunk.bx>
     0x000005ac <+15>:	add    ebx,0x1a20
     0x000005b2 <+21>:	sub    esp,0x8
     0x000005b5 <+24>:	lea    eax,[ebp-0x12a]
     0x000005bb <+30>:	push   eax
     0x000005bc <+31>:	lea    eax,[ebx-0x191c]
     0x000005c2 <+37>:	push   eax
     0x000005c3 <+38>:	call   0x410 <printf@plt>
     0x000005c8 <+43>:	add    esp,0x10
     0x000005cb <+46>:	sub    esp,0xc
     0x000005ce <+49>:	lea    eax,[ebp-0x12a]
     0x000005d4 <+55>:	push   eax
     0x000005d5 <+56>:	call   0x420 <gets@plt>
     0x000005da <+61>:	add    esp,0x10
     0x000005dd <+64>:	nop
     0x000005de <+65>:	mov    ebx,DWORD PTR [ebp-0x4]
     0x000005e1 <+68>:	leave  
     0x000005e2 <+69>:	ret    
  End of assembler dump.
```
#### The function loads whatever are in the locations ```[ebp-0x12a]``` and ```[ebx-0x191c]``` into the stack and used as arguments for the printf call. Recalling what we have got so far with the initial start up of the binary, we know that ```[ebx-0x191c]``` in this part stores the address which is printed. Looking below the disassembly, we see a ```gets``` call which stores the input into the buffer at ```[ebp-0x12a]```. The size of the buffer is 0x12a(298) and that is the exact offset at which the stack can be started to be overwritten.
#### Putting together what we already know, we can perform a buffer overflow attack and execute some code in the stack. So our exploit method will be a buffer overflow into executing shellcode. To do that, we need the address of the stack - but that isn't a problem anymore since the address for the stack is already given at the start of the program.
